/**
 * TLS anomaly scoring — stage 3 for the `tls_anomaly` candidate type.
 *
 * The handshake is the last thing an implant shows in the clear. Everything after it is
 * encrypted; everything in it — the certificate the server presented, the client's TLS
 * fingerprint, the name it asked for — is not. This scorer reads that handshake.
 *
 * Entity: `(src_ip, dest_ip, dest_port)`. A candidate covers every ssl record for the
 * triple, and each dimension keeps the WORST value seen across them.
 *
 * THREE INDEPENDENT DIMENSIONS, COMBINED WITH max(), NOT a weighted sum:
 *
 *   1. CERTIFICATE   self-signed, expired, implausibly short or long validity, a serial
 *                    too short to be randomly generated. Sub-weights accumulate WITHIN
 *                    the dimension, because these are facets of one judgment about one
 *                    certificate.
 *   2. FINGERPRINT   JA3 / JA3S / JA4X against the known-bad sets. A JA3+JA3S PAIR or a
 *                    JA4X match scores highest (0.95) — client and server both recognized
 *                    is a stronger statement than either alone; JA3 alone is 0.90, JA3S
 *                    alone 0.80. NOTE: the four known-bad sets DEFAULT TO EMPTY, so with
 *                    the shipped config this dimension always scores 0. Populating them
 *                    means passing a config to the scorer directly — `athanor.yaml` does
 *                    not reach in here.
 *   3. SNI           no server name at all, a name that does not match the certificate,
 *                    or a connection made to a bare IP.
 *
 * max() rather than a mean is the whole design decision. These are three ALTERNATIVE
 * reasons to look at a connection, not three components of one reason. Averaging them
 * would let two clean dimensions dilute one damning one — a connection with a perfectly
 * ordinary certificate and a perfectly ordinary SNI, presenting a fingerprint belonging
 * to a known implant, would score a third of what it deserves. The strongest independent
 * signal wins, and the candidate records all three so the reader sees which fired.
 *
 * Every dimension is floored by `min_dimension_score`: below it, the entity produces no
 * candidate at all. That is separate from and earlier than the emit floor.
 */

import type { TlsSslEvent } from '../../schema/events.js';
import type { TlsAnomalyCandidate } from '../../schema/candidates.js';
import { round } from '../../stats/descriptive.js';
import { isRfc1918 } from '../../utils/ip.js';
import { assignDeterministicCandidateIds } from './candidate-id.js';

// ─── Configuration ──────────────────────────────────────────

export interface TlsAnomalyConfig {
  // Minimum dimension score to emit a candidate
  min_dimension_score: number;

  // Cert anomaly sub-weights
  cert_self_signed_weight: number;
  cert_expired_weight: number;
  cert_short_validity_weight: number;
  cert_long_validity_weight: number;
  cert_short_serial_weight: number;

  // Cert anomaly thresholds
  cert_short_validity_days: number;
  cert_long_validity_years: number;
  cert_short_serial_bytes: number;

  // Fingerprint scores
  fp_ja3_ja3s_pair_score: number;
  fp_ja4x_match_score: number;
  fp_ja3_match_score: number;
  fp_ja3s_match_score: number;

  // SNI scores
  sni_mismatch_score: number;
  sni_to_ip_score: number;
  sni_missing_score: number;

  // Known-bad fingerprint sets
  known_bad_ja3: Set<string>;
  known_bad_ja3s: Set<string>;
  known_bad_ja3_ja3s_pairs: Set<string>;  // "ja3|ja3s" format
  known_bad_ja4x: Set<string>;
}

export const DEFAULT_TLS_ANOMALY_CONFIG: TlsAnomalyConfig = {
  min_dimension_score: 0.30,

  cert_self_signed_weight: 0.40,
  cert_expired_weight: 0.20,
  cert_short_validity_weight: 0.15,
  cert_long_validity_weight: 0.15,
  cert_short_serial_weight: 0.10,

  cert_short_validity_days: 7,
  cert_long_validity_years: 10,
  cert_short_serial_bytes: 4,

  fp_ja3_ja3s_pair_score: 0.95,
  fp_ja4x_match_score: 0.95,
  fp_ja3_match_score: 0.90,
  fp_ja3s_match_score: 0.80,

  sni_mismatch_score: 0.70,
  sni_to_ip_score: 0.60,
  sni_missing_score: 0.50,

  known_bad_ja3: new Set(),
  known_bad_ja3s: new Set(),
  known_bad_ja3_ja3s_pairs: new Set(),
  known_bad_ja4x: new Set(),
};

function normalizeHash(value: string | null | undefined): string | null {
  if (!value) return null;
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

function hasHash(set: Set<string>, hash: string): boolean {
  return set.has(hash) || set.has(hash.toLowerCase()) || set.has(hash.toUpperCase());
}

// ─── Dimension 1: Certificate Anomaly ───────────────────────

export function computeCertAnomalyScore(event: TlsSslEvent, config: TlsAnomalyConfig): number {
  // Self-signed to internal IP → excluded
  if (event.cert_self_signed && isRfc1918(event.dest_ip)) return 0;

  let score = 0;

  if (event.cert_self_signed) {
    score += config.cert_self_signed_weight;
  }

  if (event.cert_expired) {
    score += config.cert_expired_weight;
  }

  if (event.cert_validity_days !== null && event.cert_validity_days !== undefined) {
    if (event.cert_validity_days < config.cert_short_validity_days) {
      score += config.cert_short_validity_weight;
    }
    if (event.cert_validity_days > config.cert_long_validity_years * 365) {
      score += config.cert_long_validity_weight;
    }
  }

  if (event.cert_serial !== null && event.cert_serial !== undefined) {
    const hex = event.cert_serial.replace(/^0x/i, '');
    const serialBytes = Math.ceil(hex.length / 2);
    if (serialBytes > 0 && serialBytes < config.cert_short_serial_bytes) {
      score += config.cert_short_serial_weight;
    }
  }

  return Math.min(1.0, score);
}

// ─── Dimension 2: Fingerprint Anomaly ───────────────────────

export function computeFingerprintAnomalyScore(event: TlsSslEvent, config: TlsAnomalyConfig): number {
  let maxScore = 0;
  const ja3 = normalizeHash(event.ja3_hash);
  const ja3s = normalizeHash(event.ja3s_hash);
  const ja4x = normalizeHash(event.ja4x_hash);

  // JA3+JA3S pair match (highest specificity)
  if (ja3 && ja3s) {
    const pair = `${ja3}|${ja3s}`;
    if (hasHash(config.known_bad_ja3_ja3s_pairs, pair)) {
      maxScore = Math.max(maxScore, config.fp_ja3_ja3s_pair_score);
    }
  }

  // JA4X match
  if (ja4x && hasHash(config.known_bad_ja4x, ja4x)) {
    maxScore = Math.max(maxScore, config.fp_ja4x_match_score);
  }

  // JA3 match against known-bad database
  if (ja3 && hasHash(config.known_bad_ja3, ja3)) {
    maxScore = Math.max(maxScore, config.fp_ja3_match_score);
  }

  // JA3S match
  if (ja3s && hasHash(config.known_bad_ja3s, ja3s)) {
    maxScore = Math.max(maxScore, config.fp_ja3s_match_score);
  }

  return maxScore;
}

// ─── Dimension 3: SNI Anomaly ───────────────────────────────

export function computeSniAnomalyScore(event: TlsSslEvent, config: TlsAnomalyConfig): number {
  let maxScore = 0;

  // SNI present but doesn't match cert CN/SAN
  if (event.server_name && event.sni_matches_cert === false) {
    maxScore = Math.max(maxScore, config.sni_mismatch_score);
  }

  // SNI present but connecting to raw IP (no DNS resolution observed)
  if (event.server_name && event.connection_to_ip) {
    maxScore = Math.max(maxScore, config.sni_to_ip_score);
  }

  // Missing SNI entirely
  if (!event.server_name) {
    maxScore = Math.max(maxScore, config.sni_missing_score);
  }

  return maxScore;
}

// ─── Core Scoring ───────────────────────────────────────────

export function scoreTlsAnomalyCandidates(
  events: TlsSslEvent[],
  config: TlsAnomalyConfig = DEFAULT_TLS_ANOMALY_CONFIG,
): TlsAnomalyCandidate[] {
  const groups = groupByEntityKey(events);
  const candidates: TlsAnomalyCandidate[] = [];

  for (const [key, entries] of groups) {
    // Take max across all connections in group for each dimension
    let bestCert = 0;
    let bestFingerprint = 0;
    let bestSni = 0;
    let bestEntry: TlsSslEvent = entries[0];
    let bestEntryMax = -1;

    // Track known-bad booleans across all connections
    let ja3Bad = false;
    let ja3sBad = false;
    let pairBad = false;
    let ja4xBad = false;

    for (const e of entries) {
      const certScore = computeCertAnomalyScore(e, config);
      const fpScore = computeFingerprintAnomalyScore(e, config);
      const sniScore = computeSniAnomalyScore(e, config);
      const entryMax = Math.max(certScore, fpScore, sniScore);
      const ja3 = normalizeHash(e.ja3_hash);
      const ja3s = normalizeHash(e.ja3s_hash);
      const ja4x = normalizeHash(e.ja4x_hash);

      if (entryMax > bestEntryMax) {
        bestEntry = e;
        bestEntryMax = entryMax;
      }

      bestCert = Math.max(bestCert, certScore);
      bestFingerprint = Math.max(bestFingerprint, fpScore);
      bestSni = Math.max(bestSni, sniScore);

      // Track known-bad hits
      if (ja3 && hasHash(config.known_bad_ja3, ja3)) ja3Bad = true;
      if (ja3s && hasHash(config.known_bad_ja3s, ja3s)) ja3sBad = true;
      if (ja3 && ja3s && hasHash(config.known_bad_ja3_ja3s_pairs, `${ja3}|${ja3s}`)) pairBad = true;
      if (ja4x && hasHash(config.known_bad_ja4x, ja4x)) ja4xBad = true;
    }

    // Composite = max of dimensions
    const composite = Math.max(bestCert, bestFingerprint, bestSni);

    // Filter: at least one dimension must meet minimum
    if (composite < config.min_dimension_score) continue;

    // Timestamps
    const timestamps = entries.map(e => new Date(e.timestamp).getTime() / 1000).sort((a, b) => a - b);

    // Build candidate using bestEntry for informational fields
    const [srcIp, destIp, destPort] = key.split('|');

    candidates.push({
      candidate_id: '',
      type: 'tls_anomaly',
      time_window_start: new Date(timestamps[0] * 1000).toISOString(),
      time_window_end: new Date(timestamps[timestamps.length - 1] * 1000).toISOString(),

      src_ip: srcIp,
      dest_ip: destIp,
      dest_port: parseInt(destPort),

      cert_anomaly_score: round(bestCert, 4),
      fingerprint_anomaly_score: round(bestFingerprint, 4),
      sni_anomaly_score: round(bestSni, 4),
      tls_anomaly_score: round(composite, 4),

      cert_subject: bestEntry.cert_subject ?? null,
      cert_issuer: bestEntry.cert_issuer ?? null,
      cert_serial: bestEntry.cert_serial ?? null,
      cert_validity_days: bestEntry.cert_validity_days ?? null,
      cert_not_before: bestEntry.cert_not_before ?? null,
      cert_not_after: bestEntry.cert_not_after ?? null,
      cert_self_signed: bestEntry.cert_self_signed ?? false,
      cert_expired: bestEntry.cert_expired ?? false,
      cert_key_type: bestEntry.cert_key_type ?? null,
      cert_key_length: bestEntry.cert_key_length ?? null,
      cert_san_dns: bestEntry.cert_san_dns ?? [],
      cert_chain_length: bestEntry.cert_chain_length ?? 0,

      ja3_hash: bestEntry.ja3_hash ?? null,
      ja4_hash: bestEntry.ja4_hash ?? null,
      ja3s_hash: bestEntry.ja3s_hash ?? null,
      ja4x_hash: bestEntry.ja4x_hash ?? null,
      ja3_known_bad: ja3Bad,
      ja3s_known_bad: ja3sBad,
      ja3_ja3s_pair_known_bad: pairBad,
      ja4x_known_bad: ja4xBad,

      server_name: bestEntry.server_name ?? null,
      sni_matches_cert: bestEntry.sni_matches_cert ?? null,
      connection_to_ip: bestEntry.connection_to_ip ?? false,

      tls_version: bestEntry.tls_version ?? null,
      cipher_suite: bestEntry.cipher ?? null,
      total_tls_connections: entries.length,
      session_count: entries.length,

      process_name: null,
      process_id: null,
      enrichment: {},
      evidence: { constituent_event_ids: entries.map(e => e.id) },
    });
  }

  return assignDeterministicCandidateIds('TLS', candidates.sort((a, b) => b.tls_anomaly_score - a.tls_anomaly_score));
}

// ─── Helpers ────────────────────────────────────────────────

function groupByEntityKey(events: TlsSslEvent[]): Map<string, TlsSslEvent[]> {
  const groups = new Map<string, TlsSslEvent[]>();
  for (const e of events) {
    const key = `${e.src_ip}|${e.dest_ip}|${e.dest_port}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(e);
  }
  return groups;
}

export function resetCandidateCounter(): void {}
