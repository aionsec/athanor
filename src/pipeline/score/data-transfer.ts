/**
 * Data-transfer scoring — stage 3 for the `data_transfer` candidate type.
 *
 * Beaconing asks how REGULARLY a host talks to a destination. This asks how
 * LOPSIDEDLY. Normal client traffic pulls: a browser sends a small request and receives
 * a large response. Data leaving an estate inverts that ratio.
 *
 * Entity: `(src_ip, dest_ip, dest_port)`, the same triple the beacon scorer uses — which
 * is why one exfiltrating connection produces both a beacon and a data-transfer candidate
 * in the sample dataset. Nothing here composes them; each scorer reports what it saw.
 *
 * One gate: total outbound payload below `min_bytes_out` (1 MB) and the entity is
 * skipped. Lopsidedness over a few kilobytes describes most of an estate.
 *
 * TWO FEATURES, EQUALLY WEIGHTED:
 *
 *   pcr_aggregate       0.50  Producer-Consumer Ratio, (out − in) / (out + in), clamped
 *                             at 0. +1 is pure upload, 0 is balanced or inbound-dominant.
 *   bytes_out_norm      0.50  total bytes out, normalized against a 100 MB cap. Bounds
 *                             the term so a single enormous transfer cannot alone carry
 *                             the composite past everything else.
 *
 * Ratio and volume together, because either alone is ordinary: a 2 KB POST is pure
 * upload, and a 4 GB download is high volume. Neither is worth a human minute.
 *
 * Also computed and recorded, but NOT scored — they are context for whoever reads the
 * candidate: per-connection PCR consistency, burstiness (largest single connection as a
 * fraction of the total), transfer rate, and the per-service byte distribution.
 */

import type { ConnLogEvent } from '../../schema/events.js';
import type { DataTransferCandidate } from '../../schema/candidates.js';
import { madConsistency, round } from '../../stats/descriptive.js';
import { assignDeterministicCandidateIds } from './candidate-id.js';

// ─── Configuration ──────────────────────────────────────────

export interface DataTransferConfig {
  min_bytes_out: number;         // default: 1048576 (1 MB)
  bytes_out_norm_cap: number;    // default: 104857600 (100 MB)
  max_smb_filenames: number;     // default: 50
}

export const DEFAULT_DATA_TRANSFER_CONFIG: DataTransferConfig = {
  min_bytes_out: 1048576,
  bytes_out_norm_cap: 104857600,
  max_smb_filenames: 50,
};

// ─── Core Scoring ───────────────────────────────────────────

export function scoreDataTransferCandidates(
  events: ConnLogEvent[],
  config: DataTransferConfig = DEFAULT_DATA_TRANSFER_CONFIG,
): DataTransferCandidate[] {
  const groups = groupByEntityKey(events);
  const candidates: DataTransferCandidate[] = [];

  for (const [key, entries] of groups) {
    // ── Aggregate bytes ───────────────────────────────────
    const bytesOutTotal = entries.reduce((s, e) => s + (e.orig_bytes ?? 0), 0);
    const bytesInTotal = entries.reduce((s, e) => s + (e.resp_bytes ?? 0), 0);

    if (bytesOutTotal < config.min_bytes_out) continue;

    const timestamps = entries.map(e => new Date(e.timestamp).getTime() / 1000).sort((a, b) => a - b);
    const timeSpanHours = timestamps.length >= 2
      ? (timestamps[timestamps.length - 1] - timestamps[0]) / 3600
      : 0;
    const totalDurationSec = Math.max(timeSpanHours * 3600, 1);

    // ── PCR (Producer-Consumer Ratio) ─────────────────────
    const totalBytes = bytesOutTotal + bytesInTotal;
    const pcrRaw = totalBytes > 0
      ? (bytesOutTotal - bytesInTotal) / totalBytes
      : 0;
    const pcrAggregate = Math.max(0, pcrRaw);

    // Per-connection PCR for consistency
    const perConnPcr = entries.map(e => {
      const total = (e.orig_bytes ?? 0) + (e.resp_bytes ?? 0);
      return total > 0 ? ((e.orig_bytes ?? 0) - (e.resp_bytes ?? 0)) / total : 0;
    });
    const pcrConsistency = perConnPcr.length >= 3 ? madConsistency(perConnPcr) : 0;

    // ── Volume normalization ──────────────────────────────
    const bytesOutNorm = Math.min(bytesOutTotal / config.bytes_out_norm_cap, 1.0);

    // ── Burstiness ────────────────────────────────────────
    const maxConnBytes = Math.max(...entries.map(e => e.orig_bytes ?? 0));
    const burstiness = bytesOutTotal > 0 ? maxConnBytes / bytesOutTotal : 0;

    // ── Transfer rate (informational) ─────────────────────
    const transferRateBps = bytesOutTotal / totalDurationSec;

    // ── Protocol distribution (informational) ─────────────
    const protocolDist: Record<string, number> = {};
    for (const e of entries) {
      const svc = (e as Record<string, unknown>).service as string ?? 'unknown';
      protocolDist[svc] = (protocolDist[svc] ?? 0) + (e.orig_bytes ?? 0);
    }

    // ── Composite score ───────────────────────────────────
    const dataTransferScore =
        pcrAggregate * 0.50
      + bytesOutNorm * 0.50;

    // ── Build candidate record ────────────────────────────
    const [srcIp, destIp, destPort] = key.split('|');

    candidates.push({
      candidate_id: '',
      type: 'data_transfer',
      src_ip: srcIp,
      dest_ip: destIp,
      dest_port: parseInt(destPort),
      time_window_start: new Date(timestamps[0] * 1000).toISOString(),
      time_window_end: new Date(timestamps[timestamps.length - 1] * 1000).toISOString(),

      pcr_aggregate: round(pcrAggregate, 4),
      bytes_out_total_norm: round(bytesOutNorm, 4),
      burstiness: round(burstiness, 4),
      data_transfer_score: round(dataTransferScore, 4),

      pcr_aggregate_raw: round(pcrRaw, 4),
      pcr_consistency: round(pcrConsistency, 4),
      bytes_out_total: bytesOutTotal,
      bytes_in_total: bytesInTotal,
      bytes_out_deviation: null,
      transfer_rate_bps: round(transferRateBps, 2),
      connection_count: entries.length,
      mean_bytes_per_connection: round(bytesOutTotal / entries.length, 2),
      time_span_hours: round(timeSpanHours, 2),
      protocol_distribution: protocolDist,
      session_count: entries.length,

      smb_file_count: 0,
      smb_file_size_total: 0,
      smb_file_names: [],
      http_post_bytes_total: 0,
      http_upload_count: 0,

      process_name: null,
      process_id: null,
      enrichment: {},
      evidence: { constituent_event_ids: entries.map(e => e.id) },
    });
  }

  candidates.sort((a, b) => b.data_transfer_score - a.data_transfer_score);
  return assignDeterministicCandidateIds('DTR', candidates);
}

// ─── Helpers ────────────────────────────────────────────────

function groupByEntityKey(events: ConnLogEvent[]): Map<string, ConnLogEvent[]> {
  const groups = new Map<string, ConnLogEvent[]>();
  for (const e of events) {
    const key = `${e.src_ip}|${e.dest_ip}|${e.dest_port}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(e);
  }
  return groups;
}

export function resetCandidateCounter(): void {}
