/**
 * Beacon scoring — stage 3 for the `beacon` candidate type.
 *
 * Implanted software calls home on a schedule. That schedule is what this scorer looks
 * for: not the destination, not the payload, but the SHAPE of a repeated connection.
 *
 * Entity: `(src_ip, dest_ip, dest_port)` — one host talking to one service. Every Zeek
 * conn record for that triple is one session in the entity's history, and the features
 * are statistics over that history.
 *
 * Two gates come first, and they exist to keep the statistics honest. Fewer than
 * `min_connections` (10) sessions, or a history spanning less than `min_time_span_hours`
 * (2), and the entity is skipped entirely — a regularity computed over four connections
 * in ten minutes is noise wearing a number's clothes.
 *
 * SIX FEATURES, COMBINED AS A WEIGHTED SUM, because beaconing evidence ACCUMULATES:
 *
 *   regularity              0.30  MAD-consistency of the inter-arrival intervals. The
 *                                 core signal. A human's traffic is bursty; a timer's
 *                                 is not.
 *   bytes_out_consistency   0.15  MAD-consistency of bytes sent. A fixed-size heartbeat
 *   bytes_in_consistency    0.15  MAD-consistency of bytes received.   is a strong tell.
 *   duration_consistency    0.10  MAD-consistency of session durations.
 *   histogram_score         0.15  max(hourly coefficient of variation, bimodal score) —
 *                                 flat-across-the-day, or the two-peak shape a beacon
 *                                 with a sleep window produces.
 *   consecutive_hours       0.15  longest run of hours with at least one connection,
 *                                 normalized against 12 and wrapping midnight. Software
 *                                 keeps working at 3am; people do not.
 *
 * Each alone is weak — plenty of legitimate software polls on a timer, which is exactly
 * why the sample dataset's top-scoring beacon is an EDR agent. The composite is what
 * carries information, and even then the answer is "look at this", not "this is bad".
 *
 * Candidates are sorted by score descending and given deterministic content-derived ids.
 */

import type { ConnLogEvent } from '../../schema/events.js';
import type { BeaconCandidate } from '../../schema/candidates.js';
import { mean, median, stddev, mad, madConsistency, round } from '../../stats/descriptive.js';
import { assignDeterministicCandidateIds } from './candidate-id.js';

// ─── Configuration ──────────────────────────────────────────

export interface BeaconConfig {
  min_connections: number;
  min_time_span_hours: number;
  histogram_bimodal_min_hours: number;
  histogram_bimodal_outlier_removal: number;
  histogram_mode_sensitivity: number;  // bin size as fraction of max count
  consecutive_hours_ideal: number;     // normalization target
}

export const DEFAULT_BEACON_CONFIG: BeaconConfig = {
  min_connections: 10,
  min_time_span_hours: 2,
  histogram_bimodal_min_hours: 11,
  histogram_bimodal_outlier_removal: 1,
  histogram_mode_sensitivity: 0.05,
  consecutive_hours_ideal: 12,
};

// ─── Core Scoring ───────────────────────────────────────────

export function scoreBeaconCandidates(
  events: ConnLogEvent[],
  config: BeaconConfig = DEFAULT_BEACON_CONFIG,
): BeaconCandidate[] {
  const groups = groupByEntityKey(events);
  const candidates: BeaconCandidate[] = [];

  for (const [key, entries] of groups) {
    if (entries.length < config.min_connections) continue;

    const timestamps = entries.map(e => new Date(e.timestamp).getTime() / 1000).sort((a, b) => a - b);
    const timeSpanHours = (timestamps[timestamps.length - 1] - timestamps[0]) / 3600;

    if (timeSpanHours < config.min_time_span_hours) continue;

    // ── Interval analysis ─────────────────────────────────
    const intervals = computeIntervals(timestamps);
    if (intervals.length === 0) continue;

    const medianInterval = median(intervals);
    if (medianInterval === 0) continue;

    const regularity = madConsistency(intervals);
    const meanInterval = mean(intervals);
    const stdInterval = stddev(intervals);

    // Jitter: MAD of intervals (raw spread in seconds)
    const jitterMad = mad(intervals);

    // ── Byte size analysis ────────────────────────────────
    const origBytesValues = entries
      .map(e => e.orig_bytes)
      .filter((v): v is number => v != null && v >= 0);
    const respBytesValues = entries
      .map(e => e.resp_bytes)
      .filter((v): v is number => v != null && v >= 0);

    const bytesOutConsistency = origBytesValues.length >= 3 ? madConsistency(origBytesValues) : 0;
    const bytesInConsistency = respBytesValues.length >= 3 ? madConsistency(respBytesValues) : 0;

    const bytesOutTotal = origBytesValues.reduce((s, v) => s + v, 0);
    const bytesInTotal = respBytesValues.reduce((s, v) => s + v, 0);
    const bytesRatio = bytesInTotal > 0 ? bytesOutTotal / bytesInTotal : Infinity;

    // ── Duration analysis ─────────────────────────────────
    const durations = entries
      .map(e => e.duration)
      .filter((v): v is number => v != null && v > 0);

    const durationConsistency = durations.length >= 3 ? madConsistency(durations) : 0;

    const consecutiveHours = computeConsecutiveHours(timestamps);

    // ── Histogram / periodicity ───────────────────────────
    const hourlyBins = computeHourlyBins(timestamps);
    const histogramCv = computeHistogramCv(hourlyBins);
    const bimodalScore = computeBimodalScore(hourlyBins, config);
    const histogramScore = Math.max(histogramCv, bimodalScore);

    // ── Composite score ───────────────────────────────────
    const consecutiveHoursNorm = Math.min(consecutiveHours / config.consecutive_hours_ideal, 1.0);
    const beaconScore =
      regularity * 0.30 +
      bytesOutConsistency * 0.15 +
      bytesInConsistency * 0.15 +
      durationConsistency * 0.10 +
      histogramScore * 0.15 +
      consecutiveHoursNorm * 0.15;

    // ── Build candidate record ────────────────────────────
    const [srcIp, destIp, destPort] = key.split('|');

    candidates.push({
      candidate_id: '',
      type: 'beacon',
      src_ip: srcIp,
      dest_ip: destIp,
      dest_port: parseInt(destPort),
      observed_service: resolveObservedService(entries),
      time_window_start: new Date(timestamps[0] * 1000).toISOString(),
      time_window_end: new Date(timestamps[timestamps.length - 1] * 1000).toISOString(),

      regularity: round(regularity, 4),
      mean_interval_sec: round(meanInterval, 2),
      std_interval_sec: round(stdInterval, 2),
      jitter_mad: round(jitterMad, 4),

      bytes_out_consistency: round(bytesOutConsistency, 4),
      bytes_in_consistency: round(bytesInConsistency, 4),
      bytes_out_total: bytesOutTotal,
      bytes_in_total: bytesInTotal,
      bytes_ratio: round(bytesRatio, 4),

      duration_consistency: round(durationConsistency, 4),
      consecutive_hours: consecutiveHours,
      session_count: entries.length,
      time_span_hours: round(timeSpanHours, 2),

      histogram_cv: round(histogramCv, 4),
      bimodal_score: round(bimodalScore, 4),
      histogram_score: round(histogramScore, 4),

      beacon_score: round(beaconScore, 4),

      // Attribution — populated by Stage 3B, not here
      process_name: null,
      process_id: null,

      // Enrichment — populated by Stage 4, not here
      enrichment: {},

      // Evidence trail
      evidence: {
        constituent_event_ids: entries.map(e => e.id),
      },
    });
  }

  // Sort by beacon_score descending
  candidates.sort((a, b) => b.beacon_score - a.beacon_score);
  return assignDeterministicCandidateIds('BCN', candidates);
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

function resolveObservedService(events: readonly ConnLogEvent[]): string | null {
  const services = new Set(
    events.flatMap((event) => {
      const service = event.service?.trim().toLowerCase();
      return service ? [service] : [];
    }),
  );
  return services.size === 1 ? services.values().next().value ?? null : null;
}

function computeIntervals(sortedTimestamps: number[]): number[] {
  const intervals: number[] = [];
  for (let i = 1; i < sortedTimestamps.length; i++) {
    intervals.push(sortedTimestamps[i] - sortedTimestamps[i - 1]);
  }
  return intervals;
}

/**
 * Compute longest run of consecutive hours with at least one connection.
 * Wraps around (activity at hour 23 and hour 0 counts as consecutive).
 */
function computeConsecutiveHours(sortedTimestamps: number[]): number {
  if (sortedTimestamps.length === 0) return 0;

  // Bucket timestamps into hours
  const hourSet = new Set<number>();
  for (const ts of sortedTimestamps) {
    hourSet.add(Math.floor(ts / 3600));
  }

  if (hourSet.size === 0) return 0;
  if (hourSet.size === 1) return 1;

  const hours = [...hourSet].sort((a, b) => a - b);

  // Find longest run of consecutive hour values
  let maxRun = 1;
  let currentRun = 1;

  for (let i = 1; i < hours.length; i++) {
    if (hours[i] === hours[i - 1] + 1) {
      currentRun++;
      maxRun = Math.max(maxRun, currentRun);
    } else {
      currentRun = 1;
    }
  }

  // Check wraparound: does last hour connect to first via wrap?
  // This handles beacons spanning midnight (e.g., 22,23,0,1,2)
  if (hours.length >= 2) {
    const firstHourOfDay = hours[0] % 24;
    const lastHourOfDay = hours[hours.length - 1] % 24;

    // Only check wrap if the span covers less than 24 unique hours
    if (hourSet.size < 24 && lastHourOfDay === 23 && firstHourOfDay === 0) {
      // Count backward from end and forward from start
      let wrapRun = 0;
      let j = hours.length - 1;
      while (j > 0 && hours[j] === hours[j - 1] + 1) { wrapRun++; j--; }
      wrapRun++; // include hours[j]
      let k = 0;
      while (k < hours.length - 1 && hours[k + 1] === hours[k] + 1) { wrapRun++; k++; }
      wrapRun++; // include hours[k]
      // Subtract 1 because we double-counted the boundary
      maxRun = Math.max(maxRun, wrapRun - 1);
    }
  }

  return maxRun;
}

/**
 * Bin timestamps into 24 hourly buckets (hour-of-day, 0-23).
 * Returns array of 24 counts.
 */
function computeHourlyBins(sortedTimestamps: number[]): number[] {
  const bins = new Array(24).fill(0);
  for (const ts of sortedTimestamps) {
    const hour = new Date(ts * 1000).getUTCHours();
    bins[hour]++;
  }
  return bins;
}

/**
 * Histogram CV score: 1 - CV of hourly bin counts (non-zero bins only).
 * Flat distribution = low CV = high score.
 */
function computeHistogramCv(hourlyBins: number[]): number {
  const nonZero = hourlyBins.filter(c => c > 0);
  if (nonZero.length < 2) return 0;

  const m = mean(nonZero);
  if (m === 0) return 0;

  const s = stddev(nonZero);
  const histCv = s / m;
  return Math.max(0, Math.min(1, 1 - histCv));
}

/**
 * Bimodal detection: identify if the histogram has two dominant modes.
 * Catches beacons alternating between active/sleep periods.
 *
 * Based on RITA's approach:
 * 1. Group bins by frequency into mode buckets (sensitivity = 5% of max)
 * 2. Find top 2 modes by count of bins
 * 3. Score = proportion of bins accounted for by top 2 modes
 */
function computeBimodalScore(hourlyBins: number[], config: BeaconConfig): number {
  const nonZero = hourlyBins.filter(c => c > 0);
  if (nonZero.length < config.histogram_bimodal_min_hours) return 0;

  const maxCount = Math.max(...hourlyBins);
  if (maxCount === 0) return 0;

  const binSize = Math.max(1, Math.floor(maxCount * config.histogram_mode_sensitivity));

  // Group hourly counts into frequency bins
  const modeBuckets = new Map<number, number>();
  for (const count of hourlyBins) {
    const bucket = Math.floor(count / binSize);
    modeBuckets.set(bucket, (modeBuckets.get(bucket) ?? 0) + 1);
  }

  // Sort modes by count of bars (descending)
  const sortedModes = [...modeBuckets.values()].sort((a, b) => b - a);

  if (sortedModes.length < 2) return 0;

  const top2 = sortedModes[0] + sortedModes[1];
  const totalBars = 24 - config.histogram_bimodal_outlier_removal;

  return Math.min(1, top2 / Math.max(1, totalBars));
}

export function resetCandidateCounter(): void {}
