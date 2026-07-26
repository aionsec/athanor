/**
 * The ordering rule — how raw dialect files become canon-ordered normalized events.
 *
 * Raw logs do NOT carry event ids. Ids are `evt-%05d`, assigned by a global timestamp
 * sort over every dialect at once, so ingest must REPRODUCE that sequence rather than
 * read it: merge every parsed dialect by (timestamp ms, dialect rank), then number the
 * result.
 *
 * `DIALECT_ORDER_RANK` and the comparator below are a CONTRACT with whatever wrote the
 * logs. The renderer that produces the sample dataset runs the identical rule over its
 * own output as a mandatory self-check, and if the two ever diverge, ids drift — and
 * every content-addressed candidate id downstream drifts with them.
 *
 * Only `zeek/conn` (0) before `sysmon/network_connect` (1) is grounded in data — all 149
 * equal-timestamp groups in the sample dataset are exactly that pair, the network and
 * endpoint views of one connection. The other two ranks exist to give the rule a total
 * order.
 *
 * THE CONSEQUENCE, which is inherent to the id model rather than a defect: adding a file
 * to a telemetry folder inserts records into this sequence and renumbers everything after
 * them. Same folder, same ids, always. Different folder, different ids.
 */

import type { TelemetryEvent } from '../schema/events.js';
import { IngestError, isoFromMs } from './codecs.js';

export const DIALECT_KINDS = [
  'zeek/conn',
  'zeek/ssl',
  'sysmon/process_create',
  'sysmon/network_connect',
  'powershell/script_block',
] as const;

export type DialectKind = (typeof DIALECT_KINDS)[number];

/** Tiebreak ranks for the id-reconstruction ordering rule. Mirrors the emitter. */
export const DIALECT_ORDER_RANK: Readonly<Record<string, number>> = {
  'zeek/conn': 0,
  'sysmon/network_connect': 1,
  'zeek/ssl': 2,
  'sysmon/process_create': 3,
};

/** One parsed raw line: the normalized event MINUS its id, plus the ordering keys. */
export interface ParsedEvent {
  dialect: DialectKind;
  timestampMs: number;
  /** Normalized fields, id excluded — `mergeAndAssignIds` supplies the id. */
  event: Record<string, unknown>;
  /** Source coordinates, for ambiguity reports. */
  origin: string;
}

/** Canon id shape: `evt-` + the 1-based merge index padded to five digits. */
export function assignEventId(index: number): string {
  return `evt-${String(index + 1).padStart(5, '0')}`;
}

/**
 * Two records the rule cannot order: identical timestamp AND identical dialect.
 * The emitter REFUSES to render such an input (canon ids would be unreproducible);
 * ingest of a real estate must not refuse, so the merge falls back to file/line
 * order and reports the pairs here for the caller to surface.
 */
export interface OrderingAmbiguity {
  dialect: DialectKind;
  timestamp: string;
  origins: [string, string];
}

interface Ordered extends ParsedEvent {
  sequence: number;
}

function sortByRule(parsed: ReadonlyArray<ParsedEvent>): Ordered[] {
  const records: Ordered[] = parsed.map((item, sequence) => ({ ...item, sequence }));

  // VERBATIM from the emitter's `reconstructOrder`. Records that tie on BOTH keys
  // keep their input order (Array.prototype.sort is stable — ES2019), which is
  // deterministic here because the folder scan reads files in sorted-name order and
  // each file in line order.
  records.sort((left, right) => {
    if (left.timestampMs !== right.timestampMs) return left.timestampMs - right.timestampMs;
    const leftRank = DIALECT_ORDER_RANK[left.dialect] ?? Number.MAX_SAFE_INTEGER;
    const rightRank = DIALECT_ORDER_RANK[right.dialect] ?? Number.MAX_SAFE_INTEGER;
    return leftRank - rightRank;
  });

  return records;
}

/** Pairs the ordering rule cannot separate, in merged order. */
export function findOrderingAmbiguities(parsed: ReadonlyArray<ParsedEvent>): OrderingAmbiguity[] {
  const records = sortByRule(parsed);
  const out: OrderingAmbiguity[] = [];
  for (let index = 1; index < records.length; index += 1) {
    const previous = records[index - 1]!;
    const current = records[index]!;
    if (previous.timestampMs === current.timestampMs && previous.dialect === current.dialect) {
      out.push({
        dialect: current.dialect,
        timestamp: isoFromMs(current.timestampMs),
        origins: [previous.origin, current.origin],
      });
    }
  }
  return out;
}

/** Number of equal-timestamp groups in the merged sequence (the emitter reports the same stat). */
export function countEqualTimestampGroups(parsed: ReadonlyArray<ParsedEvent>): number {
  const records = sortByRule(parsed);
  let groups = 0;
  for (let index = 1; index < records.length; index += 1) {
    if (records[index]!.timestampMs === records[index - 1]!.timestampMs) {
      if (index === 1 || records[index - 1]!.timestampMs !== records[index - 2]!.timestampMs) {
        groups += 1;
      }
    }
  }
  return groups;
}

/**
 * The rule: merge-sort every parsed dialect by (timestamp ms, dialect rank) and
 * assign `evt-%05d` by 1-based index. This is what makes a folder of raw logs
 * reproduce the canon event stream exactly.
 */
export function mergeAndAssignIds(parsed: ReadonlyArray<ParsedEvent>): TelemetryEvent[] {
  return sortByRule(parsed).map(
    (item, index) => ({ id: assignEventId(index), ...item.event }) as unknown as TelemetryEvent,
  );
}

/** The identity tuple the sequence check compares. */
export interface SequenceEntry {
  id: string;
  source: string;
  event_type: string;
  timestamp: string;
}

export function toSequence(events: ReadonlyArray<Record<string, unknown>>): SequenceEntry[] {
  return events.map((event) => ({
    id: String(event.id),
    source: String(event.source),
    event_type: String(event.event_type),
    timestamp: String(event.timestamp),
  }));
}

/**
 * The emitter's self-check, exposed for ingest: assert a reconstructed event stream
 * matches an expected (id, source, event_type, timestamp) sequence element by
 * element. Fails naming the FIRST divergent position, so a round-trip regression
 * localizes to one event instead of to a candidate diff.
 */
export function assertSequenceMatches(
  reconstructed: ReadonlyArray<Record<string, unknown>>,
  expected: ReadonlyArray<SequenceEntry>,
): void {
  const got = toSequence(reconstructed);
  if (got.length !== expected.length) {
    throw new IngestError(
      `sequence check: reconstructed ${got.length} events but expected ${expected.length}`,
    );
  }
  for (let index = 0; index < expected.length; index += 1) {
    const want = expected[index]!;
    const have = got[index]!;
    if (
      have.id !== want.id
      || have.source !== want.source
      || have.event_type !== want.event_type
      || have.timestamp !== want.timestamp
    ) {
      throw new IngestError(
        `sequence check: diverges at position ${index + 1} — expected `
        + `(${want.id}, ${want.source}/${want.event_type}, ${want.timestamp}) but got `
        + `(${have.id}, ${have.source}/${have.event_type}, ${have.timestamp})`,
      );
    }
  }
}
