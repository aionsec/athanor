// Unit — the ordering rule. This is the contract that makes raw logs reproduce the same
// event ids every time, and it is SHARED with whatever wrote the logs: the renderer that
// produces `fixtures/raw/` runs the identical rule over its own output as a self-check.
// The literal below pins athanor's half, so a drift on either side fails HERE, loudly,
// instead of silently renumbering every event and every content-derived candidate id
// downstream.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertSequenceMatches,
  assignEventId,
  countEqualTimestampGroups,
  DIALECT_ORDER_RANK,
  findOrderingAmbiguities,
  mergeAndAssignIds,
  type ParsedEvent,
  toSequence,
} from '../../src/ingest/merge.js';

function stub(dialect: ParsedEvent['dialect'], iso: string, tag: string): ParsedEvent {
  const [source, eventType] = dialect.split('/');
  return {
    dialect,
    timestampMs: Date.parse(iso),
    event: { timestamp: iso, source, event_type: eventType, tag },
    origin: `${tag}.log:1`,
  };
}

describe('ingest/merge — the shared ordering contract', () => {
  it('pins the dialect rank table VERBATIM — it is a contract, not a preference', () => {
    assert.deepEqual(DIALECT_ORDER_RANK, {
      'zeek/conn': 0,
      'sysmon/network_connect': 1,
      'zeek/ssl': 2,
      'sysmon/process_create': 3,
    });
  });

  it('assigns canon-shaped ids by 1-based merge index', () => {
    assert.equal(assignEventId(0), 'evt-00001');
    assert.equal(assignEventId(675), 'evt-00676');
    assert.equal(assignEventId(3858), 'evt-03859');
  });

  it('sorts by timestamp first, dialect rank second', () => {
    const merged = mergeAndAssignIds([
      stub('sysmon/process_create', '2026-03-09T12:00:00.000Z', 'eid1'),
      stub('sysmon/network_connect', '2026-03-09T12:00:00.000Z', 'eid3'),
      stub('zeek/ssl', '2026-03-09T12:00:00.000Z', 'ssl'),
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'conn'),
      stub('sysmon/process_create', '2026-03-09T11:59:59.999Z', 'earlier'),
    ]);

    assert.deepEqual(merged.map((event) => [event.id, (event as Record<string, unknown>).tag]), [
      ['evt-00001', 'earlier'],
      ['evt-00002', 'conn'],
      ['evt-00003', 'eid3'],
      ['evt-00004', 'ssl'],
      ['evt-00005', 'eid1'],
    ]);
  });

  it('puts an unranked dialect last within its timestamp (total order, never a crash)', () => {
    const merged = mergeAndAssignIds([
      stub('powershell/script_block', '2026-03-09T12:00:00.000Z', 'ps'),
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'conn'),
    ]);
    assert.deepEqual(merged.map((event) => (event as Record<string, unknown>).tag), ['conn', 'ps']);
  });

  it('reports — but does not refuse — a tie the rule cannot break', () => {
    const parsed = [
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'a'),
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'b'),
    ];

    const ambiguities = findOrderingAmbiguities(parsed);
    assert.equal(ambiguities.length, 1);
    assert.equal(ambiguities[0]!.dialect, 'zeek/conn');
    assert.equal(ambiguities[0]!.timestamp, '2026-03-09T12:00:00.000Z');

    // Ingest of a real estate must still produce a stream; the fallback is input
    // order (stable sort), which the folder scan makes deterministic.
    const merged = mergeAndAssignIds(parsed);
    assert.deepEqual(merged.map((event) => (event as Record<string, unknown>).tag), ['a', 'b']);
  });

  it('counts equal-timestamp groups the way the emitter self-check does', () => {
    assert.equal(countEqualTimestampGroups([
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'a'),
      stub('sysmon/network_connect', '2026-03-09T12:00:00.000Z', 'b'),
      stub('zeek/conn', '2026-03-09T12:00:01.000Z', 'c'),
      stub('zeek/conn', '2026-03-09T12:00:02.000Z', 'd'),
      stub('sysmon/network_connect', '2026-03-09T12:00:02.000Z', 'e'),
    ]), 2);
  });
});

describe('ingest/merge — the sequence check', () => {
  const expected = toSequence([
    { id: 'evt-00001', source: 'zeek', event_type: 'conn', timestamp: '2026-03-09T12:00:00.000Z' },
    { id: 'evt-00002', source: 'sysmon', event_type: 'network_connect', timestamp: '2026-03-09T12:00:00.000Z' },
  ]);

  it('passes when the reconstruction matches', () => {
    const merged = mergeAndAssignIds([
      stub('sysmon/network_connect', '2026-03-09T12:00:00.000Z', 'eid3'),
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'conn'),
    ]);
    assert.doesNotThrow(() => assertSequenceMatches(merged, expected));
  });

  it('names the first divergent position when it does not', () => {
    const merged = mergeAndAssignIds([
      stub('zeek/ssl', '2026-03-09T12:00:00.000Z', 'ssl'),
      stub('zeek/conn', '2026-03-09T12:00:00.000Z', 'conn'),
    ]);
    assert.throws(
      () => assertSequenceMatches(merged, expected),
      /diverges at position 2 — expected \(evt-00002, sysmon\/network_connect/,
    );
  });

  it('fails on a length mismatch', () => {
    assert.throws(
      () => assertSequenceMatches([], expected),
      /reconstructed 0 events but expected 2/,
    );
  });
});
