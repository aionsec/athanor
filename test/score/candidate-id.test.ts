import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateDeterministicCandidateId } from '../../src/pipeline/score/candidate-id.js';
import { scoreBeaconCandidates } from '../../src/pipeline/score/beacon.js';
import type { ConnLogEvent } from '../../src/schema/events.js';

function withMockedNow<T>(nowIso: string, run: () => T): T {
  const RealDate = Date;

  class MockDate extends RealDate {
    constructor(value?: string | number | Date) {
      if (arguments.length === 0) {
        super(nowIso);
        return;
      }
      super(value as string | number | Date);
    }

    static now(): number {
      return new RealDate(nowIso).getTime();
    }
  }

  globalThis.Date = MockDate as DateConstructor;
  try {
    return run();
  } finally {
    globalThis.Date = RealDate;
  }
}

function makeBeaconEvents(): ConnLogEvent[] {
  const baseTime = Date.parse('2025-07-14T06:00:00.000Z');
  return Array.from({ length: 150 }, (_, index) => ({
    id: `evt-${String(index + 1).padStart(5, '0')}`,
    timestamp: new Date(baseTime + index * 60_000).toISOString(),
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.1',
    dest_ip: '203.0.113.10',
    dest_port: 443,
    proto: 'tcp',
    orig_bytes: 120,
    resp_bytes: 480,
    duration: 0.5,
    zeek_uid: `C${index}`,
  }));
}

describe('deterministic candidate ids', () => {
  it('stay stable across object key order', () => {
    const first = generateDeterministicCandidateId('BCN', {
      type: 'beacon',
      src_ip: '10.0.0.1',
      dest_ip: '203.0.113.10',
      dest_port: 443,
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
    });

    const second = generateDeterministicCandidateId('BCN', {
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
      dest_port: 443,
      dest_ip: '203.0.113.10',
      src_ip: '10.0.0.1',
      type: 'beacon',
    });

    assert.equal(first, second);
  });

  it('stay stable across array order', () => {
    const first = generateDeterministicCandidateId('IMT', {
      type: 'intel_match',
      corroborating_sources: [
        { source: 'feed-a', source_tier: 'T1' },
        { source: 'feed-b', source_tier: 'T2' },
      ],
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
    });

    const second = generateDeterministicCandidateId('IMT', {
      type: 'intel_match',
      evidence: { constituent_event_ids: ['evt-2', 'evt-1'] },
      corroborating_sources: [
        { source_tier: 'T2', source: 'feed-b' },
        { source_tier: 'T1', source: 'feed-a' },
      ],
    });

    assert.equal(first, second);
  });

  it('change when the candidate payload changes', () => {
    const first = generateDeterministicCandidateId('BCN', {
      type: 'beacon',
      src_ip: '10.0.0.1',
      dest_ip: '203.0.113.10',
      dest_port: 443,
    });

    const second = generateDeterministicCandidateId('BCN', {
      type: 'beacon',
      src_ip: '10.0.0.1',
      dest_ip: '203.0.113.10',
      dest_port: 8443,
    });

    assert.notEqual(first, second);
  });

  it('ignore wall-clock date when scoring candidates', () => {
    const events = makeBeaconEvents();

    const first = withMockedNow('2026-04-19T23:56:00.000Z', () => scoreBeaconCandidates(events));
    const second = withMockedNow('2026-04-20T05:58:00.000Z', () => scoreBeaconCandidates(events));

    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.equal(first[0].candidate_id, second[0].candidate_id);
  });
});
