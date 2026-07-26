import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scoreBeaconCandidates, resetCandidateCounter, DEFAULT_BEACON_CONFIG } from '../../src/pipeline/score/beacon.js';
import type { ConnLogEvent } from '../../src/schema/events.js';

function makeConnEvents(
  count: number,
  intervalS: number,
  opts: {
    jitterPct?: number;
    origBytes?: number;
    origBytesJitter?: number;
    respBytes?: number;
    respBytesJitter?: number;
    duration?: number;
    durationJitter?: number;
    srcIp?: string;
    destIp?: string;
    destPort?: number;
    service?: string;
    seed?: number;
  } = {},
): ConnLogEvent[] {
  const {
    jitterPct = 0, origBytes = 100, origBytesJitter = 0,
    respBytes = 500, respBytesJitter = 0, duration = 0.1, durationJitter = 0,
    srcIp = '10.0.0.1', destIp = '192.168.1.1', destPort = 443,
    service, seed = 123456789,
  } = opts;

  const events: ConnLogEvent[] = [];
  const baseTime = new Date('2025-07-14T06:00:00Z').getTime();
  let state = seed >>> 0;

  const nextRandom = (): number => {
    // Deterministic LCG for stable CI behavior across test runs.
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };

  const nextSignedRandom = (): number => nextRandom() * 2 - 1;

  for (let i = 0; i < count; i++) {
    const jitterMs = intervalS * 1000 * (jitterPct / 100) * nextSignedRandom();
    const ts = baseTime + i * intervalS * 1000 + jitterMs;

    const obJitter = origBytes * (origBytesJitter / 100) * nextSignedRandom();
    const rbJitter = respBytes * (respBytesJitter / 100) * nextSignedRandom();
    const dJitter = duration * (durationJitter / 100) * nextSignedRandom();

    events.push({
      id: `evt-${String(i + 1).padStart(5, '0')}`,
      timestamp: new Date(ts).toISOString(),
      source: 'zeek',
      event_type: 'conn',
      src_ip: srcIp,
      dest_ip: destIp,
      dest_port: destPort,
      proto: 'tcp',
      ...(service ? { service } : {}),
      orig_bytes: Math.max(1, Math.round(origBytes + obJitter)),
      resp_bytes: Math.max(1, Math.round(respBytes + rbJitter)),
      duration: Math.max(0.001, duration + dJitter),
      zeek_uid: `C${i}`,
    });
  }
  return events;
}

describe('Beacon scoring', () => {
  it('produces no candidates below min_connections', () => {
    resetCandidateCounter();
    const events = makeConnEvents(5, 60);
    const result = scoreBeaconCandidates(events);
    assert.equal(result.length, 0);
  });

  it('produces a candidate with sufficient data', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60); // 150 min = 2.5 hours, exceeds min_time_span_hours
    const result = scoreBeaconCandidates(events);
    assert.equal(result.length, 1);
    assert.equal(result[0].type, 'beacon');
    assert.equal(result[0].session_count, 150);
  });

  it('emits one normalized observed service and preserves ambiguity', () => {
    resetCandidateCounter();
    const ssl = scoreBeaconCandidates(makeConnEvents(150, 60, { service: ' SSL ' }));
    assert.equal(ssl[0].observed_service, 'ssl');

    resetCandidateCounter();
    const mixed = makeConnEvents(150, 60, { service: 'ssl' });
    mixed[0].service = 'http';
    assert.equal(scoreBeaconCandidates(mixed)[0].observed_service, null);

    resetCandidateCounter();
    assert.equal(scoreBeaconCandidates(makeConnEvents(150, 60))[0].observed_service, null);
  });

  it('perfect beacon scores high regularity', () => {
    resetCandidateCounter();
    const events = makeConnEvents(200, 60, { jitterPct: 0 });
    const result = scoreBeaconCandidates(events);
    assert.equal(result.length, 1);
    assert.ok(result[0].regularity >= 0.95, `regularity ${result[0].regularity} should be >= 0.95`);
  });

  it('high jitter scores lower regularity', () => {
    resetCandidateCounter();
    const events = makeConnEvents(200, 60, { jitterPct: 40 });
    const result = scoreBeaconCandidates(events);
    assert.equal(result.length, 1);
    assert.ok(result[0].regularity < 0.8, `regularity ${result[0].regularity} should be < 0.8 with 40% jitter`);
  });

  it('uniform bytes score high consistency', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60, {
      origBytes: 120, origBytesJitter: 2,
      respBytes: 480, respBytesJitter: 2,
    });
    const result = scoreBeaconCandidates(events);
    assert.ok(result[0].bytes_out_consistency >= 0.9, `bytes_out ${result[0].bytes_out_consistency} should be >= 0.9`);
    assert.ok(result[0].bytes_in_consistency >= 0.9, `bytes_in ${result[0].bytes_in_consistency} should be >= 0.9`);
  });

  it('random bytes score low consistency', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60, {
      origBytes: 120, origBytesJitter: 80,
      respBytes: 480, respBytesJitter: 80,
    });
    const result = scoreBeaconCandidates(events);
    assert.ok(result[0].bytes_out_consistency < 0.7, `bytes_out ${result[0].bytes_out_consistency} should be < 0.7`);
    assert.ok(result[0].bytes_in_consistency < 0.7, `bytes_in ${result[0].bytes_in_consistency} should be < 0.7`);
  });

  it('duration consistency is high for uniform durations', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60, { duration: 0.1, durationJitter: 3 });
    const result = scoreBeaconCandidates(events);
    assert.ok(result[0].duration_consistency >= 0.9,
      `duration_consistency ${result[0].duration_consistency} should be >= 0.9 with 3% jitter`);
  });

  it('computes histogram features', () => {
    resetCandidateCounter();
    // 8 hours of data → should populate multiple hourly bins
    const events = makeConnEvents(480, 60);
    const result = scoreBeaconCandidates(events);
    assert.ok(result[0].histogram_cv >= 0, 'histogram_cv computed');
    assert.ok(result[0].histogram_score >= 0, 'histogram_score computed');
    assert.ok(result[0].consecutive_hours >= 7, `consecutive hours ${result[0].consecutive_hours} should be >= 7`);
  });

  it('composite beacon_score is bounded [0, 1]', () => {
    resetCandidateCounter();
    const events = makeConnEvents(200, 60);
    const result = scoreBeaconCandidates(events);
    assert.ok(result[0].beacon_score >= 0 && result[0].beacon_score <= 1,
      `beacon_score ${result[0].beacon_score} should be in [0, 1]`);
  });

  it('perfect beacon scores higher composite than sloppy', () => {
    resetCandidateCounter();
    const perfect = makeConnEvents(200, 60, {
      jitterPct: 0, origBytesJitter: 0, respBytesJitter: 0, durationJitter: 0,
    });
    const perfectResult = scoreBeaconCandidates(perfect);

    resetCandidateCounter();
    const sloppy = makeConnEvents(200, 60, {
      jitterPct: 40, origBytesJitter: 60, respBytesJitter: 60, durationJitter: 50,
    });
    const sloppyResult = scoreBeaconCandidates(sloppy);

    assert.ok(perfectResult[0].beacon_score > sloppyResult[0].beacon_score,
      `perfect ${perfectResult[0].beacon_score} should beat sloppy ${sloppyResult[0].beacon_score}`);
  });

  it('groups by entity key — different dest_ports produce separate candidates', () => {
    resetCandidateCounter();
    const events443 = makeConnEvents(150, 60, { destPort: 443 });
    const events80 = makeConnEvents(150, 60, { destPort: 80 });
    const result = scoreBeaconCandidates([...events443, ...events80]);
    assert.equal(result.length, 2, 'should produce 2 candidates for 2 different ports');
  });

  it('populates evidence trail with event IDs', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60);
    const result = scoreBeaconCandidates(events);
    assert.equal(result[0].evidence.constituent_event_ids.length, 150);
  });

  it('attribution fields are null (populated by later pipeline stage)', () => {
    resetCandidateCounter();
    const events = makeConnEvents(150, 60);
    const result = scoreBeaconCandidates(events);
    assert.equal(result[0].process_name, null);
    assert.equal(result[0].process_id, null);
  });

  it('jitter_mad increases with higher jitter', () => {
    resetCandidateCounter();
    const tight = makeConnEvents(150, 60, { jitterPct: 3 });
    const tightResult = scoreBeaconCandidates(tight);

    resetCandidateCounter();
    const sloppy = makeConnEvents(150, 60, { jitterPct: 35 });
    const sloppyResult = scoreBeaconCandidates(sloppy);

    assert.ok(sloppyResult[0].jitter_mad > tightResult[0].jitter_mad,
      `sloppy jitter_mad ${sloppyResult[0].jitter_mad} should be > tight ${tightResult[0].jitter_mad}`);
  });
});
