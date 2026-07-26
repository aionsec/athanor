// The distillation factory's own seams, tested at the factory rather than through a
// per-type runner: the `postScore` hook, the stage-3B attribution chaining, and the
// array isolation between the scorer and everything downstream of it.
//
// Three claims about the factory's contract, all exercised on a beacon candidate over the
// conn -> network_connect -> process_create chain: omitting `postScore` equals supplying an
// identity `postScore`, the hook's RETURN value is what downstream stages see, and
// attribution runs inside the chain when EID 3 telemetry is present.
//
// The fourth case pins the array isolation described in `runner-factory.ts`: a scorer that
// reverses and truncates its input must not be able to move attribution or the frequency
// tables. Without the defensive copy it could, and nothing would report it.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createDistillationRunner } from '../../src/run/runner-factory.js';
import { selectConnEvents, type DistillationStage1Events } from '../../src/run/select.js';
import type { PostEnrichmentCandidate } from '../../src/pipeline/types/post-enrichment-candidate.js';
import type { PreEnrichmentCandidate } from '../../src/pipeline/types/pre-enrichment-candidate.js';

/** conn -> network_connect -> process_create on one host: the attribution chain. */
const EVENTS = [
  {
    id: 'evt-proc-1',
    timestamp: '2026-03-09T14:00:28.000Z',
    source: 'sysmon',
    event_type: 'process_create',
    host: 'DEV-WS03',
    process_guid: '{proc-1}',
    process_name: 'svchost-health.exe',
    process_path: 'C:\\Users\\jane\\AppData\\Local\\Temp\\svchost-health.exe',
    process_id: 5006,
    parent_process_guid: '{proc-parent}',
    parent_process_name: 'powershell.exe',
    parent_process_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    user: 'CORP\\jane',
  },
  {
    id: 'evt-eid3-1',
    timestamp: '2026-03-09T14:00:30.005Z',
    source: 'sysmon',
    event_type: 'network_connect',
    host: 'DEV-WS03',
    src_ip: '10.42.10.45',
    src_port: 49600,
    dest_ip: '185.225.73.217',
    dest_port: 443,
    process_guid: '{proc-1}',
    process_name: 'svchost-health.exe',
    process_id: 5006,
    user: 'CORP\\jane',
  },
  {
    id: 'evt-conn-1',
    timestamp: '2026-03-09T14:00:30.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.42.10.45',
    src_port: 49600,
    dest_ip: '185.225.73.217',
    dest_port: 443,
    proto: 'tcp',
    zeek_uid: 'C001',
  },
] as unknown as DistillationStage1Events;

function beaconCandidate(): PreEnrichmentCandidate {
  return {
    candidate_id: 'BCN-0000000000000001',
    type: 'beacon',
    time_window_start: '2026-03-09T14:00:00.000Z',
    time_window_end: '2026-03-09T14:01:00.000Z',
    src_ip: '10.42.10.45',
    dest_ip: '185.225.73.217',
    dest_port: 443,
    beacon_score: 0.9,
    process_name: null,
    process_id: null,
    enrichment: {},
    evidence: { constituent_event_ids: ['evt-conn-1'] },
  } as unknown as PreEnrichmentCandidate;
}

const BASE_CONFIG = {
  candidateType: 'beacon' as const,
  selectScorerInput: selectConnEvents,
  scoreCandidates: () => [beaconCandidate()],
};

describe('createDistillationRunner — the postScore seam', () => {
  it('treats an omitted postScore as an identity postScore', () => {
    const without = createDistillationRunner(BASE_CONFIG).withContext(EVENTS);
    const identity = createDistillationRunner({
      ...BASE_CONFIG,
      postScore: (candidates) => candidates,
    }).withContext(EVENTS);

    assert.deepEqual(identity.candidates, without.candidates);
    assert.deepEqual(identity.events, without.events);
  });

  it('hands postScore the scored candidates and the FULL stage-2 event set', () => {
    let observed: { candidateCount: number; eventCount: number } | null = null;
    const result = createDistillationRunner({
      ...BASE_CONFIG,
      postScore: (candidates, events) => {
        observed = { candidateCount: candidates.length, eventCount: events.length };
        return [];
      },
    }).withContext(EVENTS);

    // The scorer saw one conn event; postScore sees all three, as every stage after
    // the scorer does.
    assert.deepEqual(observed, { candidateCount: 1, eventCount: EVENTS.length });
    assert.equal(result.events.length, EVENTS.length);
  });

  it('makes postScore\'s RETURN the source of truth downstream, not its input', () => {
    const dropped = createDistillationRunner({
      ...BASE_CONFIG,
      postScore: () => [],
    }).withContext(EVENTS);
    assert.equal(dropped.candidates.length, 0, 'a postScore that returns nothing emits nothing');

    const replaced = createDistillationRunner({
      ...BASE_CONFIG,
      postScore: () => [
        { ...beaconCandidate(), candidate_id: 'BCN-0000000000000002' } as PreEnrichmentCandidate,
      ],
    }).withContext(EVENTS);
    assert.deepEqual(
      replaced.candidates.map((candidate) => candidate.candidate_id),
      ['BCN-0000000000000002'],
      'the candidate that reaches stage 3B is the one postScore returned',
    );
  });
});

describe('createDistillationRunner — stage 3B attribution in the chain', () => {
  it('attributes a conn-derived candidate to its process when EID 3 telemetry is present', () => {
    const result = createDistillationRunner(BASE_CONFIG).withContext(EVENTS);

    assert.equal(result.candidates.length, 1);
    const candidate = result.candidates[0] as unknown as Record<string, unknown>;
    assert.equal(candidate.process_name, 'svchost-health.exe');
    assert.equal(candidate.process_id, 5006);
    const attribution = candidate.attribution as Record<string, unknown>;
    assert.equal(attribution.confidence, 'full');
    assert.equal(attribution.process_guid, '{proc-1}');
  });

  it('stamps no attribution block at all on a folder with no endpoint view', () => {
    // A network-only estate has no bridge telemetry, so attribution is skipped rather
    // than stamped `unavailable` — the candidate passes through as it scored. The
    // distinction is visible to a student the moment they run athanor on Zeek alone.
    const networkOnly = EVENTS.filter(
      (event) => (event as unknown as Record<string, unknown>).event_type === 'conn',
    ) as unknown as DistillationStage1Events;

    const result = createDistillationRunner(BASE_CONFIG).withContext(networkOnly);
    const candidate = result.candidates[0] as unknown as Record<string, unknown>;
    assert.equal(Object.hasOwn(candidate, 'attribution'), false);
    assert.equal(candidate.process_name, null);
  });

  it('stamps `unavailable` when EID 3 telemetry exists but matches nothing', () => {
    const unrelatedEid3 = {
      ...(EVENTS[1] as unknown as Record<string, unknown>),
      id: 'evt-eid3-2',
      dest_ip: '203.0.113.9',
    };
    const events = [
      EVENTS[0] as unknown as Record<string, unknown>,
      unrelatedEid3,
      EVENTS[2] as unknown as Record<string, unknown>,
    ] as unknown as DistillationStage1Events;

    const result = createDistillationRunner(BASE_CONFIG).withContext(events);
    const candidate = result.candidates[0] as unknown as Record<string, unknown>;
    const attribution = candidate.attribution as Record<string, unknown>;
    assert.equal(attribution.confidence, 'unavailable');
    assert.deepEqual(
      attribution.data_quality_flags,
      ['no_eid3_match', 'partial_evidence_unattributed'],
      'the conn evidence WAS resolvable, so the miss is recorded as partial, not absent',
    );
  });
});

describe('createDistillationRunner — the scorer is isolated from the later stages', () => {
  it('gives the scorer an array instance no later stage consumes', () => {
    // `selectTelemetryEvents` returns its argument by cast, so aliasing
    // the two arrays handed the scorer the very array attribution and the LFA
    // precompute go on to read. A scorer that sorts its input for convenience would
    // then reorder evidence and rarity tables from underneath them.
    let scorerInput: unknown[] = [];
    const result = createDistillationRunner({
      candidateType: 'beacon' as const,
      selectScorerInput: (events) => {
        scorerInput = events;
        return selectConnEvents(events);
      },
      scoreCandidates: () => [beaconCandidate()],
    }).withContext(EVENTS);

    assert.notEqual(scorerInput, result.events, 'the scorer must not hold the downstream array');
    assert.deepEqual(scorerInput.length, result.events.length, 'it is a copy, not a subset');
  });

  it('survives a scorer that mutates the array it was handed', () => {
    const clean = createDistillationRunner(BASE_CONFIG).withContext(EVENTS);
    const vandal = createDistillationRunner({
      candidateType: 'beacon' as const,
      selectScorerInput: (events) => {
        events.reverse();
        events.length = 1;
        return selectConnEvents(events);
      },
      scoreCandidates: (): PostEnrichmentCandidate[] => [
        beaconCandidate() as unknown as PostEnrichmentCandidate,
      ],
    }).withContext(EVENTS);

    assert.deepEqual(
      vandal.events.map((event) => (event as unknown as Record<string, unknown>).id),
      clean.events.map((event) => (event as unknown as Record<string, unknown>).id),
      'attribution and LFA still see the full stream in its original order',
    );
    assert.deepEqual(vandal.candidates, clean.candidates);
  });
});
