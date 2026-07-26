// The spine's own contract: stage order, the emit floors, presentation-id assignment, and
// the equivalence between `runPipeline` and `runBackHalf`.
//
// Exercised on beacon plus data_transfer, which is the pairing that also covers the real
// `data_transfer → DT` prefix override — the deterministic ids for that type carry the
// prefix DTR, so a presentation id of DT-001 proves the override was applied rather than
// inherited. Config-validation cases live in `test/run/config.test.ts`.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assignPresentationIds } from '../../src/run/presentation.js';
import { runBackHalf, runPipeline } from '../../src/run/runner.js';
import { repoRoot } from '../../src/lib/paths.js';
import type { TelemetryEvent } from '../../src/schema/events.js';
import type { PostEnrichmentEvent } from '../../src/pipeline/types/post-enrichment-event.js';

const BASE_TS = Date.parse('2026-04-11T00:00:00.000Z');

function buildBeaconConnEvent(idx: number, destIp: string, group: string): Record<string, unknown> {
  return {
    id: `evt-bcn-${group}-${String(idx + 1).padStart(3, '0')}`,
    timestamp: new Date(BASE_TS + idx * 15 * 60 * 1000).toISOString(),
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.10.10.5',
    dest_ip: destIp,
    dest_port: 443,
    proto: 'tcp',
    duration: 10,
    orig_bytes: 2048,
    resp_bytes: 4096,
  };
}

function buildDataTransferConnEvent(idx: number): Record<string, unknown> {
  return {
    id: `evt-dt-${String(idx + 1).padStart(3, '0')}`,
    timestamp: new Date(BASE_TS + idx * 15 * 60 * 1000).toISOString(),
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.10.10.42',
    dest_ip: '203.0.113.77',
    dest_port: 443,
    proto: 'tcp',
    service: 'ssl',
    conn_state: 'SF',
    duration: 1200,
    orig_bytes: 2_000_000,
    resp_bytes: 50_000,
  };
}

function buildEvents(): TelemetryEvent[] {
  return [
    ...Array.from({ length: 12 }, (_, idx) => buildBeaconConnEvent(idx, '203.0.113.10', 'a')),
    ...Array.from({ length: 12 }, (_, idx) => buildBeaconConnEvent(idx, '203.0.113.20', 'b')),
    ...Array.from({ length: 8 }, (_, idx) => buildDataTransferConnEvent(idx)),
  ] as unknown as TelemetryEvent[];
}

describe('athanor pipeline runner', () => {
  it('throws a clear error when the config resolves an unsupported candidate type', () => {
    assert.throws(
      () => runPipeline([], { candidateTypes: ['nonexistent_candidate_type'] }),
      /No per-candidate distillation runner registered for candidate type: nonexistent_candidate_type/,
    );
  });

  it('rewrites candidate ids when presentation ids are enabled, preserving order and provenance', () => {
    const events = buildEvents();
    const plain = runPipeline(events, { presentationIds: null });
    const enabled = runPipeline(events);

    assert.equal(enabled.candidates.length > 0, true);
    assert.equal(enabled.candidates.length, plain.candidates.length);

    // Provenance + array order: positionally, each candidate's
    // pipeline_candidate_id is the hash id the plain run emitted.
    assert.deepEqual(
      enabled.candidates.map((candidate) => candidate.pipeline_candidate_id),
      plain.candidates.map((candidate) => candidate.candidate_id),
    );

    // Sequential per-type ids: beacon keeps its native BCN prefix, the
    // data_transfer override applies (DTR → DT), and the top-ranked candidate of
    // each type is -001.
    const beaconIds = enabled.candidates
      .filter((candidate) => candidate.type === 'beacon')
      .map((candidate) => candidate.candidate_id);
    const dataTransferIds = enabled.candidates
      .filter((candidate) => candidate.type === 'data_transfer')
      .map((candidate) => candidate.candidate_id);
    assert.equal(beaconIds.length > 0, true);
    assert.equal(dataTransferIds.length > 0, true);
    for (const id of beaconIds) assert.match(id, /^BCN-\d{3}$/);
    for (const id of dataTransferIds) assert.match(id, /^DT-\d{3}$/);
    assert.equal(beaconIds.includes('BCN-001'), true);
    assert.equal(dataTransferIds.includes('DT-001'), true);

    // Only ids change: stripping both id fields, the runs are identical.
    const strip = (candidate: unknown) => {
      const { candidate_id, pipeline_candidate_id, ...rest } = candidate as Record<string, unknown>;
      void candidate_id;
      void pipeline_candidate_id;
      return rest;
    };
    assert.deepEqual(enabled.candidates.map(strip), plain.candidates.map(strip));
  });

  it('leaves candidate ids untouched when presentation ids are disabled', () => {
    const result = runPipeline(buildEvents(), {
      candidateTypes: ['beacon'],
      presentationIds: null,
    });

    assert.equal(result.candidates.length > 0, true);
    for (const candidate of result.candidates) {
      assert.match(candidate.candidate_id, /^BCN-[0-9a-f]{16}$/);
      assert.equal('pipeline_candidate_id' in candidate, false);
    }
  });

  it('applies per-type emit floors and returns the discards as caput mortuum', () => {
    const result = runPipeline(buildEvents(), { emitFloors: { data_transfer: 0.99 } });

    assert.ok(result.candidates.some((candidate) => candidate.type === 'beacon'));
    assert.equal(
      result.candidates.filter((candidate) => candidate.type === 'data_transfer').length,
      0,
    );
    // The floor does not delete: what it drops comes back as caput mortuum, fully
    // scored and enriched, still carrying its deterministic id.
    assert.equal(result.caputMortuum.length, 1);
    assert.equal(result.caputMortuum[0].type, 'data_transfer');
    assert.match(result.caputMortuum[0].candidate_id, /^DTR-[0-9a-f]{16}$/);
    assert.equal('pipeline_candidate_id' in result.caputMortuum[0], false);
  });

  it('assignPresentationIds ranks per type by score desc with hash-id tiebreak', () => {
    const candidates = [
      { candidate_id: 'BCN-cccc000000000003', type: 'beacon', beacon_score: 0.4 },
      { candidate_id: 'DTR-aaaa000000000001', type: 'data_transfer', data_transfer_score: 0.7 },
      { candidate_id: 'BCN-aaaa000000000001', type: 'beacon', beacon_score: 0.9 },
      { candidate_id: 'BCN-bbbb000000000002', type: 'beacon', beacon_score: 0.9 },
      { candidate_id: 'DTR-bbbb000000000002', type: 'data_transfer', data_transfer_score: 0.9 },
      { candidate_id: 'BCN-dddd000000000004', type: 'beacon' },
    ];

    const result = assignPresentationIds(candidates, { data_transfer: 'DT' });

    // Array order preserved; every candidate keeps its former hash id as provenance.
    assert.deepEqual(
      result.map((candidate) => candidate.pipeline_candidate_id),
      candidates.map((candidate) => candidate.candidate_id),
    );
    // Per type: score desc, tiebreak hash id asc; default prefix from the hash id
    // (beacon → BCN), override honored (data_transfer → DT); a candidate
    // missing its score field ranks last.
    assert.deepEqual(
      result.map((candidate) => candidate.candidate_id),
      ['BCN-003', 'DT-002', 'BCN-001', 'BCN-002', 'DT-001', 'BCN-004'],
    );
    // Inputs are not mutated and other fields pass through untouched.
    assert.equal(candidates[0].candidate_id, 'BCN-cccc000000000003');
    assert.equal(result[2].beacon_score, 0.9);
  });

  // `runBackHalf` runs stages 3-4 over telemetry that is already stage-2 output. Its
  // contract is that it is exactly `runPipeline` with the enrichment pass skipped — which
  // is what makes Pin B a tripwire for Pin A rather than a different measurement.
  it('runBackHalf reproduces runPipeline over the same telemetry', () => {
    const enriched = JSON.parse(
      readFileSync(`${repoRoot()}/fixtures/events_enriched.json`, 'utf-8'),
    ) as PostEnrichmentEvent[];
    const stripped = enriched.map((event) => {
      const { enrichment: _ignored, ...rest } = event as PostEnrichmentEvent & { enrichment?: unknown };
      return rest;
    }) as unknown as TelemetryEvent[];

    const backHalf = runBackHalf(enriched);
    const fullPipe = runPipeline(stripped);

    assert.deepEqual(backHalf.candidates, fullPipe.candidates);
    assert.deepEqual(backHalf.caputMortuum, fullPipe.caputMortuum);
    assert.equal(backHalf.candidates.length, 10);
    assert.equal(backHalf.caputMortuum.length, 3);
  });
});
