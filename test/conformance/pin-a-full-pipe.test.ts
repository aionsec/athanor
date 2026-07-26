// PIN A — the normalized full pipe.
//
//   fixtures/events.json → runPipeline (default config)
//     → canonicalJsonWithRounding → BYTE-EQUAL to fixtures/candidates_enriched.json
//
// The pipeline's standing proof that it still computes what it computed: normalized
// events in, the committed golden out, byte for byte.
//
// A failure here is a PIPELINE defect — fix the code, never the fixture. Pin B
// (`pin-b-back-half.test.ts`) is the tripwire that says which half drifted: Pin B green
// with Pin A red isolates the fault to stage-2 event enrichment; both red points at
// stages 3–4.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJsonWithRounding } from '../../src/lib/canonical-json.js';
import { repoRoot } from '../../src/lib/paths.js';
import { runPipeline } from '../../src/run/runner.js';
import type { TelemetryEvent } from '../../src/schema/events.js';
import { deriveStage1Events } from '../../scripts/derive-stage1-fixture.js';

const FIXTURES = join(repoRoot(), 'fixtures');

const stage1Raw = readFileSync(join(FIXTURES, 'events.json'), 'utf-8');
const enrichedRaw = readFileSync(join(FIXTURES, 'events_enriched.json'), 'utf-8');
const goldenRaw = readFileSync(join(FIXTURES, 'candidates_enriched.json'), 'utf-8');

describe('Pin A — normalized full pipe reproduces the course canon byte-for-byte', () => {
  it('serializes fixtures/events.json through the whole pipeline to candidates_enriched.json', () => {
    const events = JSON.parse(stage1Raw) as TelemetryEvent[];
    assert.equal(events.length, 3859, 'the canon stage-1 fixture is 3,859 normalized events');

    // No config argument: the baked defaults ARE the course canon (the four emit
    // floors, the candidate-type order, the DT / UPCA presentation prefixes) — see
    // `src/run/config.ts`, verified block-by-block against the scenario YAML that
    // produced the golden.
    const result = runPipeline(events);

    const serialized = canonicalJsonWithRounding(result.candidates);
    assert.equal(
      serialized,
      goldenRaw,
      'Pin A: pipeline output is not byte-equal to fixtures/candidates_enriched.json',
    );

    // The emit-floor discard pile (`caput_mortuum`) is deliberately NOT part of the
    // comparison: the golden is what the course teaches against, i.e. what survived.
    assert.equal(result.candidates.length, 10, 'the canon is 10 emitted candidates');
    assert.equal(result.caputMortuum.length, 3, 'the canon discards 3 sub-floor PSI candidates');
  });

  // Guards the derivation (see fixtures/README.md): `events.json` IS the
  // enrichment-stripped form of `events_enriched.json`, not an independently committed
  // file. Asserted in two directions, so the pair cannot silently desynchronize:
  //   forward  — stripping stage 2 off the enriched fixture reproduces events.json
  //   backward — running athanor's stage 2 over events.json reproduces the enriched one
  it('keeps events.json and events_enriched.json on one lineage', () => {
    assert.equal(
      deriveStage1Events(enrichedRaw),
      stage1Raw,
      'fixtures/events.json is stale — re-run scripts/derive-stage1-fixture.ts',
    );

    const events = JSON.parse(stage1Raw) as TelemetryEvent[];
    assert.equal(
      canonicalJsonWithRounding(runPipeline(events).events),
      enrichedRaw,
      "athanor's stage-2 output is not byte-equal to fixtures/events_enriched.json",
    );
  });
});
