// PIN B — the back-half tripwire.
//
//   fixtures/events_enriched.json → runBackHalf (stages 3–4 only, NO re-enrichment)
//     → canonicalJsonWithRounding → BYTE-EQUAL to fixtures/candidates_enriched.json
//
// Pin A and Pin B assert the same bytes from different entry points, which is the
// whole point: they bisect the pipe.
//
//   A green, B green  → the extraction is faithful end to end.
//   A red,   B green  → the fault is in stage-2 event enrichment (or the stage-1
//                       fixture lineage) — stages 3–4 are clean.
//   A red,   B red    → the fault is in the scorers / attribution / LFA / stage-4.
//
// Do not "fix" a red pin by editing scoring code or a fixture; diff the canonical JSON
// and report the first differing path.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJsonWithRounding } from '../../src/lib/canonical-json.js';
import { repoRoot } from '../../src/lib/paths.js';
import { runBackHalf } from '../../src/run/runner.js';
import type { PostEnrichmentEvent } from '../../src/pipeline/types/post-enrichment-event.js';

const FIXTURES = join(repoRoot(), 'fixtures');

const enrichedRaw = readFileSync(join(FIXTURES, 'events_enriched.json'), 'utf-8');
const goldenRaw = readFileSync(join(FIXTURES, 'candidates_enriched.json'), 'utf-8');

describe('Pin B — stages 3–4 over pre-enriched events reproduce the course canon', () => {
  it('serializes fixtures/events_enriched.json through the back half to candidates_enriched.json', () => {
    const enriched = JSON.parse(enrichedRaw) as PostEnrichmentEvent[];
    assert.equal(enriched.length, 3859, 'the canon stage-2 fixture is 3,859 enriched events');
    assert.ok(
      enriched.every((event) => 'enrichment' in event),
      'every event in events_enriched.json must carry its stage-2 enrichment block',
    );

    const result = runBackHalf(enriched);

    const serialized = canonicalJsonWithRounding(result.candidates);
    assert.equal(
      serialized,
      goldenRaw,
      'Pin B: back-half output is not byte-equal to fixtures/candidates_enriched.json',
    );

    assert.equal(result.candidates.length, 10, 'the canon is 10 emitted candidates');
    assert.equal(result.caputMortuum.length, 3, 'the canon discards 3 sub-floor PSI candidates');
  });
});
