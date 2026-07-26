// PIN C — the RAW full pipe.
//
//   fixtures/raw/ (4 authentic dialect files) → ingestFolder → runPipeline
//     (course-canon default config) → canonicalJsonWithRounding
//       → BYTE-EQUAL to fixtures/candidates_enriched.json
//
// Pin A proves athanor's pipeline is faithful given NORMALIZED events. Pin C proves
// the ingest layer in front of it is faithful given the shapes a real estate emits:
// Zeek JSON conn.log/ssl.log and Sysmon EID 1/3 JSONL, with no event ids in the data
// at all — the `evt-%05d` ids are RECONSTRUCTED by the ordering rule in
// `src/ingest/merge.ts`, which mirrors the rule the renderer of these files applies to
// its own output.
//
// TWO assertions, in this order, and the order is the point:
//   1. INTERMEDIATE — the ingested events are byte-equal to `fixtures/events.json`.
//      This is the stronger claim and it localizes a failure: if it fails, the fault
//      is in ingest (or in the emitter that wrote the fixtures), NOT in the pipeline.
//   2. FULL PIPE — the candidates are byte-equal to the golden.
//
// A failure here is an INGEST defect. Fix the parser, never the fixture, never the
// pipeline. If the intermediate diverges, the assertion prints the first divergent
// event id and JSON path.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJsonWithRounding } from '../../src/lib/canonical-json.js';
import { repoRoot } from '../../src/lib/paths.js';
import { runPipeline } from '../../src/run/runner.js';
import { assertSequenceMatches, ingestFolder, toSequence } from '../../src/ingest/index.js';
import type { TelemetryEvent } from '../../src/schema/events.js';

const FIXTURES = join(repoRoot(), 'fixtures');
const RAW_DIR = join(FIXTURES, 'raw');

const stage1Raw = readFileSync(join(FIXTURES, 'events.json'), 'utf-8');
const goldenRaw = readFileSync(join(FIXTURES, 'candidates_enriched.json'), 'utf-8');

/** First differing (event id, JSON path) between two normalized event arrays. */
function firstDivergence(
  got: ReadonlyArray<Record<string, unknown>>,
  want: ReadonlyArray<Record<string, unknown>>,
): string {
  if (got.length !== want.length) {
    return `event count: ingested ${got.length}, canon ${want.length}`;
  }
  for (let index = 0; index < want.length; index += 1) {
    const a = canonicalJsonWithRounding(got[index]);
    const b = canonicalJsonWithRounding(want[index]);
    if (a === b) continue;

    const gotRecord = got[index]!;
    const wantRecord = want[index]!;
    const keys = [...new Set([...Object.keys(gotRecord), ...Object.keys(wantRecord)])].sort();
    for (const key of keys) {
      const left = canonicalJsonWithRounding(gotRecord[key] ?? null);
      const right = canonicalJsonWithRounding(wantRecord[key] ?? null);
      if (left !== right) {
        return `${String(wantRecord.id)} (index ${index}) at $.${key}: `
          + `ingested ${left.trim()} vs canon ${right.trim()}`;
      }
    }
    return `${String(wantRecord.id)} (index ${index}): records differ but no single key does`;
  }
  return 'no divergence';
}

describe('Pin C — raw dialect folder reproduces the course canon byte-for-byte', () => {
  it('reconstructs fixtures/events.json from fixtures/raw/ (the intermediate assert)', async () => {
    const result = await ingestFolder(RAW_DIR);

    assert.deepEqual(
      result.files.map((file) => `${file.file}:${file.classifiedAs}:${file.events}`),
      [
        'conn.log:zeek/conn:1614',
        'ssl.log:zeek/ssl:480',
        'sysmon-eid1.jsonl:sysmon/process_create:151',
        'sysmon-eid3.jsonl:sysmon/network_connect:1614',
      ],
      'fixtures/raw/ is exactly the four canon dialect files',
    );
    assert.equal(result.events.length, 3859, 'the canon is 3,859 events');
    assert.deepEqual(result.ambiguities, [], 'the ordering rule orders the canon with no ambiguity');
    assert.equal(result.equalTimestampGroups, 149, 'the canon has 149 equal-timestamp groups');

    const canon = JSON.parse(stage1Raw) as Array<Record<string, unknown>>;
    const ingested = result.events as unknown as Array<Record<string, unknown>>;

    // Ids are not carried in raw logs — this asserts the reconstruction, id by id.
    assertSequenceMatches(ingested, toSequence(canon));

    const serialized = canonicalJsonWithRounding(result.events);
    if (serialized !== stage1Raw) {
      assert.fail(
        'Pin C intermediate: ingested events are not byte-equal to fixtures/events.json — '
        + `first divergence: ${firstDivergence(ingested, canon)}`,
      );
    }
  });

  it('serializes fixtures/raw/ through the whole pipeline to candidates_enriched.json', async () => {
    const { events } = await ingestFolder(RAW_DIR);

    // No config argument: the baked defaults ARE the course canon — the same call
    // Pin A makes, so any difference between the two pins is ingest, not pipeline.
    const result = runPipeline(events as TelemetryEvent[]);

    assert.equal(
      canonicalJsonWithRounding(result.candidates),
      goldenRaw,
      'Pin C: raw-ingested pipeline output is not byte-equal to fixtures/candidates_enriched.json',
    );
    assert.equal(result.candidates.length, 10, 'the canon is 10 emitted candidates');
    assert.equal(result.caputMortuum.length, 3, 'the canon discards 3 sub-floor PSI candidates');
  });
});
