// `fixtures/sample-estate/` — the second, UNPINNED estate.
//
// The three conformance pins measure `fixtures/raw` to the byte. This file deliberately
// does not do that for `sample-estate/`: the folder exists so a reader has somewhere to
// change a floor and watch the answers move, and a golden would make it another contract
// nobody may touch.
//
// What it asserts instead is a count-level canary. The estate ingests cleanly, the
// id-reconstruction rule separates every record, and the built-in defaults still distil
// the same five candidates and twenty-six discards out of it. That catches the class of
// change the goldens cannot see — one that happens to reproduce `candidates_enriched.json`
// while answering differently on a dataset it was never fitted to — and it is cheap to
// move on purpose when a change means to move it.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { ingestFolder } from '../../src/ingest/index.js';
import { repoRoot } from '../../src/lib/paths.js';
import { runPipeline } from '../../src/run/runner.js';

const ESTATE = join(repoRoot(), 'fixtures', 'sample-estate');

describe('fixtures/sample-estate — the unpinned second estate', () => {
  it('ingests as four dialect files with no ordering ambiguity', async () => {
    const ingested = await ingestFolder(ESTATE);

    assert.equal(ingested.events.length, 1294);
    assert.equal(ingested.files.length, 4);
    assert.deepEqual(ingested.byDialect, {
      'zeek/conn': 422,
      'zeek/ssl': 422,
      'sysmon/network_connect': 422,
      'sysmon/process_create': 28,
    });
    // 38 groups share a timestamp, and the dialect rank separates every one of them —
    // so nothing here depends on the order the folder happened to be read in.
    assert.deepEqual(ingested.ambiguities, [], 'the ordering rule separates every record');
    assert.equal(ingested.equalTimestampGroups, 38);
    assert.deepEqual(ingested.skipped, [], 'the folder holds telemetry and nothing else');
    assert.equal(ingested.normalized, false, 'this is the raw lane, ids are reconstructed');
  });

  it('distills to a stable candidate count under the built-in defaults', async () => {
    const { events } = await ingestFolder(ESTATE);
    const result = runPipeline(events);

    // The count, and the type of each — NOT the scores, and not the bytes.
    assert.equal(result.candidates.length, 5);
    assert.deepEqual(
      result.candidates.map((candidate) => candidate.type),
      [
        'beacon',
        'data_transfer',
        'tls_anomaly',
        'unusual_parent_child_anomaly',
        'powershell_invocation_anomaly',
      ],
      'one candidate per type, in the canon emit order',
    );

    // The reason the estate is worth shipping: a caput mortuum with something in it.
    assert.equal(result.caputMortuum.length, 26);
    assert.equal(
      result.caputMortuum.filter((c) => c.type === 'powershell_invocation_anomaly').length,
      25,
      'the pile is a developer spawning shells, which is what a floor is for',
    );
    assert.ok(
      result.caputMortuum.every((candidate) => candidate.emit_floor === 0.6),
      'every discard names the floor that cut it',
    );
  });
});
