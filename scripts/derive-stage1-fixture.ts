/**
 * Derives `fixtures/events.json` from `fixtures/events_enriched.json`.
 *
 * WHY THIS EXISTS
 * ---------------
 * Stage 1 is by definition stage 2's input, so the only `events.json` guaranteed to be
 * consistent with `events_enriched.json` is that file minus its stage-2 `enrichment`
 * block. Deriving it makes that relationship a property of the repo rather than
 * something two committed files have to be kept in agreement about by hand — and Pin A
 * asserts the derivation in both directions on every test run.
 *
 * It removes exactly the `enrichment` key from each event — nothing else — and writes
 * with `canonicalJsonWithRounding`, the same serialization the two goldens already use
 * (both round-trip through it byte-for-byte).
 *
 * Usage:
 *   node --import tsx scripts/derive-stage1-fixture.ts           # write fixtures/events.json
 *   node --import tsx scripts/derive-stage1-fixture.ts --check   # verify, never write
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJsonWithRounding } from '../src/lib/canonical-json.js';
import { repoRoot } from '../src/lib/paths.js';

const ENRICHED_PATH = join(repoRoot(), 'fixtures', 'events_enriched.json');
const STAGE1_PATH = join(repoRoot(), 'fixtures', 'events.json');

/**
 * The derivation itself: parse the enriched fixture, drop the `enrichment` key from
 * every event, re-serialize canonically. Exported so a test can assert the committed
 * `events.json` still equals it.
 */
export function deriveStage1Events(enrichedRaw: string): string {
  const parsed = JSON.parse(enrichedRaw) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error('events_enriched.json must contain a JSON array');
  }

  const stage1 = parsed.map((event, idx) => {
    if (event === null || typeof event !== 'object' || Array.isArray(event)) {
      throw new Error(`events_enriched.json[${idx}] is not an object`);
    }
    const { enrichment: _stage2, ...rest } = event as Record<string, unknown>;
    return rest;
  });

  return canonicalJsonWithRounding(stage1);
}

function main(argv: string[]): void {
  const check = argv.includes('--check');
  const derived = deriveStage1Events(readFileSync(ENRICHED_PATH, 'utf-8'));

  if (check) {
    const committed = readFileSync(STAGE1_PATH, 'utf-8');
    if (committed === derived) {
      process.stdout.write(`OK  fixtures/events.json matches the derivation (${derived.length} bytes)\n`);
      return;
    }
    process.stderr.write(
      `DRIFT  fixtures/events.json does not match the derivation `
        + `(committed ${committed.length} bytes, derived ${derived.length} bytes)\n`,
    );
    process.exitCode = 1;
    return;
  }

  writeFileSync(STAGE1_PATH, derived, 'utf-8');
  process.stdout.write(`wrote fixtures/events.json (${derived.length} bytes)\n`);
}

// Run only when invoked directly, so a test can import `deriveStage1Events` safely.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
