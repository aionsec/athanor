/**
 * Repo-relative path resolution.
 *
 * Every data-file loader routes through `dataPath()`, so the taxonomies, whitelists and
 * the minimal geo/lots/intel tables resolve the same way whether athanor runs from source,
 * from a test, or from an installed package. `tsconfig.build.json` explains why the
 * two-levels-up derivation below is load-bearing rather than cosmetic.
 */

import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// This file lives at <repoRoot>/src/lib/paths.ts, so the root is two levels up.
const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(THIS_DIR, '..', '..');

/** Absolute path of the athanor repo root. */
export function repoRoot(): string {
  return REPO_ROOT;
}

/** Absolute path inside the repo's committed `data/` tree. */
export function dataPath(...segments: string[]): string {
  return join(REPO_ROOT, 'data', ...segments);
}
