#!/usr/bin/env bash
#
# Post-build smoke: does the COMPILED, PACKAGED athanor still distill the canon?
#
# `npm test` proves the library. It cannot prove the distribution, because the tests
# import TypeScript from `src/` where every relative path is trivially correct. The
# thing that breaks silently at packaging time is `src/lib/paths.ts`: it derives the
# package root as two levels up from itself, so the compiled file MUST land at
# `dist/lib/paths.js`. If a tsconfig change moves it (the classic case: tsc inferring
# `rootDir` and emitting `dist/src/lib/paths.js`), `dataPath()` starts pointing one
# directory too high, every data loader falls back to an empty table, and athanor
# still runs — it just scores differently. No exception, no warning.
#
# So the assertion here is byte-equality against the same golden Pin C uses. A
# degraded geo/lots/intel/taxonomy load cannot survive it.
#
# Also asserts the npm tarball's shape: `dist/` and `data/` in, `fixtures/` out.
#
# Usage: npm run smoke      (or: bash scripts/smoke-dist.sh)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/athanor-smoke.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "smoke: FAIL — $1" >&2
  exit 1
}

echo "smoke: building…"
npm run --silent build

# ── 1. the compiled layout ────────────────────────────────────────────────────
[ -f dist/cli.js ] || fail "dist/cli.js missing"
[ -f dist/lib/paths.js ] || fail "dist/lib/paths.js missing — the build layout moved (dist/src/…?)"
head -n 1 dist/cli.js | grep -q '^#!/usr/bin/env node' \
  || fail "dist/cli.js lost its shebang; npx/bin execution would break"
[ -x dist/cli.js ] || fail "dist/cli.js is not executable"

# ── 2. data resolution from the COMPILED paths module ─────────────────────────
RESOLVED_ROOT="$(node -e "import('./dist/lib/paths.js').then(m => console.log(m.repoRoot()))")"
[ "$RESOLVED_ROOT" = "$REPO_ROOT" ] \
  || fail "dist/lib/paths.js resolves the package root to '$RESOLVED_ROOT', expected '$REPO_ROOT'"
RESOLVED_DATA="$(node -e "import('./dist/lib/paths.js').then(m => console.log(m.dataPath('geoip','minimal.json')))")"
[ -f "$RESOLVED_DATA" ] || fail "dataPath() from dist/ does not resolve a real data file: $RESOLVED_DATA"

# ── 3. the built CLI reproduces the golden, byte for byte ─────────────────────
echo "smoke: running the built CLI over fixtures/raw…"
node dist/cli.js fixtures/raw \
  -o "$TMP_DIR/candidates.json" \
  --discards "$TMP_DIR/caput.json"

cmp -s "$TMP_DIR/candidates.json" fixtures/candidates_enriched.json \
  || fail "built CLI output differs from fixtures/candidates_enriched.json (data resolution or emit drift)"
[ -s "$TMP_DIR/caput.json" ] || fail "--discards wrote nothing"
# `process.stdout.write` rather than console.log: console.log inspects, and inspection
# colorizes numbers when it thinks it has a terminal, which would poison the comparison.
DISCARDS="$(node -e "process.stdout.write(String(JSON.parse(require('fs').readFileSync('$TMP_DIR/caput.json','utf8')).length))")"
[ "$DISCARDS" = "3" ] || fail "expected 3 caput-mortuum discards, got $DISCARDS"

# ── 4. the tarball's shape ────────────────────────────────────────────────────
echo "smoke: npm pack --dry-run…"
PACK_LIST="$TMP_DIR/pack.txt"
npm pack --dry-run --json > "$TMP_DIR/pack.json" 2>"$TMP_DIR/pack.log"
node -e "
  const report = JSON.parse(require('fs').readFileSync('$TMP_DIR/pack.json','utf8'));
  const files = report[0].files.map(f => f.path);
  require('fs').writeFileSync('$PACK_LIST', files.join('\n') + '\n');
"

grep -q '^dist/cli\.js$' "$PACK_LIST" || fail "dist/cli.js is not in the npm tarball"
grep -q '^dist/lib/paths\.js$' "$PACK_LIST" || fail "dist/lib/paths.js is not in the npm tarball"
grep -q '^data/geoip/minimal\.json$' "$PACK_LIST" || fail "data/ is not in the npm tarball"
grep -q '^package\.json$' "$PACK_LIST" || fail "package.json is not in the npm tarball"
! grep -q '^fixtures/' "$PACK_LIST" || fail "fixtures/ leaked into the npm tarball"
! grep -q '^test/' "$PACK_LIST" || fail "test/ leaked into the npm tarball"

echo "smoke: OK — $(wc -l < "$PACK_LIST" | tr -d ' ') files in the tarball, candidates byte-equal to the golden"
