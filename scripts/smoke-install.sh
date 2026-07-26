#!/usr/bin/env bash
#
# Installed-package self-test: does the athanor a STUDENT installs still distill the canon?
#
# `npm run smoke` proves the built tree in this repo. It cannot prove the installed
# package, because it runs `dist/cli.js` from the checkout — where `data/`, `README.md`
# and every dependency happen to be present whether or not the manifest says so. The
# failures that live in that gap are all packaging failures:
#
#   * a `files` list that forgot `data/`  → every loader falls back to an empty table
#     and athanor scores differently, with no error;
#   * a runtime dependency left in devDependencies → the installed bin cannot import;
#   * a bin entry that does not resolve, or is not executable;
#   * a `paths.ts` root that only resolves inside a checkout.
#
# So: pack the tarball, install it into a throwaway prefix as a real dependency, run
# the INSTALLED bin over `fixtures/raw` and byte-compare the same golden Pin C uses.
#
# The package name and bin name are read from package.json at runtime — this script
# must keep working across a rename (the scoped name lands with the publish prep).
#
# Usage: npm run smoke:install      (or: bash scripts/smoke-install.sh)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/athanor-smoke-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "smoke:install: FAIL — $1" >&2
  exit 1
}

PKG_NAME="$(node -p "require('$REPO_ROOT/package.json').name")"
PKG_VERSION="$(node -p "require('$REPO_ROOT/package.json').version")"
BIN_NAME="$(node -p "Object.keys(require('$REPO_ROOT/package.json').bin || {})[0] || ''")"
[ -n "$BIN_NAME" ] || fail "package.json declares no bin; there is nothing to install"

echo "smoke:install: building…"
npm run --silent build

# ── 1. pack the tarball the registry would receive ────────────────────────────
echo "smoke:install: npm pack…"
TARBALL_NAME="$(npm pack --silent --pack-destination "$TMP_DIR" | tail -n 1)"
TARBALL="$TMP_DIR/$TARBALL_NAME"
[ -f "$TARBALL" ] || fail "npm pack produced no tarball at $TARBALL"

# ── 2. install it into a clean prefix, as a dependency of nothing ─────────────
INSTALL_DIR="$TMP_DIR/install"
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/package.json" <<'JSON'
{
  "name": "athanor-install-smoke",
  "version": "1.0.0",
  "private": true,
  "description": "Throwaway host package: proves the tarball installs and runs."
}
JSON

echo "smoke:install: installing $PKG_NAME@$PKG_VERSION into a clean prefix…"
(cd "$INSTALL_DIR" && npm install --silent --no-audit --no-fund --prefer-offline "$TARBALL") \
  || fail "the packed tarball does not install"

INSTALLED_BIN="$INSTALL_DIR/node_modules/.bin/$BIN_NAME"
[ -x "$INSTALLED_BIN" ] || fail "no executable bin at node_modules/.bin/$BIN_NAME after install"

# The installed tree must carry its data: this is the failure that scores differently
# instead of erroring, so it is asserted directly rather than inferred from the output.
INSTALLED_PKG="$INSTALL_DIR/node_modules/$PKG_NAME"
[ -f "$INSTALLED_PKG/data/geoip/minimal.json" ] \
  || fail "data/ is missing from the installed package — every loader would fall back to an empty table"

# ── 3. the installed bin identifies itself ────────────────────────────────────
REPORTED="$("$INSTALLED_BIN" --version)"
[ "$REPORTED" = "$BIN_NAME $PKG_VERSION" ] \
  || fail "--version from the installed bin reported '$REPORTED', expected '$BIN_NAME $PKG_VERSION'"

# ── 4. the installed bin reproduces the golden, byte for byte ─────────────────
echo "smoke:install: running the INSTALLED bin over fixtures/raw…"
"$INSTALLED_BIN" "$REPO_ROOT/fixtures/raw" \
  -o "$TMP_DIR/candidates.json" \
  --discards "$TMP_DIR/caput.json" \
  || fail "the installed bin exited non-zero"

cmp -s "$TMP_DIR/candidates.json" "$REPO_ROOT/fixtures/candidates_enriched.json" \
  || fail "installed CLI output differs from fixtures/candidates_enriched.json (packaging or data resolution)"

DISCARDS="$(node -e "process.stdout.write(String(JSON.parse(require('fs').readFileSync('$TMP_DIR/caput.json','utf8')).length))")"
[ "$DISCARDS" = "3" ] || fail "expected 3 caput-mortuum discards from the installed bin, got $DISCARDS"

# ── 5. it works from any working directory ────────────────────────────────────
# `npx athanor ./telemetry/` runs wherever the student happens to be standing.
ELSEWHERE="$TMP_DIR/elsewhere"
mkdir -p "$ELSEWHERE"
(cd "$ELSEWHERE" && "$INSTALLED_BIN" "$REPO_ROOT/fixtures/raw" -o "$ELSEWHERE/candidates.json" >/dev/null 2>&1) \
  || fail "the installed bin failed when run from another working directory"
cmp -s "$ELSEWHERE/candidates.json" "$REPO_ROOT/fixtures/candidates_enriched.json" \
  || fail "installed CLI output depends on the working directory"

echo "smoke:install: OK — $PKG_NAME@$PKG_VERSION installs, runs as \`$BIN_NAME\`, and reproduces the golden"
