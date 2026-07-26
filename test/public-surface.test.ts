// The public-surface gate.
//
// athanor was extracted from a private codebase and is authored alongside private
// course material. Everything in this repository is read by strangers: the published
// tarball, the source tree on the hosting platform, the tests, the scripts. A single
// leftover internal name — a private repo, a private notes directory, an author's home
// directory, an unshipped design document a comment still cites — is a paper cut for
// every reader who tries to follow it and finds nothing there.
//
// So the sweep that was run by hand before the repository went public is committed here
// as a test. It scans, in one pass:
//
//   1. every file `npm pack` would publish (the tarball readers install);
//   2. all of `src/` — `tsc` PRESERVES comments, so an internal reference in a source
//      comment ships inside `dist/*.js` and `dist/*.d.ts`, and a gate that only read the
//      pack manifest of an un-rebuilt tree would wave it through;
//   3. all of `test/` and `scripts/` — not published, but part of the public tree;
//   4. `README.md`, `docs/`, and `fixtures/README.md` — scanned by name so they stay
//      covered even if the `files` list changes underneath them;
//   5. `fixtures/sample-estate/` — a vendored second dataset. Its files are rendered log
//      records rather than prose, but they carry process paths, user names and command
//      lines, and any of those is somewhere an internal name arrives by accident.
//
// Each banned term is spelled in fragments (`'HU' + 'NT'`) for one reason: this file is
// inside the scanned set, so a term written out in full here would fail its own scan.
// The `id` on each entry is what a failure prints, and what the allowlist keys on.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { repoRoot } from '../src/lib/paths.js';

const ROOT = repoRoot();

/** The internal repository this pipeline was extracted from, in fragments. */
const INTERNAL_REPO = 'HU' + 'NT';

interface BannedTerm {
  /** Printed on a hit, and the key an allowlist entry names. */
  readonly id: string;
  /** Why a public reader must never see it. */
  readonly why: string;
  readonly pattern: RegExp;
}

// Case-insensitive unless a case-sensitive form is what keeps the term honest — noted
// per entry. Every pattern is built from a string so the fragments survive; a regex
// literal would put the term in this file verbatim.
const BANNED_TERMS: readonly BannedTerm[] = [
  {
    id: 'internal-repo-qualified',
    why: 'the private repository athanor was extracted from',
    pattern: new RegExp('aionsec_' + INTERNAL_REPO, 'i'),
  },
  {
    id: 'internal-repo-bare',
    why: 'the same private repository, unqualified (and its sub-projects)',
    // Case-SENSITIVE, and bounded so that ordinary prose survives: the security sense of
    // the lowercase word, and the `threat-hunting` package keyword, are legitimate and
    // must not be flagged. Only the shouted form is a name. The lookarounds (rather than
    // `\b`) catch the underscore-joined sub-project names, where `\b` would not fire.
    pattern: new RegExp('(?<![A-Za-z])' + INTERNAL_REPO + '(?![a-z])'),
  },
  {
    id: 'strategy-word',
    why: 'internal commercial-strategy vocabulary; nothing to do with the software',
    pattern: new RegExp('\\b' + 'mo' + 'at' + '\\b', 'i'),
  },
  {
    id: 'notes-application',
    why: "the author's private notes tree, where the course material lives",
    pattern: new RegExp('\\b' + 'va' + 'ult' + '\\b', 'i'),
  },
  {
    id: 'internal-planning-doc',
    why: 'an internal planning artifact no reader can open',
    pattern: new RegExp('\\b' + 'val' + 'ue[ _-]' + 'map' + '\\b', 'i'),
  },
  {
    id: 'sibling-site-repo',
    why: 'a private sibling repository',
    pattern: new RegExp('site' + '-v2', 'i'),
  },
  {
    id: 'agent-tooling-dir',
    why: 'the agent-workflow directory; also catches its dot-prefixed form',
    pattern: new RegExp('super' + 'powers', 'i'),
  },
  {
    id: 'authoring-process',
    why: 'how the code was written, which is not the reader’s concern',
    pattern: new RegExp('maker' + '[\\s_/-]*' + 'checker', 'i'),
  },
  {
    id: 'reviewer-role',
    why: 'the internal review role, same reason',
    pattern: new RegExp('\\bthe ' + 'checker' + '\\b', 'i'),
  },
  {
    id: 'author-first-name',
    why: 'the project ships under the organization, not a person',
    pattern: new RegExp('\\b' + 'Fa' + 'an' + '\\b', 'i'),
  },
  {
    id: 'author-handle',
    why: 'a personal account name in what is an organization’s package',
    pattern: new RegExp('fa' + 'anross', 'i'),
  },
  {
    id: 'personal-path',
    why: 'an absolute path out of one machine; never reproducible for a reader',
    // Case-SENSITIVE: the capitalized form is the macOS home prefix. A lowercase
    // `/users/` is an ordinary URL or API path and is not a leak.
    pattern: new RegExp('/Us' + 'ers/'),
  },
  {
    id: 'agent-instruction-file',
    why: 'agent-tooling files and session caches, in any spelling',
    pattern: new RegExp('cla' + 'ude', 'i'),
  },
  {
    id: 'unshipped-design-doc',
    why: 'the internal design document 27 rationale links used to point at; docs/design.md replaced it',
    pattern: new RegExp('Distillation_' + 'Pipeline_' + 'Design', 'i'),
  },
];

/**
 * Legitimate uses, keyed by exact repo-relative path + term id. Empty by design: the
 * patterns above are drawn tightly enough that the tree needs no exceptions today.
 *
 * Add an entry only with the third field filled in, and only for a use a stranger would
 * read as ordinary. The keyword `threat-hunting` in `package.json`, for instance, needs
 * NO entry — `internal-repo-bare` is case-sensitive precisely so the ordinary word stays
 * usable — and a term that needs an exception in more than one or two places is a term
 * whose pattern wants narrowing instead.
 */
const ALLOWLIST: readonly { file: string; id: string; why: string }[] = [];

function isAllowed(file: string, id: string): boolean {
  return ALLOWLIST.some((entry) => entry.file === file && entry.id === id);
}

/** Repo-relative, forward-slashed, so paths read the same as they do in the manifest. */
function rel(absolutePath: string): string {
  return relative(ROOT, absolutePath).split(sep).join('/');
}

/** Every file under `dir`, recursively. Missing directories yield nothing. */
function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      found.push(...walk(full));
    } else if (entry.isFile()) {
      found.push(full);
    }
  }
  return found;
}

/**
 * What `npm pack` would publish, as repo-relative paths.
 *
 * Asks npm rather than re-implementing the `files` semantics, because the manifest's
 * implicit inclusions (README, LICENSE, package.json) and its ignore rules are exactly
 * the part a hand-rolled reader would get wrong.
 */
function packedFiles(): string[] {
  // Prefer the npm that invoked this run; fall back to whatever is on PATH so the file
  // also works under a bare `node --test`.
  const npmCli = process.env.npm_execpath;
  const useNode = typeof npmCli === 'string' && npmCli.endsWith('.js');
  const result = spawnSync(
    useNode ? process.execPath : 'npm',
    [...(useNode ? [npmCli as string] : []), 'pack', '--dry-run', '--json'],
    { cwd: ROOT, encoding: 'utf-8', maxBuffer: 32 * 1024 * 1024 },
  );
  assert.equal(result.status, 0, `npm pack --dry-run failed:\n${result.stderr}`);

  const parsed = JSON.parse(result.stdout) as { files: { path: string }[] }[];
  assert.ok(parsed.length > 0, 'npm pack --dry-run reported no package');
  return parsed[0].files.map((file) => file.path);
}

const PACKED = packedFiles();

interface Hit {
  file: string;
  line: number;
  id: string;
  why: string;
  text: string;
}

/** Scan one file. Binary content is skipped: a term hidden in a blob is not a leak. */
function scan(absolutePath: string): Hit[] {
  const buffer = readFileSync(absolutePath);
  if (buffer.includes(0)) return [];
  const file = rel(absolutePath);
  const hits: Hit[] = [];
  buffer
    .toString('utf-8')
    .split('\n')
    .forEach((text, index) => {
      for (const term of BANNED_TERMS) {
        if (!term.pattern.test(text)) continue;
        if (isAllowed(file, term.id)) continue;
        hits.push({ file, line: index + 1, id: term.id, why: term.why, text: text.trim() });
      }
    });
  return hits;
}

/** One assertion shared by all four scopes, so every failure reads the same way. */
function assertClean(label: string, absolutePaths: readonly string[]): void {
  assert.ok(absolutePaths.length > 0, `${label}: nothing to scan — the gate would pass vacuously`);
  const hits = absolutePaths.flatMap(scan);
  if (hits.length === 0) return;

  const shown = hits.slice(0, 40);
  const report = shown
    .map((hit) => `  ${hit.file}:${hit.line}  [${hit.id}] ${hit.why}\n      ${hit.text.slice(0, 140)}`)
    .join('\n');
  const more = hits.length > shown.length ? `\n  …and ${hits.length - shown.length} more` : '';
  assert.fail(
    `${label}: ${hits.length} internal reference(s) in the public surface.\n${report}${more}\n` +
      'Rewrite the line, or — if the use is genuinely ordinary — add an ALLOWLIST entry ' +
      'in test/public-surface.test.ts with a reason.',
  );
}

describe('public surface', () => {
  it('publishes dist, data and docs — and nothing from the working tree', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')) as {
      files?: string[];
    };
    // Asserted on the manifest rather than the listing so the claim holds on a clean
    // clone, before anyone has run `npm run build`.
    for (const dir of ['dist', 'data', 'docs']) {
      assert.ok(manifest.files?.includes(dir), `package.json "files" must include ${dir}/`);
    }
    // docs/ is load-bearing: the README links all three documents, and a tarball without
    // them ships three dead links.
    for (const doc of ['docs/design.md', 'docs/extending.md', 'docs/schema.md']) {
      assert.ok(PACKED.includes(doc), `${doc} must be in the published tarball`);
    }
    for (const file of ['README.md', 'LICENSE', 'package.json']) {
      assert.ok(PACKED.includes(file), `${file} must be in the published tarball`);
    }
    assert.ok(
      PACKED.some((file) => file.startsWith('data/')),
      'data/ must be in the published tarball — without it every lookup table loads empty',
    );

    const leaked = PACKED.filter((file) => /^(fixtures|test|src|scripts)\//.test(file));
    assert.deepEqual(leaked, [], 'the tarball must not carry the development tree');
  });

  it('the published tarball carries no internal references', () => {
    const existing = PACKED.map((file) => join(ROOT, file)).filter(
      (path) => existsSync(path) && statSync(path).isFile(),
    );
    // `dist/` may be absent on a tree that has not been built; the same comments are
    // scanned at source below, so coverage does not depend on a build having run.
    assertClean('published tarball', existing);
  });

  it('src/ carries no internal references — comments survive into dist/', () => {
    assertClean('src/', walk(join(ROOT, 'src')));
  });

  it('test/ and scripts/ carry no internal references', () => {
    assertClean('test/ and scripts/', [...walk(join(ROOT, 'test')), ...walk(join(ROOT, 'scripts'))]);
  });

  it('the prose a reader meets first carries no internal references', () => {
    const prose = [
      join(ROOT, 'README.md'),
      join(ROOT, 'fixtures', 'README.md'),
      ...walk(join(ROOT, 'docs')),
    ];
    assertClean('README and docs', prose);
  });

  it('the vendored second estate carries no internal references', () => {
    // Telemetry is authored content too: a hostname, a user or a command line in a
    // rendered log is as public as a sentence in the README, and this dataset came out
    // of a private tree rather than out of the scenario renderer in this repository.
    assertClean('fixtures/sample-estate/', walk(join(ROOT, 'fixtures', 'sample-estate')));
  });
});
