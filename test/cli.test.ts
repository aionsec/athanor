// The CLI, exercised the way a student runs it: as a spawned process.
//
// These tests deliberately do NOT import `src/cli.ts` — a bin entry point's contract
// is its argv, its exit code, its stderr and the bytes it leaves on disk, and an
// in-process call would test none of those. Every case here spawns node.
//
// The expensive case (the full `fixtures/raw/` folder) runs exactly once and asserts
// byte-equality against the same golden Pin C uses: the CLI must be a thin shell over
// the library, so anything it adds — a stray field, a different serializer, a config
// it forgot to pass — shows up as a diff. Every other case runs against a two-line
// micro-fixture so the error paths stay cheap.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { repoRoot } from '../src/lib/paths.js';

const ROOT = repoRoot();
const CLI = join(ROOT, 'src', 'cli.ts');
const RAW_DIR = join(ROOT, 'fixtures', 'raw');
const GOLDEN = readFileSync(join(ROOT, 'fixtures', 'candidates_enriched.json'), 'utf-8');

// Resolved absolutely so the loader still loads when the spawn's cwd is a tmp dir
// (`--import tsx` resolves relative to cwd, which the default-output case moves).
const TSX_LOADER = import.meta.resolve('tsx');

interface CliRun {
  status: number;
  stdout: string;
  stderr: string;
}

function runCli(args: readonly string[], cwd: string = ROOT): CliRun {
  const result = spawnSync(
    process.execPath,
    ['--import', TSX_LOADER, CLI, ...args],
    { cwd, encoding: 'utf-8' },
  );
  if (result.error) throw result.error;
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

let tmpRoot: string;
let scratchCount = 0;

/** A fresh empty directory under the suite's tmp root. */
function scratch(name: string): string {
  scratchCount += 1;
  const dir = join(tmpRoot, `${scratchCount}-${name}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Two authentic conn records — the first two lines of the canon `conn.log` — with the
 * second's timestamp forced onto the first's and its uid changed. Same millisecond,
 * same dialect: exactly the tie the id-reconstruction rule cannot break, which is what
 * `result.ambiguities` reports and the CLI must surface.
 */
function writeTiedConnFolder(dir: string): void {
  const [first, second] = readFileSync(join(RAW_DIR, 'conn.log'), 'utf-8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .slice(0, 2)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const tied = { ...second, ts: first!.ts, uid: 'CtieTie000000000001' };
  writeFileSync(
    join(dir, 'conn.log'),
    `${JSON.stringify(first)}\n${JSON.stringify(tied)}\n`,
  );
}

/** The same two records, untied — a valid, cheap folder for the non-ordering cases. */
function writeTinyConnFolder(dir: string): void {
  const lines = readFileSync(join(RAW_DIR, 'conn.log'), 'utf-8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .slice(0, 2);
  writeFileSync(join(dir, 'conn.log'), `${lines.join('\n')}\n`);
}

before(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), 'athanor-cli-test-'));
});

after(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

describe('athanor CLI — the happy path', () => {
  it('distills fixtures/raw/ into the canon candidates, byte-equal to the golden', () => {
    const out = scratch('golden');
    const candidatesPath = join(out, 'candidates.json');
    const discardsPath = join(out, 'caput.json');

    const run = runCli([RAW_DIR, '-o', candidatesPath, '--discards', discardsPath]);

    assert.equal(run.status, 0, `CLI exited ${run.status}\n${run.stderr}`);
    assert.equal(
      readFileSync(candidatesPath, 'utf-8'),
      GOLDEN,
      'CLI candidates are not byte-equal to fixtures/candidates_enriched.json',
    );

    // The caput mortuum: the three sub-floor PSI candidates, serialized the same way.
    const discards = JSON.parse(readFileSync(discardsPath, 'utf-8')) as Array<Record<string, unknown>>;
    assert.equal(discards.length, 3, '--discards writes the 3 floor-dropped candidates');
    assert.deepEqual(
      [...new Set(discards.map((candidate) => candidate.type))],
      ['powershell_invocation_anomaly'],
      'the canon floor drops PSI candidates only',
    );
    assert.ok(
      discards.every((candidate) => typeof candidate.candidate_id === 'string'
        && !('pipeline_candidate_id' in candidate)),
      'discards keep their deterministic ids and never receive presentation ids',
    );

    // The summary: per-dialect parse counts, candidates by type, the floor discards.
    assert.match(run.stderr, /3859 events from 4 files/);
    assert.match(run.stderr, /conn\.log\s+zeek\/conn\s+1614/);
    assert.match(run.stderr, /ssl\.log\s+zeek\/ssl\s+480/);
    assert.match(run.stderr, /sysmon-eid1\.jsonl\s+sysmon\/process_create\s+151/);
    assert.match(run.stderr, /sysmon-eid3\.jsonl\s+sysmon\/network_connect\s+1614/);
    assert.match(run.stderr, /candidates: 10/);
    assert.match(run.stderr, /beacon\s+5/);
    assert.match(run.stderr, /powershell_invocation_anomaly\s+1\s+\(3 below the 0\.6 floor\)/);
    assert.match(run.stderr, /caput mortuum \(dropped by the emit floors\): 3/);
    assert.doesNotMatch(run.stderr, /warning:/, 'the canon has no ordering ambiguity');

    // stdout stays clean: the report is stderr, so `-o /dev/stdout` remains pipeable.
    assert.equal(run.stdout, '', 'the summary must not contaminate stdout');
  });

  it('writes candidates.json into the working directory when -o is omitted', () => {
    const dir = scratch('default-output');
    const telemetry = join(dir, 'telemetry');
    mkdirSync(telemetry);
    writeTinyConnFolder(telemetry);

    const run = runCli([telemetry], dir);

    assert.equal(run.status, 0, run.stderr);
    const written = join(dir, 'candidates.json');
    assert.ok(existsSync(written), 'default output lands in the cwd as candidates.json');
    assert.deepEqual(JSON.parse(readFileSync(written, 'utf-8')), [], 'two conn events yield no candidates');
    // realpath: on macOS the tmp dir is /var/… but a child process' cwd resolves to
    // /private/var/…, and the summary prints the absolute path the child computed.
    assert.match(
      run.stderr,
      new RegExp(`wrote ${realpathSync(written).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'),
      'the summary names the absolute path it wrote',
    );
  });

  it('applies --config instead of the baked course-canon defaults', () => {
    const dir = scratch('config');
    // The config lives BESIDE the telemetry folder, never inside it: ingest refuses a
    // folder holding a file it cannot classify, and an athanor.yaml is not telemetry.
    const telemetry = join(dir, 'telemetry');
    mkdirSync(telemetry);
    writeTinyConnFolder(telemetry);
    const configPath = join(dir, 'athanor.yaml');
    writeFileSync(configPath, 'distill_candidates:\n  - beacon\n');

    const run = runCli([telemetry, '-o', join(dir, 'out.json'), '--config', configPath]);

    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /beacon/);
    assert.doesNotMatch(
      run.stderr,
      /tls_anomaly/,
      'a config naming one candidate type must actually narrow the run',
    );
  });
});

describe('athanor CLI — the ordering-ambiguity warning', () => {
  it('warns when two records share a timestamp and a dialect', () => {
    const dir = scratch('ambiguous');
    writeTiedConnFolder(dir);

    const run = runCli([dir, '-o', join(dir, 'out.json')]);

    assert.equal(run.status, 0, `an ambiguity is a warning, not a failure\n${run.stderr}`);
    assert.match(run.stderr, /warning: 1 record pair shares a timestamp AND a dialect/);
    assert.match(run.stderr, /file\/line order/, 'the warning says WHY the ids are order-dependent');
    assert.match(run.stderr, /evidence ids/, 'the warning names the consequence');
    assert.match(run.stderr, /zeek\/conn @ .+conn\.log:1 \/ .+conn\.log:2/, 'the tied pair is located');
  });
});

describe('athanor CLI — what the run passed over', () => {
  // Every case here exits 0. Skipping a subdirectory, refusing a hand-edited record and
  // replacing a config block are all legitimate; being quiet about them is not, because
  // each one is evidence or a threshold that left the run without anyone deciding so.

  it('warns about a skipped subdirectory and still exits 0', () => {
    const dir = scratch('subdir');
    writeTinyConnFolder(dir);
    mkdirSync(join(dir, 'zeek'));
    writeFileSync(join(dir, 'zeek', 'ssl.log'), '{}\n');

    const run = runCli([dir, '-o', join(dir, 'out.json')]);

    assert.equal(run.status, 0, `a skip is a warning, not a failure\n${run.stderr}`);
    assert.match(run.stderr, /warning: the scan passed over 1 entry: zeek \(subdirectory\)/);
    assert.match(run.stderr, /does not descend into it/, 'the warning says why');
  });

  it('warns that the normalized lane refused records, naming how many and where', () => {
    const dir = scratch('dropped-records');
    const telemetry = join(dir, 'telemetry');
    mkdirSync(telemetry);
    const event = {
      id: 'evt-00001',
      timestamp: '2026-03-09T12:00:30.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.20.30.41',
      dest_ip: '104.18.22.51',
      dest_port: 443,
      proto: 'tcp',
    };
    const { dest_ip: _typo, ...incomplete } = event;
    writeFileSync(
      join(telemetry, 'events.json'),
      JSON.stringify([event, { ...incomplete, id: 'evt-00002' }]),
    );

    const run = runCli([telemetry, '-o', join(dir, 'out.json')]);

    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /warning: 1 of 2 records in the normalized events file were refused/);
    assert.match(run.stderr, /array index 1\b/, 'the refused record is located');
    assert.match(run.stderr, /raw dialect lanes\s+hard-error/, 'the posture difference is stated');
  });

  it('reports what a --config overrode and removed, in one line', () => {
    const dir = scratch('config-summary');
    const telemetry = join(dir, 'telemetry');
    mkdirSync(telemetry);
    writeTinyConnFolder(telemetry);
    const configPath = join(dir, 'athanor.yaml');
    writeFileSync(configPath, 'emit_floors:\n  beacon: 0.2\n  tls_anomaly: null\n');

    const run = runCli([telemetry, '-o', join(dir, 'out.json'), '--config', configPath]);

    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /config: .*athanor\.yaml — 1 key overridden \(emit_floors\.beacon\)/);
    assert.match(run.stderr, /1 removed \(emit_floors\.tls_anomaly\)/);
    assert.match(
      run.stderr,
      /every key the config does not name keeps its built-in default/,
      'the merge rule is stated where the merge is reported',
    );
    // A merge is not a warning: nothing was silently dropped.
    assert.doesNotMatch(run.stderr, /warning:/);
  });

  it('says a config that names nothing kept every default', () => {
    const dir = scratch('empty-config');
    const telemetry = join(dir, 'telemetry');
    mkdirSync(telemetry);
    writeTinyConnFolder(telemetry);
    const configPath = join(dir, 'athanor.yaml');
    writeFileSync(configPath, '# nothing declared\n{}\n');

    const run = runCli([telemetry, '-o', join(dir, 'out.json'), '--config', configPath]);

    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /0 keys overridden, 0 removed — every built-in default kept/);
  });

  it('passes over a config file sitting inside the telemetry folder', () => {
    // Ingest used to refuse the whole run for it ("unrecognized telemetry file"),
    // which made a reasonable folder layout a hard error. It is now skipped and
    // reported: configuration is not evidence, so losing it loses nothing.
    const dir = scratch('config-inside');
    writeTinyConnFolder(dir);
    const configPath = join(dir, 'athanor.yaml');
    writeFileSync(configPath, 'emit_floors:\n  beacon: 0.2\n');

    const run = runCli([dir, '-o', join(dir, 'out.json'), '--config', configPath]);

    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stderr, /warning: the scan passed over 1 entry: athanor\.yaml \(config file\)/);
    assert.match(run.stderr, /config: .*athanor\.yaml — 1 key overridden/);
    assert.match(run.stderr, /2 events from 1 file/, 'the telemetry still ingested');
  });
});

describe('athanor CLI — the failure paths', () => {
  it('exits 1 on an empty folder', () => {
    const dir = scratch('empty');
    const out = join(dir, 'out.json');

    const run = runCli([dir, '-o', out]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /athanor: cannot ingest .*: no files to ingest/);
    assert.equal(existsSync(out), false, 'a failed run writes nothing');
  });

  it('exits 1 on a folder holding an unrecognized file', () => {
    const dir = scratch('unrecognized');
    writeFileSync(join(dir, 'notes.txt'), 'this is not telemetry\n');

    const run = runCli([dir, '-o', join(dir, 'out.json')]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /unrecognized telemetry file: .*notes\.txt/);
  });

  it('exits 1 on a missing directory', () => {
    const run = runCli([join(tmpRoot, 'does-not-exist'), '-o', join(tmpRoot, 'x.json')]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /athanor: cannot ingest .*does-not-exist/);
  });

  it('exits 1 when the config cannot be read, before touching the telemetry', () => {
    const dir = scratch('bad-config');
    writeTinyConnFolder(dir);
    const out = join(dir, 'out.json');

    const run = runCli([dir, '-o', out, '--config', join(dir, 'nope.yaml')]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /athanor: cannot read config .*nope\.yaml/);
    assert.equal(existsSync(out), false);
  });

  it('exits 1 when the config is malformed', () => {
    const dir = scratch('malformed-config');
    writeTinyConnFolder(dir);
    const configPath = join(dir, 'athanor.yaml');
    writeFileSync(configPath, 'emit_floors:\n  beacon: 42\n');

    const run = runCli([dir, '-o', join(dir, 'out.json'), '--config', configPath]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /cannot read config .*emit_floors\.beacon must be a number in \[0, 1\]/);
  });

  it('exits 1 when the output cannot be written', () => {
    const dir = scratch('unwritable');
    writeTinyConnFolder(dir);

    const run = runCli([dir, '-o', join(dir, 'no-such-dir', 'out.json')]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /athanor: cannot write candidates to .*out\.json/);
  });

  it('exits 1 with the usage text when no folder is given', () => {
    const run = runCli([]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /athanor: no telemetry folder given/);
    assert.match(run.stderr, /Usage: athanor <telemetry-dir>/);
  });

  it('exits 1 with the usage text on an unknown flag', () => {
    const run = runCli([RAW_DIR, '--nope']);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /--nope/);
    assert.match(run.stderr, /Usage: athanor <telemetry-dir>/);
  });

  it('exits 1 when given more than one folder', () => {
    const run = runCli([RAW_DIR, RAW_DIR]);

    assert.equal(run.status, 1);
    assert.match(run.stderr, /ONE folder at a time/);
  });
});

describe('athanor CLI — help and version', () => {
  it('prints the usage text on stdout and exits 0', () => {
    const run = runCli(['--help']);

    assert.equal(run.status, 0);
    assert.match(run.stdout, /Usage: athanor <telemetry-dir> \[options\]/);
    assert.match(run.stdout, /--discards <path>/);
    assert.match(run.stdout, /Merged per key/, 'the help states the config semantics');
    assert.equal(run.stderr, '');
  });

  it('prints the package version and exits 0, without a telemetry folder', () => {
    const run = runCli(['--version']);

    assert.equal(run.status, 0, run.stderr);
    const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')) as {
      version: string;
    };
    assert.equal(run.stdout, `athanor ${version}\n`, 'the version comes from the manifest');
    assert.equal(run.stderr, '');
  });
});
