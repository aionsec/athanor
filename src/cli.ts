#!/usr/bin/env node
/**
 * `athanor ./telemetry/ → candidates.json` — the whole kit behind one command.
 *
 * The CLI is deliberately thin: it is argument parsing, three library calls
 * (`ingestFolder` → `runPipeline` → `canonicalJsonWithRounding`), a file write and
 * a summary. Every decision that changes a score lives in the library, so running
 * athanor from the CLI and running it from a test are the same computation — that
 * is what lets Pin C's golden double as the CLI's golden.
 *
 * Two honesty rules the summary exists to serve:
 *
 * 1. Raw logs carry no event ids; athanor RECONSTRUCTS them by the ordering rule in
 *    `src/ingest/merge.ts`. When two records tie on both keys the rule cannot
 *    separate them and the merge falls back to file/line order — so the ids (and
 *    every content-derived candidate id downstream) depend on the input ordering.
 *    That case is reported, never swallowed.
 * 2. The emit floors discard candidates. The count of what was dropped is always
 *    printed, and `--discards` writes the pile itself, so a floor is never an
 *    invisible deletion.
 *
 * The same rule governs everything else the run passed over: a directory entry the
 * scan could not read, a config file it stepped around, a record the normalized
 * loader refused. Each of them is legitimate; none of them is allowed to be silent.
 * They are warnings, not failures — the exit code stays 0.
 *
 * Config is EXPLICIT: without `--config`, the baked course-canon defaults apply.
 * athanor never picks up a stray `athanor.yaml` from the working directory, because
 * a config that is found rather than named changes scores without anyone asking. A
 * config that IS named is merged per key — what it names wins, what it omits keeps
 * its default, what it nulls is removed — and the summary reports the merge, because
 * thresholds nobody can account for afterwards are the same problem as silence.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { describeSkippedEntries, ingestFolder, type IngestResult } from './ingest/index.js';
import { canonicalJsonWithRounding } from './lib/canonical-json.js';
import { nodeVersionComplaint } from './lib/node-version.js';
import { repoRoot } from './lib/paths.js';
import {
  type AthanorConfig,
  type ConfigMergeSummary,
  defaultAthanorConfig,
  loadAthanorConfigWithSummary,
} from './run/config.js';
import { type PipelineRunResult, runPipeline } from './run/runner.js';

const PROGRAM = 'athanor';
const DEFAULT_OUTPUT = 'candidates.json';

const USAGE = `Usage: ${PROGRAM} <telemetry-dir> [options]

Distills a folder of raw telemetry into scored candidates. Recognized dialects:
Zeek conn.log / ssl.log (JSON lines), Sysmon EID 1 / EID 3 JSONL, PowerShell 4104
JSONL, or a single already-normalized events.json.

Options:
  -o, --output <path>    where to write the candidates (default: ${DEFAULT_OUTPUT})
      --config <path>    athanor.yaml; without it the built-in defaults apply.
                         Merged per key: what it names wins, what it does not name
                         keeps the default, and a key set to null is removed
      --discards <path>  also write the caput mortuum — the candidates the emit
                         floors dropped
      --version          print the version and exit
  -h, --help             show this help

Exit codes: 0 = distilled, 1 = bad usage, unreadable input or unwritable output.`;

/** A failure the user can act on: printed as one line, no stack trace. */
class CliError extends Error {
  readonly withUsage: boolean;

  constructor(message: string, withUsage = false) {
    super(message);
    this.name = 'CliError';
    this.withUsage = withUsage;
  }
}

/**
 * Nothing in this module is exported. The file's last statement RUNS the CLI, so an
 * import would run it too — a bin entry point should have exactly one way in.
 */
interface CliOptions {
  telemetryDir: string;
  outputPath: string;
  configPath?: string;
  discardsPath?: string;
}

function requireValue(value: string | undefined, flag: string): string {
  if (value === undefined || value.length === 0) {
    throw new CliError(`${flag} needs a path`, true);
  }
  return value;
}

/**
 * The version this build was published as, read from the package manifest rather
 * than baked into the source: two places to bump is one place to forget. `paths.ts`
 * resolves the package root the same way from `src/` and from an installed
 * `dist/lib/`, so this works for `npx` as well as for a checkout.
 */
function packageVersion(): string {
  try {
    const manifest = JSON.parse(readFileSync(join(repoRoot(), 'package.json'), 'utf-8')) as {
      version?: unknown;
    };
    return typeof manifest.version === 'string' ? manifest.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

/** `'help'`/`'version'` mean the user asked for output, not for a distillation. */
function parseCliArgs(argv: readonly string[]): CliOptions | 'help' | 'version' {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        output: { type: 'string', short: 'o' },
        config: { type: 'string' },
        discards: { type: 'string' },
        version: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (error) {
    // parseArgs' own messages already name the offending token.
    throw new CliError((error as Error).message, true);
  }

  if (parsed.values.help) return 'help';
  if (parsed.values.version) return 'version';

  const positionals = parsed.positionals;
  if (positionals.length === 0) {
    throw new CliError('no telemetry folder given', true);
  }
  if (positionals.length > 1) {
    throw new CliError(
      `unexpected extra argument "${positionals[1]}" — athanor distills ONE folder at a time`,
      true,
    );
  }

  const options: CliOptions = {
    telemetryDir: positionals[0]!,
    outputPath: parsed.values.output === undefined
      ? DEFAULT_OUTPUT
      : requireValue(parsed.values.output, '--output'),
  };
  if (parsed.values.config !== undefined) {
    options.configPath = requireValue(parsed.values.config, '--config');
  }
  if (parsed.values.discards !== undefined) {
    options.discardsPath = requireValue(parsed.values.discards, '--discards');
  }
  return options;
}

interface LoadedConfig {
  config: AthanorConfig;
  /** One line naming what the config changed; absent when no `--config` was given. */
  summaryLine?: string;
}

function loadConfig(configPath: string | undefined): LoadedConfig {
  if (configPath === undefined) return { config: defaultAthanorConfig() };
  try {
    const { config, summary } = loadAthanorConfigWithSummary(configPath);
    return { config, summaryLine: configSummaryLine(configPath, summary) };
  } catch (error) {
    throw new CliError(`cannot read config ${configPath}: ${(error as Error).message}`);
  }
}

/** `a, b, c, … and 2 more` — the merged keys, capped so the line stays a line. */
function nameKeys(keys: readonly string[], limit = 5): string {
  if (keys.length === 0) return '';
  const shown = keys.slice(0, limit).join(', ');
  const more = keys.length > limit ? `, … and ${keys.length - limit} more` : '';
  return ` (${shown}${more})`;
}

/**
 * What the config file actually did, in one line.
 *
 * `--config` is a PER-KEY DEEP MERGE: a key the file names wins, a key it does not
 * name keeps its canon default, and a key set to `null` is removed. That is the
 * forgiving semantics — a partial `emit_floors` no longer deletes the floors it did
 * not mention — but a merge is exactly the kind of thing that is impossible to debug
 * when it is invisible, so the effective config is always reported.
 */
function configSummaryLine(configPath: string, summary: ConfigMergeSummary): string {
  const { overridden, removed } = summary;
  const line = `config: ${resolve(configPath)} — ${overridden.length} `
    + `key${overridden.length === 1 ? '' : 's'} overridden${nameKeys(overridden)}, `
    + `${removed.length} removed${nameKeys(removed)}`;
  return overridden.length === 0 && removed.length === 0
    ? `${line} — every built-in default kept`
    : `${line}; every key the config does not name keeps its built-in default`;
}

function writeArtifact(path: string, body: string, what: string): void {
  try {
    writeFileSync(path, body);
  } catch (error) {
    throw new CliError(`cannot write ${what} to ${path}: ${(error as Error).message}`);
  }
}

function countByType(candidates: ReadonlyArray<{ type: string }>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const candidate of candidates) {
    counts.set(candidate.type, (counts.get(candidate.type) ?? 0) + 1);
  }
  return counts;
}

/**
 * The summary. It goes to stderr so `athanor ... -o /dev/stdout` stays pipeable and
 * the report never contaminates the JSON.
 */
function summaryLines(
  telemetryDir: string,
  ingested: IngestResult,
  run: PipelineRunResult,
  config: AthanorConfig,
  outputPath: string,
  discardsPath: string | undefined,
  configSummary: string | undefined,
): string[] {
  const lines: string[] = [];

  lines.push(
    `${PROGRAM}: ${ingested.events.length} `
    + `event${ingested.events.length === 1 ? '' : 's'} from ${ingested.files.length} `
    + `file${ingested.files.length === 1 ? '' : 's'} in ${telemetryDir}`,
  );

  const nameWidth = Math.max(...ingested.files.map((file) => file.file.length));
  const kindWidth = Math.max(...ingested.files.map((file) => file.classifiedAs.length));
  for (const file of ingested.files) {
    lines.push(
      `  ${file.file.padEnd(nameWidth)}  ${file.classifiedAs.padEnd(kindWidth)}  `
      + `${String(file.events).padStart(6)}`,
    );
  }

  if (ingested.normalized) {
    lines.push('  (normalized lane: event ids were read from the file, not reconstructed)');
  }

  // The effective config, whenever one was named: a per-key merge that says nothing
  // about itself is a set of thresholds nobody can account for afterwards.
  if (configSummary !== undefined) {
    lines.push(configSummary);
  }

  // Skipping a directory entry is legitimate; not saying so is not. A subdirectory of
  // logs left out of the run is partial telemetry with a green exit code.
  if (ingested.skipped.length > 0) {
    lines.push(
      `warning: the scan passed over ${describeSkippedEntries(ingested.skipped)} — athanor `
      + 'ingests the files IN the folder you name, and does not descend into it; a config '
      + 'file is configuration, not evidence. Anything listed here contributed no evidence '
      + 'to this run.',
    );
  }

  if (ingested.droppedRecordIndices.length > 0) {
    const dropped = ingested.droppedRecordIndices;
    const declared = ingested.events.length + dropped.length;
    const shown = dropped.slice(0, 5).join(', ');
    const more = dropped.length > 5 ? `, … and ${dropped.length - 5} more` : '';
    lines.push(
      `warning: ${dropped.length} of ${declared} records in the normalized events file were `
      + 'refused by the schema loader (not an object, or missing a field its dialect requires) '
      + `and are absent from this run — array index ${shown}${more}. The raw dialect lanes `
      + 'hard-error on a bad record; this lane can only report one.',
    );
  }

  const candidateCounts = countByType(run.candidates);
  const discardCounts = countByType(run.caputMortuum);
  lines.push(`candidates: ${run.candidates.length}`);
  const typeWidth = Math.max(...config.candidateTypes.map((type) => type.length));
  for (const type of config.candidateTypes) {
    const floor = config.emitFloors[type];
    const dropped = discardCounts.get(type) ?? 0;
    const suffix = dropped > 0
      ? `   (${dropped} below the ${floor} floor)`
      : '';
    lines.push(`  ${type.padEnd(typeWidth)}  ${String(candidateCounts.get(type) ?? 0).padStart(4)}${suffix}`);
  }
  lines.push(`caput mortuum (dropped by the emit floors): ${run.caputMortuum.length}`);

  if (ingested.ambiguities.length > 0) {
    lines.push(
      `warning: ${ingested.ambiguities.length} record pair`
      + `${ingested.ambiguities.length === 1 ? ' shares' : 's share'} a timestamp AND a dialect, `
      + 'which the id-reconstruction rule cannot separate — those events were numbered in '
      + 'file/line order, so evidence ids (and every candidate id derived from them) depend '
      + 'on how this folder was read. Re-running on the same folder is stable; re-running on '
      + 'a re-ordered export is not.',
    );
    for (const ambiguity of ingested.ambiguities.slice(0, 5)) {
      lines.push(`  ${ambiguity.dialect} @ ${ambiguity.timestamp}: ${ambiguity.origins.join(' / ')}`);
    }
    if (ingested.ambiguities.length > 5) {
      lines.push(`  … and ${ingested.ambiguities.length - 5} more`);
    }
  }

  lines.push(`wrote ${resolve(outputPath)}`);
  if (discardsPath !== undefined) {
    lines.push(`wrote ${resolve(discardsPath)}`);
  }
  return lines;
}

async function run(argv: readonly string[]): Promise<number> {
  try {
    const options = parseCliArgs(argv);
    if (options === 'help') {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    }
    if (options === 'version') {
      process.stdout.write(`${PROGRAM} ${packageVersion()}\n`);
      return 0;
    }

    const tooOld = nodeVersionComplaint(process.versions.node, 22, PROGRAM);
    if (tooOld !== undefined) throw new CliError(tooOld);

    const { config, summaryLine: configSummary } = loadConfig(options.configPath);

    let ingested: IngestResult;
    try {
      // The named config is handed to the scan so a config sitting INSIDE the
      // telemetry folder is skipped and reported, not refused as unclassifiable.
      ingested = await ingestFolder(options.telemetryDir, { configPath: options.configPath });
    } catch (error) {
      throw new CliError(`cannot ingest ${options.telemetryDir}: ${(error as Error).message}`);
    }

    const result = runPipeline(ingested.events, config);

    writeArtifact(options.outputPath, canonicalJsonWithRounding(result.candidates), 'candidates');
    if (options.discardsPath !== undefined) {
      writeArtifact(
        options.discardsPath,
        canonicalJsonWithRounding(result.caputMortuum),
        'the caput mortuum',
      );
    }

    const summary = summaryLines(
      options.telemetryDir,
      ingested,
      result,
      config,
      options.outputPath,
      options.discardsPath,
      configSummary,
    );
    process.stderr.write(`${summary.join('\n')}\n`);
    return 0;
  } catch (error) {
    if (error instanceof CliError) {
      const usage = error.withUsage ? `\n${USAGE}\n` : '';
      process.stderr.write(`${PROGRAM}: ${error.message}\n${usage}`);
      return 1;
    }
    // Anything else is a defect, not a user error: keep the stack.
    throw error;
  }
}

process.exitCode = await run(process.argv.slice(2));
