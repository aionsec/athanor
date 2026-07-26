/**
 * Folder ingest — `athanor ./telemetry/` starts here.
 *
 * Point it at a directory of raw logs; it classifies each file (filename pattern
 * first, first-line sniffing as the fallback), parses each dialect with its own
 * parser, merges everything under the ordering rule in `merge.ts`, and returns a
 * normalized event stream with reconstructed `evt-%05d` ids.
 *
 * A folder of already-normalized events (`events.json`) is also accepted — that lane
 * goes through the schema loader's own admission rules (`loadEventsFromArray`) and
 * keeps the ids the file carries, so it must be the only telemetry file in the folder
 * (mixing the two would let two id schemes collide in one stream).
 *
 * Nothing here is lenient by default: an unclassifiable file, a malformed line and
 * an empty folder are all hard errors. Silently skipping a file is silently losing
 * evidence, which is the one failure mode a distillation kit must never have. What
 * a folder scan legitimately cannot ingest — a subdirectory, a symlink that leads
 * nowhere, a config file, a record the normalized loader refuses — is REPORTED
 * (`skipped`, `droppedRecordIndices`) rather than dropped in silence: skipping is
 * allowed to be legitimate, it is not allowed to be quiet.
 *
 * Dotfiles are the one deliberate exception. `.DS_Store` is not evidence.
 *
 * Compression is invisible here: `decodeTelemetryBytes` gunzips on the magic bytes,
 * so `conn.log.gz` — what Zeek's own rotation writes — is the `zeek/conn` dialect
 * like any other file, in every lane.
 */

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import { basename, extname, join, resolve } from 'node:path';
import { DEFAULT_ATHANOR_CONFIG_FILENAME } from '../run/config.js';
import { loadEventsFromArray, type TelemetryEvent } from '../schema/events.js';
import {
  decodeTelemetryBytes,
  describeUnreadableText,
  IngestError,
  parseJsonLines,
  type RawRecord,
} from './codecs.js';
import {
  countEqualTimestampGroups,
  type DialectKind,
  findOrderingAmbiguities,
  mergeAndAssignIds,
  type OrderingAmbiguity,
  type ParsedEvent,
} from './merge.js';
import { parsePowerShell4104Record, POWERSHELL_SCRIPT_BLOCK_DIALECT } from './ps-4104.js';
import {
  parseSysmonRecord,
  SYSMON_NETWORK_CONNECT_DIALECT,
  SYSMON_PROCESS_CREATE_DIALECT,
} from './sysmon-jsonl.js';
import { parseZeekConnRecord, ZEEK_CONN_DIALECT } from './zeek-conn.js';
import { parseZeekSslRecord, ZEEK_SSL_DIALECT } from './zeek-ssl.js';

/** What a file in the folder was recognized as. */
export type FileKind = DialectKind | 'normalized-events';

export const NORMALIZED_EVENTS_KIND = 'normalized-events';

type RecordParser = (raw: RawRecord) => ParsedEvent;

/**
 * Sysmon files are parsed with the per-record dispatcher rather than with the
 * EID-specific parser: the filename is a hint, the `EventID` on each line is the
 * authority (real estates ship one mixed Sysmon stream).
 */
const PARSER_BY_KIND: Record<DialectKind, RecordParser> = {
  [ZEEK_CONN_DIALECT]: parseZeekConnRecord,
  [ZEEK_SSL_DIALECT]: parseZeekSslRecord,
  [SYSMON_PROCESS_CREATE_DIALECT]: parseSysmonRecord,
  [SYSMON_NETWORK_CONNECT_DIALECT]: parseSysmonRecord,
  [POWERSHELL_SCRIPT_BLOCK_DIALECT]: parsePowerShell4104Record,
};

/**
 * Filename patterns, most specific first. `network_connect` is matched before the
 * bare `conn` rule so a `sysmon-network_connect.jsonl` is never read as a Zeek
 * conn.log.
 */
const NAME_RULES: ReadonlyArray<readonly [RegExp, FileKind]> = [
  [/(^|[^a-z0-9])(4104|script[_-]?block|powershell)([^a-z0-9]|$)/i, POWERSHELL_SCRIPT_BLOCK_DIALECT],
  [/(^|[^a-z0-9])(eid[_-]?1|process[_-]?create)([^0-9]|$)/i, SYSMON_PROCESS_CREATE_DIALECT],
  [/(^|[^a-z0-9])(eid[_-]?3|network[_-]?connect)([^0-9]|$)/i, SYSMON_NETWORK_CONNECT_DIALECT],
  [/(^|[^a-z0-9])ssl([^a-z0-9]|$)/i, ZEEK_SSL_DIALECT],
  [/(^|[^a-z0-9])conn([^a-z0-9]|$)/i, ZEEK_CONN_DIALECT],
  [/(^|[^a-z0-9])events\.json$/i, NORMALIZED_EVENTS_KIND],
];

/**
 * Classify by filename alone. `undefined` = the name says nothing; sniff the content.
 *
 * A trailing `.gz` is stripped first: `conn.log.gz` is what Zeek's own rotation
 * writes, and it is the same dialect as `conn.log` — the compression is a wrapper the
 * decoder has already dealt with by the time anything downstream sees the bytes.
 */
export function classifyByName(fileName: string): FileKind | undefined {
  const name = basename(fileName).replace(/\.gz$/i, '');
  for (const [pattern, kind] of NAME_RULES) {
    if (pattern.test(name)) return kind;
  }
  return undefined;
}

/**
 * Classify by the first record's shape. Zeek conn and ssl share `ts`/`uid`/`id.*`,
 * so the ssl-only columns are the discriminator.
 */
export function classifyByRecord(record: Record<string, unknown>): FileKind | undefined {
  if ('ScriptBlockText' in record || 'ScriptBlockId' in record) {
    return POWERSHELL_SCRIPT_BLOCK_DIALECT;
  }
  if ('EventID' in record) {
    if (record.EventID === 3) return SYSMON_NETWORK_CONNECT_DIALECT;
    if (record.EventID === 1) return SYSMON_PROCESS_CREATE_DIALECT;
    return undefined;
  }
  if ('ts' in record && 'id.orig_h' in record) {
    const sslMarkers = ['server_name', 'ja3', 'ja3s', 'ja4', 'subject', 'issuer', 'cipher'];
    if (sslMarkers.some((marker) => marker in record)) return ZEEK_SSL_DIALECT;
    return ZEEK_CONN_DIALECT;
  }
  return undefined;
}

export interface IngestedFileSummary {
  /** File name relative to the ingested folder. */
  file: string;
  classifiedAs: FileKind;
  /** How the classification was reached. */
  classifiedBy: 'filename' | 'content';
  events: number;
}

/** Why a directory entry was not read as telemetry. */
export type SkipReason =
  | 'subdirectory'
  | 'symlink to a directory'
  | 'broken symlink'
  | 'not a regular file'
  | 'config file';

/** A directory entry the scan did not read — reported, never silent. */
export interface SkippedEntry {
  name: string;
  reason: SkipReason;
}

export interface IngestResult {
  /** Normalized events in canon order, with reconstructed ids. */
  events: TelemetryEvent[];
  files: IngestedFileSummary[];
  /**
   * Directory entries the scan could not read as a file (dotfiles excluded — those
   * are skipped by convention). Empty for a clean telemetry folder.
   */
  skipped: SkippedEntry[];
  /**
   * Normalized lane only: 0-based indices in the `events.json` array that
   * `loadEvents` refused (not an object, or missing a required field for its
   * dialect). The raw lanes hard-error on a bad record instead, so this is always
   * empty for them — but this lane can only report, and reporting nothing while
   * discarding evidence is the failure mode the module forswears.
   */
  droppedRecordIndices: number[];
  /** Event counts keyed `source/event_type`. */
  byDialect: Record<string, number>;
  /**
   * Records the ordering rule could not separate (same timestamp AND same dialect).
   * Empty for the course canon; a real estate may produce them, and then the ids
   * depend on file/line order rather than on the rule alone.
   */
  ambiguities: OrderingAmbiguity[];
  equalTimestampGroups: number;
  /** True when the folder was an already-normalized `events.json` lane. */
  normalized: boolean;
}

interface DirectoryScan {
  files: string[];
  skipped: SkippedEntry[];
}

/** How a caller (the CLI) tells the scan about files that are not telemetry. */
export interface IngestOptions {
  /**
   * The `--config` path, if one was named. A config that happens to sit inside the
   * telemetry folder is skipped and reported rather than refused as an
   * unclassifiable file — configuration is not evidence, and losing it loses nothing.
   */
  configPath?: string;
}

/**
 * Is this entry a config file rather than telemetry?
 *
 * Two ways to qualify: it IS the file `--config` named (compared by resolved path,
 * and by real path so a link to it counts), or it carries the default config name,
 * which athanor reserves for exactly this purpose. Any OTHER `.yaml` in the folder is
 * still an error — athanor skips the config it knows about, not every file it would
 * rather not think about.
 */
async function isConfigFile(
  entryPath: string,
  name: string,
  configPath: string | undefined,
): Promise<boolean> {
  const lower = name.toLowerCase();
  const defaultName = DEFAULT_ATHANOR_CONFIG_FILENAME.toLowerCase();
  if (lower === defaultName || lower === defaultName.replace(/\.yaml$/, '.yml')) return true;
  if (configPath === undefined) return false;
  if (resolve(entryPath) === resolve(configPath)) return true;
  const [entryReal, configReal] = await Promise.all([
    realpath(entryPath).catch(() => null),
    realpath(configPath).catch(() => null),
  ]);
  return entryReal !== null && configReal !== null && entryReal === configReal;
}

/**
 * Lists the readable files in `dir` and accounts for everything it did not list.
 *
 * Symlinks are FOLLOWED (`stat`, not the dirent's own type): an estate that presents
 * its logs as links into an archive is a normal shape, and `entry.isFile()` is false
 * for every one of them — which used to turn such a folder into "no files to ingest".
 */
async function scanDirectory(dir: string, options: IngestOptions = {}): Promise<DirectoryScan> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    const info = await stat(dir).catch(() => null);
    if (info && !info.isDirectory()) {
      throw new IngestError(`not a directory: ${dir}`);
    }
    throw new IngestError(`cannot read telemetry folder ${dir}: ${(error as Error).message}`);
  }

  const files: string[] = [];
  const skipped: SkippedEntry[] = [];

  for (const entry of entries) {
    // Dotfiles are skipped by convention (`.DS_Store`, `.gitkeep`): not evidence.
    if (entry.name.startsWith('.')) continue;
    if (await isConfigFile(join(dir, entry.name), entry.name, options.configPath)) {
      skipped.push({ name: entry.name, reason: 'config file' });
      continue;
    }
    if (entry.isFile()) {
      files.push(entry.name);
      continue;
    }
    if (entry.isSymbolicLink()) {
      const target = await stat(join(dir, entry.name)).catch(() => null);
      if (target === null) {
        skipped.push({ name: entry.name, reason: 'broken symlink' });
      } else if (target.isFile()) {
        files.push(entry.name);
      } else if (target.isDirectory()) {
        skipped.push({ name: entry.name, reason: 'symlink to a directory' });
      } else {
        skipped.push({ name: entry.name, reason: 'not a regular file' });
      }
      continue;
    }
    skipped.push({
      name: entry.name,
      reason: entry.isDirectory() ? 'subdirectory' : 'not a regular file',
    });
  }

  files.sort();
  skipped.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  return { files, skipped };
}

/** One clause naming what the scan passed over, for an error or a warning line. */
export function describeSkippedEntries(skipped: ReadonlyArray<SkippedEntry>, limit = 5): string {
  const shown = skipped.slice(0, limit)
    .map((entry) => `${entry.name} (${entry.reason})`)
    .join(', ');
  const more = skipped.length > limit ? `, … and ${skipped.length - limit} more` : '';
  return `${skipped.length} entr${skipped.length === 1 ? 'y' : 'ies'}: ${shown}${more}`;
}

/**
 * Which entries of an `events.json` array `loadEvents` did not admit.
 *
 * Derived rather than re-validated: `loadEvents` keeps input order and stamps each
 * admitted record with either its own `id` or `evt-synth-%06d` built from the input
 * index, so the id a record WOULD carry is computable here — and its absence from
 * the admitted stream is exactly "this record was dropped". That keeps the schema
 * loader's admission rules in one place (`src/schema/events.ts`) instead of forking
 * them into a second copy that could drift.
 */
function findDroppedRecordIndices(
  declared: readonly unknown[],
  admitted: ReadonlyArray<TelemetryEvent>,
): number[] {
  const remaining = new Map<string, number>();
  for (const event of admitted) {
    const id = String((event as unknown as Record<string, unknown>).id);
    remaining.set(id, (remaining.get(id) ?? 0) + 1);
  }

  const dropped: number[] = [];
  for (let index = 0; index < declared.length; index += 1) {
    const item = declared[index];
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      dropped.push(index);
      continue;
    }
    const rawId = (item as Record<string, unknown>).id;
    const id = typeof rawId === 'string' && rawId.trim().length > 0
      ? rawId.trim()
      : `evt-synth-${String(index + 1).padStart(6, '0')}`;
    const count = remaining.get(id) ?? 0;
    if (count === 0) {
      dropped.push(index);
      continue;
    }
    remaining.set(id, count - 1);
  }
  return dropped;
}

/**
 * Reads every recognized telemetry file in `dir` and returns one normalized,
 * canon-ordered event stream.
 */
export async function ingestFolder(
  dir: string,
  options: IngestOptions = {},
): Promise<IngestResult> {
  const { files: names, skipped } = await scanDirectory(dir, options);
  if (names.length === 0) {
    const passedOver = skipped.length > 0 ? ` (skipped ${describeSkippedEntries(skipped)})` : '';
    throw new IngestError(`no files to ingest in ${dir}${passedOver}`);
  }

  const classified: Array<{ name: string; kind: FileKind; by: 'filename' | 'content'; text: string }> = [];

  for (const name of names) {
    const path = join(dir, name);
    // Bytes, not a utf-8 string: gzip and UTF-16 have to be recognized BEFORE a decode
    // turns them into mojibake that dies as "malformed JSON" three layers down.
    const text = decodeTelemetryBytes(await readFile(path), path);
    // A body that is not JSON at all (Zeek's TSV default) is named for what it is
    // here, before classification can mislabel it as merely unrecognized.
    const unreadable = describeUnreadableText(text, path);
    if (unreadable !== undefined) throw new IngestError(unreadable);

    const byName = classifyByName(name);
    if (byName) {
      classified.push({ name, kind: byName, by: 'filename', text });
      continue;
    }

    // First-line sniffing: a JSON array is a normalized events file, a JSON object
    // is one telemetry record whose keys name its dialect.
    const firstLine = text.split('\n').find((line) => line.trim().length > 0);
    if (firstLine !== undefined) {
      const trimmed = firstLine.trimStart();
      if (trimmed.startsWith('[')) {
        classified.push({ name, kind: NORMALIZED_EVENTS_KIND, by: 'content', text });
        continue;
      }
      try {
        const parsed = JSON.parse(firstLine) as unknown;
        if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
          const kind = classifyByRecord(parsed as Record<string, unknown>);
          if (kind) {
            classified.push({ name, kind, by: 'content', text });
            continue;
          }
        }
      } catch {
        // fall through to the unrecognized-file error
      }
    }

    // An `athanor.yaml` and the file `--config` named are skipped by the scan; any
    // OTHER yaml is still unclassifiable, and "here are the dialects" is not the
    // answer to it.
    if (['.yaml', '.yml'].includes(extname(name.replace(/\.gz$/i, '')).toLowerCase())) {
      throw new IngestError(
        `unrecognized telemetry file: ${join(dir, name)} — a config file is not telemetry. `
        + `Name it with --config, or call it ${DEFAULT_ATHANOR_CONFIG_FILENAME}, and the scan `
        + 'will pass over it.',
      );
    }

    throw new IngestError(
      `unrecognized telemetry file: ${join(dir, name)} — athanor ingests zeek conn.log/ssl.log `
      + '(JSON lines), Sysmon EID 1/3 JSONL, PowerShell 4104 JSONL, and a normalized events.json',
    );
  }

  const normalizedFiles = classified.filter((item) => item.kind === NORMALIZED_EVENTS_KIND);
  if (normalizedFiles.length > 0) {
    if (classified.length > normalizedFiles.length) {
      throw new IngestError(
        `${dir} mixes a normalized events file (${normalizedFiles[0]!.name}) with raw dialect files; `
        + 'ingest either reconstructs ids from raw logs or trusts the ids a normalized file carries, '
        + 'never both in one stream',
      );
    }
    if (normalizedFiles.length > 1) {
      throw new IngestError(
        `${dir} holds ${normalizedFiles.length} normalized events files; ingest accepts one`,
      );
    }

    const normalizedFile = normalizedFiles[0]!;
    const normalizedPath = join(dir, normalizedFile.name);
    // The DECODED text, not a second read of the file: this lane has to admit a
    // gzip'd `events.json` like every other lane, and only the bytes that came
    // through `decodeTelemetryBytes` are known to be text.
    let declared: unknown;
    try {
      declared = JSON.parse(normalizedFile.text) as unknown;
    } catch (error) {
      throw new IngestError(
        `${normalizedPath}: malformed JSON (${(error as Error).message})`,
      );
    }
    const events = loadEventsFromArray(declared, normalizedPath);
    // The loader discards a record it cannot admit and says nothing. Its admission
    // rules stay in `src/schema/events.ts`; the accounting happens HERE so this
    // lane's posture matches the raw lanes' — one of them hard-errors, both tell you.
    const droppedRecordIndices = Array.isArray(declared)
      ? findDroppedRecordIndices(declared, events)
      : [];

    return {
      events,
      files: [{
        file: normalizedFile.name,
        classifiedAs: NORMALIZED_EVENTS_KIND,
        classifiedBy: normalizedFile.by,
        events: events.length,
      }],
      skipped,
      droppedRecordIndices,
      byDialect: countByDialect(events),
      ambiguities: [],
      equalTimestampGroups: 0,
      normalized: true,
    };
  }

  const parsed: ParsedEvent[] = [];
  const files: IngestedFileSummary[] = [];

  for (const item of classified) {
    const parser = PARSER_BY_KIND[item.kind as DialectKind];
    const records = parseJsonLines(item.text, join(dir, item.name));
    const events = records.map(parser);
    parsed.push(...events);
    files.push({
      file: item.name,
      classifiedAs: item.kind,
      classifiedBy: item.by,
      events: events.length,
    });
  }

  if (parsed.length === 0) {
    throw new IngestError(`no telemetry records found in ${dir}`);
  }

  const events = mergeAndAssignIds(parsed);
  return {
    events,
    files,
    skipped,
    // The raw lanes hard-error on an undecodable record; nothing reaches here dropped.
    droppedRecordIndices: [],
    byDialect: countByDialect(events),
    ambiguities: findOrderingAmbiguities(parsed),
    equalTimestampGroups: countEqualTimestampGroups(parsed),
    normalized: false,
  };
}

function countByDialect(events: ReadonlyArray<Record<string, unknown>>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    const key = `${String(event.source)}/${String(event.event_type)}`;
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

export { IngestError } from './codecs.js';
export {
  assignEventId,
  assertSequenceMatches,
  DIALECT_ORDER_RANK,
  type DialectKind,
  mergeAndAssignIds,
  type OrderingAmbiguity,
  type ParsedEvent,
  toSequence,
} from './merge.js';
export { parseZeekConn, parseZeekConnRecord } from './zeek-conn.js';
export { parseZeekSsl, parseZeekSslRecord } from './zeek-ssl.js';
export {
  parseSysmon,
  parseSysmonEid1,
  parseSysmonEid1Record,
  parseSysmonEid3,
  parseSysmonEid3Record,
  parseSysmonRecord,
} from './sysmon-jsonl.js';
export { parsePowerShell4104, parsePowerShell4104Record } from './ps-4104.js';
export {
  decodeTelemetryBytes,
  describeUnreadableText,
  fromIsoTimestamp,
  parseJsonLines,
  type RawRecord,
  stripBom,
} from './codecs.js';
