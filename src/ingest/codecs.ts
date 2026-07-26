/**
 * Shared raw-ingest primitives: JSONL reading, the dialect timestamp codecs, and
 * a typed field reader that reports `file:line` on every failure.
 *
 * Each codec here is the exact inverse of the one that renders the sample dataset's raw
 * dialect files: that renderer writes a token only after re-parsing it with the rule
 * below and asserting the result reproduces its input, so the pair round-trips by
 * construction rather than by hope. Pin C is the standing proof.
 */

import { gunzipSync } from 'node:zlib';

/** Raised for anything ingest cannot decode. Always carries `file:line` context. */
export class IngestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IngestError';
  }
}

/** Zeek's "unset" token — written for a null OR empty string field. */
export const ZEEK_UNSET = '-';
/** Sysmon's "unset" token for absent PE metadata (Description/Product/Company/OriginalFileName). */
export const SYSMON_UNSET = '-';

/** One decoded JSONL record plus the source coordinates for error messages. */
export interface RawRecord {
  record: Record<string, unknown>;
  file: string;
  line: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** U+FEFF — the UTF-8 byte-order mark. Windows exports carry one routinely; it is not data. */
const BOM_CODE_POINT = 0xfeff;

/**
 * Strips a leading UTF-8 BOM. A BOM'd first line is valid JSON with it removed, and
 * "Unexpected token '﻿'" is not a message anyone can act on.
 */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === BOM_CODE_POINT ? text.slice(1) : text;
}

/**
 * The `#separator`-style banner Zeek's DEFAULT (ASCII/TSV) logger writes. athanor v1
 * reads JSON only, so the honest thing is to name the situation rather than let the
 * banner surface as "malformed JSON line (Unexpected token '#')".
 */
const ZEEK_TSV_BANNER_RE
  = /^#(separator|set_separator|empty_field|unset_field|path|open|close|fields|types)\b/;

/**
 * Recognizes a body athanor cannot read at all and explains it. `undefined` = the
 * text is at least plausibly JSON lines; the per-line parser takes it from there.
 */
export function describeUnreadableText(text: string, file: string): string | undefined {
  const firstLine = text.split('\n').find((line) => line.trim().length > 0);
  if (firstLine === undefined) return undefined;
  const trimmed = stripBom(firstLine).trimStart();

  // No gzip branch here any more: compression is decided on BYTES in
  // `decodeTelemetryBytes`, which decompresses before any of this text exists.
  const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');
  if (!looksJson && (ZEEK_TSV_BANNER_RE.test(trimmed) || trimmed.includes('\t'))) {
    return `${file}: this is a TAB-SEPARATED Zeek log; athanor v1 reads JSON logs only. `
      + 'Re-run Zeek with JSON logging (`redef LogAscii::use_json=T;` in local.zeek, or the '
      + 'json-streaming-logs package) and ingest the resulting conn.log / ssl.log.';
  }
  return undefined;
}

function startsWithMagic(bytes: Uint8Array, magic: readonly number[]): boolean {
  if (bytes.length < magic.length) return false;
  return magic.every((byte, index) => bytes[index] === byte);
}

/** gzip: `1f 8b`. Zeek rotates its logs into this by default, so athanor reads it. */
const GZIP_MAGIC = [0x1f, 0x8b] as const;

/**
 * The other compressed containers a log directory collects. athanor decompresses
 * gzip and only gzip — every one of these is one command away from a file it reads,
 * and guessing at an archive's internal layout is not ingest's job.
 */
const FOREIGN_COMPRESSION: ReadonlyArray<{
  magic: readonly number[];
  name: string;
  fix: string;
}> = [
  { magic: [0x28, 0xb5, 0x2f, 0xfd], name: 'zstd', fix: 'unzstd <file>' },
  { magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], name: 'xz', fix: 'unxz <file>' },
  { magic: [0x42, 0x5a, 0x68], name: 'bzip2', fix: 'bunzip2 <file>' },
  { magic: [0x50, 0x4b, 0x03, 0x04], name: 'zip', fix: 'unzip <file> -d <folder>' },
  { magic: [0x04, 0x22, 0x4d, 0x18], name: 'lz4', fix: 'unlz4 <file>' },
  { magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], name: '7-zip', fix: '7z x <file>' },
];

/** `ustar` at offset 257 — a tar, usually what was inside the `.tar.gz` just opened. */
function isTar(bytes: Uint8Array): boolean {
  const magic = [0x75, 0x73, 0x74, 0x61, 0x72];
  if (bytes.length < 262) return false;
  return magic.every((byte, index) => bytes[257 + index] === byte);
}

/** Nested-gzip guard: a real log is never wrapped more than once. */
const MAX_INFLATIONS = 4;

/**
 * Turns a telemetry file's BYTES into text.
 *
 * gzip is TRANSPARENT — `conn.log.gz` is what Zeek's own rotation writes, so a folder
 * of rotated logs ingests exactly like a folder of plain ones, and the magic bytes
 * rather than the extension decide (a mislabeled `conn.log` that is really gzip is
 * still read). Everything else that is not UTF-8 text is named for what it is: an
 * encoding or a container athanor does not open, said plainly, instead of mojibake
 * that dies as "malformed JSON" three layers down. The checks live here because a
 * utf-8 decode destroys the evidence of what the file was.
 */
export function decodeTelemetryBytes(bytes: Uint8Array, file: string): string {
  let body = bytes;
  let inflations = 0;
  while (startsWithMagic(body, GZIP_MAGIC)) {
    if (inflations >= MAX_INFLATIONS) {
      throw new IngestError(
        `${file}: this file is gzip'd more than ${MAX_INFLATIONS} times over; `
        + 'decompress it by hand and ingest the result.',
      );
    }
    try {
      body = gunzipSync(body);
    } catch (error) {
      throw new IngestError(
        `${file}: gzip magic bytes (1f 8b) but the body did not decompress `
        + `(${(error as Error).message}) — the file is truncated or corrupt.`,
      );
    }
    inflations += 1;
  }

  if (isTar(body)) {
    throw new IngestError(
      `${file}: this is a tar archive${inflations > 0 ? ' (inside the gzip)' : ''}; athanor `
      + 'ingests a FOLDER of log files. Unpack it (`tar xf <file>`) and point athanor at the '
      + 'folder it produced.',
    );
  }

  for (const format of FOREIGN_COMPRESSION) {
    if (startsWithMagic(body, format.magic)) {
      throw new IngestError(
        `${file}: this is a ${format.name} file; athanor decompresses gzip and nothing else. `
        + `Decompress it first (\`${format.fix}\`) and ingest the result.`,
      );
    }
  }

  if (
    body.length >= 2
    && ((body[0] === 0xff && body[1] === 0xfe) || (body[0] === 0xfe && body[1] === 0xff))
  ) {
    throw new IngestError(
      `${file}: this file is UTF-16 (byte-order mark), not UTF-8 — re-export it as UTF-8 `
      + '(PowerShell: `-Encoding utf8`) and ingest the result.',
    );
  }
  return stripBom(new TextDecoder('utf-8').decode(body));
}

/**
 * Decodes a JSON-lines body. Blank lines are skipped (trailing newline is normal);
 * anything else that is not a JSON object is a hard error — silently dropping a
 * telemetry line would silently drop evidence.
 *
 * A body that is not JSON at all (Zeek's TSV default, a gzip blob) is named for what
 * it is before the first `JSON.parse`, because "Unexpected token '#'" blames JSON
 * syntax for a situation that has nothing to do with syntax.
 */
export function parseJsonLines(text: string, file: string): RawRecord[] {
  const unreadable = describeUnreadableText(text, file);
  if (unreadable !== undefined) throw new IngestError(unreadable);

  const out: RawRecord[] = [];
  const lines = stripBom(text).split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? '';
    if (raw.trim().length === 0) continue;
    const line = index + 1;

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new IngestError(
        `${file}:${line}: malformed JSON line (${(error as Error).message})`,
      );
    }
    if (!isRecord(parsed)) {
      throw new IngestError(`${file}:${line}: expected a JSON object, got ${typeof parsed}`);
    }
    out.push({ record: parsed, file, line });
  }
  return out;
}

/** Zeek `ts` (epoch seconds) → epoch milliseconds. Inverse of the emitter's 6-dp writer. */
export function fromZeekEpochSeconds(seconds: number): number {
  return Math.round(seconds * 1000);
}

const SYSMON_UTC_TIME_RE = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})$/;

/** Sysmon `UtcTime` (`YYYY-MM-DD HH:MM:SS.mmm`, UTC) → epoch milliseconds. NaN if unparseable. */
export function fromSysmonUtcTime(text: string): number {
  const match = SYSMON_UTC_TIME_RE.exec(text);
  if (!match) return Number.NaN;
  return Date.parse(
    `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}.${match[7]}Z`,
  );
}

/**
 * ISO 8601 date-time, the only shape the 4104 lane accepts. The zone is optional in
 * the grammar because real exports omit it; it is NOT optional in meaning — see
 * `fromIsoTimestamp`.
 */
const ISO_TIMESTAMP_RE
  = /^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?[ ]?(Z|z|[+-]\d{2}:?\d{2})?)?$/;

/**
 * ISO 8601 `TimeCreated` → epoch milliseconds. `NaN` if the text is not ISO 8601.
 *
 * A zone-less stamp is read as **UTC, always**. Bare `Date.parse` reads a zone-less
 * date-TIME in the machine's local zone, which would make `TZ` an input to the event
 * stream: the same folder would produce different timestamps — and therefore
 * different reconstructed ids and different content-derived candidate ids — on a
 * laptop in Cape Town and on a CI box in UTC. Anything that is not ISO 8601 at all
 * (a locale stamp like `7/25/2026 5:04:47 PM`) is refused rather than guessed at,
 * mirroring the strictness of `fromSysmonUtcTime`.
 *
 * Sub-millisecond precision (Windows writes 7 fractional digits) is TRUNCATED to ms,
 * the same resolution the rest of the contract works in.
 */
export function fromIsoTimestamp(text: string): number {
  const match = ISO_TIMESTAMP_RE.exec(text.trim());
  if (!match) return Number.NaN;
  const [, date, hours, minutes, seconds, fraction, zone] = match;
  const time = `${hours ?? '00'}:${minutes ?? '00'}:${seconds ?? '00'}`;
  const millis = (fraction ?? '').padEnd(3, '0').slice(0, 3);
  return Date.parse(`${date}T${time}.${millis}${normalizeIsoZone(zone)}`);
}

/** `undefined`/`Z` → `Z` (zone-less is UTC); `+0200` → `+02:00` (the spec form V8 parses). */
function normalizeIsoZone(zone: string | undefined): string {
  if (zone === undefined || zone.toUpperCase() === 'Z') return 'Z';
  return zone.includes(':') ? zone : `${zone.slice(0, 3)}:${zone.slice(3)}`;
}

/** Epoch milliseconds → the normalized ISO 8601 timestamp every event carries. */
export function isoFromMs(ms: number): string {
  return new Date(ms).toISOString();
}

/** Basename for Windows paths — `node:path.basename` does not split `\` on POSIX. */
export function windowsBasename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

/**
 * The hint for a field that is the right value in the wrong type. Shippers that
 * render every column as a string (winlogbeat and friends) turn `"EventID": 1` into
 * `"EventID": "1"`, and a student converting a real EVTX export otherwise meets that
 * one field at a time with no idea it is a whole-file property.
 */
function quotedNumberHint(value: unknown): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (trimmed.length === 0 || !Number.isFinite(Number(trimmed))) return '';
  return ' — this is a NUMBER written as a string, which usually means the whole export '
    + 'quotes every field; athanor wants JSON numbers here. See docs/extending.md for '
    + 'writing a converter.';
}

/**
 * Typed accessors over one raw record. Every failure names the dialect field and
 * the exact source line, so a bad estate log points at itself rather than at a
 * downstream `undefined`.
 */
export class RecordReader {
  constructor(private readonly raw: RawRecord) {}

  get label(): string {
    return `${this.raw.file}:${this.raw.line}`;
  }

  private fail(message: string): never {
    throw new IngestError(`${this.label}: ${message}`);
  }

  has(key: string): boolean {
    return key in this.raw.record && this.raw.record[key] !== undefined;
  }

  raw$(key: string): unknown {
    return this.raw.record[key];
  }

  requiredString(key: string): string {
    const value = this.raw.record[key];
    if (typeof value !== 'string' || value.length === 0) {
      this.fail(`expected non-empty string field "${key}", got ${JSON.stringify(value)}`);
    }
    return value;
  }

  /** Absent/null → `undefined`. A present non-string is an error, not a coercion. */
  optionalString(key: string): string | undefined {
    const value = this.raw.record[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== 'string') {
      this.fail(`expected string field "${key}", got ${JSON.stringify(value)}`);
    }
    return value;
  }

  /** Zeek/Sysmon string field: the unset token AND the empty string both decode to `undefined`. */
  unsetAwareString(key: string, unsetToken: string): string | undefined {
    const value = this.optionalString(key);
    if (value === undefined || value === unsetToken || value.length === 0) return undefined;
    return value;
  }

  requiredNumber(key: string): number {
    const value = this.raw.record[key];
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      this.fail(`expected finite number field "${key}", got ${JSON.stringify(value)}${quotedNumberHint(value)}`);
    }
    return value;
  }

  optionalNumber(key: string): number | undefined {
    const value = this.raw.record[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      this.fail(`expected finite number field "${key}", got ${JSON.stringify(value)}${quotedNumberHint(value)}`);
    }
    return value;
  }

  optionalBoolean(key: string): boolean | undefined {
    const value = this.raw.record[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== 'boolean') {
      this.fail(`expected boolean field "${key}", got ${JSON.stringify(value)}`);
    }
    return value;
  }

  /** Passthrough for a field whose wire type varies across estates (zeek `established`). */
  optionalScalar(key: string): string | number | boolean | undefined {
    const value = this.raw.record[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    this.fail(`expected scalar field "${key}", got ${JSON.stringify(value)}`);
  }

  optionalStringArray(key: string): string[] | undefined {
    const value = this.raw.record[key];
    if (value === undefined || value === null) return undefined;
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
      this.fail(`expected string[] field "${key}", got ${JSON.stringify(value)}`);
    }
    return value as string[];
  }

  /** Zeek `ts` → epoch ms. */
  zeekTimestampMs(key = 'ts'): number {
    const seconds = this.raw.record[key];
    if (typeof seconds !== 'number' || !Number.isFinite(seconds)) {
      const isoHint = typeof seconds === 'string' && ISO_TIMESTAMP_RE.test(seconds.trim())
        ? ' — this Zeek is writing ISO timestamps (`redef LogAscii::json_timestamps = '
          + 'JSON::TS_ISO8601;`); athanor reads the default epoch-seconds form '
          + '(`JSON::TS_EPOCH`)'
        : quotedNumberHint(seconds);
      this.fail(
        `expected numeric zeek "${key}" (epoch seconds), got ${JSON.stringify(seconds)}${isoHint}`,
      );
    }
    return fromZeekEpochSeconds(seconds);
  }

  /** Sysmon `UtcTime` → epoch ms. */
  sysmonTimestampMs(key = 'UtcTime'): number {
    const text = this.requiredString(key);
    const ms = fromSysmonUtcTime(text);
    if (!Number.isFinite(ms)) {
      this.fail(`unparseable Sysmon "${key}" "${text}" (expected YYYY-MM-DD HH:MM:SS.mmm)`);
    }
    return ms;
  }

  /**
   * ISO 8601 field → epoch ms (the 4104 lane's `TimeCreated`). Zone-less is read as
   * UTC; a non-ISO stamp is an error, never a local-time guess.
   */
  isoTimestampMs(key: string): number {
    const text = this.requiredString(key);
    const ms = fromIsoTimestamp(text);
    if (!Number.isFinite(ms)) {
      this.fail(
        `unparseable ISO timestamp "${key}" "${text}" — expected ISO 8601 `
        + '(YYYY-MM-DDTHH:MM:SS[.mmm][Z|±HH:MM]). A stamp with no zone is read as UTC; a '
        + 'locale format is refused, because its meaning would depend on the machine '
        + 'that read it',
      );
    }
    return ms;
  }
}

/**
 * Drops `undefined` values so a parser can build a normalized record by writing
 * every field unconditionally. `null` is KEPT — for the ssl contract a null field
 * is a real value ("x509 said nothing"), distinct from "this dialect has no such
 * column at all".
 */
export function compact(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}
