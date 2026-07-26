// The ingest primitives, at the point where honesty is cheapest to lose: what athanor
// will accept as a timestamp, and what it refuses to keep pretending is JSON.
//
// Both are honesty properties rather than feature tests. A timestamp codec that reads
// a zone-less stamp in the machine's local zone makes `TZ` an input to the event
// stream — the same folder distills differently on a laptop and on CI — so the
// timezone case is proven by running the SAME folder under two zones in child
// processes, not by asserting an offset in-process. And a body athanor cannot read
// (Zeek's TSV default, a zstd archive, a UTF-16 export) must be named for what it is:
// "malformed JSON line (Unexpected token '#')" blames JSON syntax for a situation
// that has nothing to do with JSON syntax. gzip is the one that turned out to be
// readable rather than merely nameable — Zeek rotates into it — so it is proven here
// as an equivalence: the gzipped canon folder distills to the same events.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { repoRoot } from '../../src/lib/paths.js';
import {
  decodeTelemetryBytes,
  describeUnreadableText,
  fromIsoTimestamp,
  IngestError,
  parseJsonLines,
  stripBom,
} from '../../src/ingest/codecs.js';
import { ingestFolder } from '../../src/ingest/index.js';

const CONN_LINE = '{"ts":1773057630.000000,"uid":"CJye6Pr4c4225XZIQx","id.orig_h":"10.20.30.41",'
  + '"id.resp_h":"104.18.22.51","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.099833,'
  + '"orig_bytes":878,"resp_bytes":308,"conn_state":"SF","history":"ShADad","orig_pkts":26,'
  + '"resp_pkts":10}\n';

/** A 4104 record whose `TimeCreated` carries no zone — the shape real exports ship. */
function scriptBlockLine(timeCreated: string): string {
  return `${JSON.stringify({
    TimeCreated: timeCreated,
    Computer: 'DEVBOX-07',
    ScriptBlockId: '6e3b798a-5db3-9fc2-0bc2-09758dc05565',
    ScriptBlockText: 'Write-Output 1',
    MessageNumber: 1,
    MessageTotal: 1,
  })}\n`;
}

function scratch(files: Record<string, string | Uint8Array>): string {
  const dir = mkdtempSync(join(tmpdir(), 'athanor-codecs-'));
  for (const [name, body] of Object.entries(files)) {
    writeFileSync(join(dir, name), body);
  }
  return dir;
}

describe('codecs — fromIsoTimestamp is timezone-proof', () => {
  it('reads a zone-less stamp as UTC, the way the emitter wrote it', () => {
    assert.equal(
      fromIsoTimestamp('2026-03-09T14:00:15.600'),
      Date.parse('2026-03-09T14:00:15.600Z'),
    );
    assert.equal(
      fromIsoTimestamp('2026-03-09 14:00:15'),
      Date.parse('2026-03-09T14:00:15.000Z'),
      'a space separator is the same instant as a T',
    );
    assert.equal(fromIsoTimestamp('2026-03-09'), Date.parse('2026-03-09T00:00:00.000Z'));
  });

  it('honours an explicit offset, in both the spec and the compact form', () => {
    const utc = Date.parse('2026-03-09T14:00:15.600Z');
    assert.equal(fromIsoTimestamp('2026-03-09T14:00:15.600Z'), utc);
    assert.equal(fromIsoTimestamp('2026-03-09T16:00:15.600+02:00'), utc);
    assert.equal(fromIsoTimestamp('2026-03-09T16:00:15.600+0200'), utc);
    assert.equal(fromIsoTimestamp('2026-03-09T09:00:15.600-05:00'), utc);
  });

  it('truncates sub-millisecond precision rather than rejecting it', () => {
    // Windows writes seven fractional digits; the contract resolves to milliseconds.
    assert.equal(
      fromIsoTimestamp('2026-03-09T14:00:15.6009999Z'),
      Date.parse('2026-03-09T14:00:15.600Z'),
    );
  });

  it('refuses anything that is not ISO 8601 instead of guessing', () => {
    // The probe from the review: a locale-format 4104 export.
    assert.ok(Number.isNaN(fromIsoTimestamp('7/25/2026 5:04:47 PM')));
    assert.ok(Number.isNaN(fromIsoTimestamp('Mon, 09 Mar 2026 14:00:15 GMT')));
    assert.ok(Number.isNaN(fromIsoTimestamp('2026-03-09T14:00:15.600+02')));
    assert.ok(Number.isNaN(fromIsoTimestamp('')));
    assert.ok(Number.isNaN(fromIsoTimestamp('2026-13-45T14:00:15Z')), 'a real calendar, too');
  });

  it('makes the 4104 lane fail loudly on a locale stamp, naming what it wanted', async () => {
    const dir = scratch({ 'powershell-4104.jsonl': scriptBlockLine('7/25/2026 5:04:47 PM') });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /unparseable ISO timestamp "TimeCreated"/.test((error as Error).message)
        && /no zone is read as UTC/.test((error as Error).message),
    );
  });
});

describe('codecs — the machine timezone is not an input', () => {
  // In-process assertions cannot prove this: `TZ` is read when the process starts.
  // So the same folder is ingested in two child processes under two zones twelve
  // hours apart, and the normalized timestamps must be identical.
  const INGEST_MODULE = import.meta.resolve('../../src/ingest/index.ts');
  const TSX_LOADER = import.meta.resolve('tsx');
  const PROBE = `import(${JSON.stringify(INGEST_MODULE)})`
    + '.then((m) => m.ingestFolder(process.argv[1]))'
    + '.then((r) => process.stdout.write(r.events.map((e) => e.timestamp).join(",")))';

  function ingestUnderTz(dir: string, tz: string): string {
    const result = spawnSync(
      process.execPath,
      ['--import', TSX_LOADER, '-e', PROBE, dir],
      { encoding: 'utf-8', env: { ...process.env, TZ: tz } },
    );
    if (result.error) throw result.error;
    assert.equal(result.status, 0, `probe under TZ=${tz} failed:\n${result.stderr}`);
    return result.stdout;
  }

  it('ingests a zone-less 4104 stamp to the same instant under TZ=UTC and TZ=Pacific/Kiritimati', () => {
    const dir = scratch({ 'powershell-4104.jsonl': scriptBlockLine('2026-03-09T14:00:15.600') });

    const utc = ingestUnderTz(dir, 'UTC');
    const kiritimati = ingestUnderTz(dir, 'Pacific/Kiritimati'); // UTC+14
    const honolulu = ingestUnderTz(dir, 'Pacific/Honolulu'); // UTC-10

    assert.equal(utc, '2026-03-09T14:00:15.600Z');
    assert.equal(kiritimati, utc, 'the reader\'s timezone must not move the event');
    assert.equal(honolulu, utc, 'the reader\'s timezone must not move the event');
  });
});

describe('codecs — a body athanor cannot read is named, not blamed on JSON', () => {
  it('recognizes a stock (TSV) Zeek log by its banner and points at JSON logging', () => {
    const tsv = '#separator \\x09\n#set_separator\t,\n#path\tconn\n'
      + '#fields\tts\tuid\tid.orig_h\n1773057630.000000\tCJye6Pr4c4225XZIQx\t10.20.30.41\n';

    const message = describeUnreadableText(tsv, '/estate/conn.log');
    assert.ok(message, 'a #separator banner must be recognized');
    assert.match(message, /TAB-SEPARATED Zeek log/);
    assert.match(message, /LogAscii::use_json=T/, 'the message names the fix');
    assert.match(message, /json-streaming-logs/);

    assert.throws(
      () => parseJsonLines(tsv, '/estate/conn.log'),
      (error: unknown) => error instanceof IngestError
        && /TAB-SEPARATED Zeek log/.test((error as Error).message)
        && !/malformed JSON/.test((error as Error).message),
    );
  });

  it('recognizes a banner-less TSV body by its tabs', () => {
    const message = describeUnreadableText(
      '1773057630.000000\tCJye6Pr4c4225XZIQx\t10.20.30.41\n',
      'conn.log',
    );
    assert.match(String(message), /TAB-SEPARATED Zeek log/);
  });

  it('leaves a JSON line alone, tabs inside a string and all', () => {
    assert.equal(describeUnreadableText(CONN_LINE, 'conn.log'), undefined);
    assert.equal(
      describeUnreadableText('{"ScriptBlockText":"a\\tb"}\n', 'ps.jsonl'),
      undefined,
      'a tab inside a JSON string is data, not a separator',
    );
    assert.equal(describeUnreadableText('[]\n', 'events.json'), undefined);
    assert.equal(describeUnreadableText('\n\n', 'empty.log'), undefined);
  });

  it('decompresses a gzip\'d log instead of refusing it', () => {
    // Zeek's own rotation writes `.gz`; the magic bytes decide, not the extension.
    assert.equal(decodeTelemetryBytes(gzipSync(Buffer.from(CONN_LINE, 'utf-8')), 'conn.log.gz'), CONN_LINE);
    assert.equal(
      decodeTelemetryBytes(gzipSync(Buffer.from(CONN_LINE, 'utf-8')), 'conn.log'),
      CONN_LINE,
      'a mislabeled file is read for what it is',
    );
    assert.equal(
      decodeTelemetryBytes(gzipSync(Buffer.from(`﻿${CONN_LINE}`, 'utf-8')), 'conn.log.gz'),
      CONN_LINE,
      'the BOM inside the gzip is stripped like any other',
    );
  });

  it('names a truncated gzip rather than blaming JSON for the mojibake', () => {
    const truncated = gzipSync(Buffer.from(CONN_LINE, 'utf-8')).subarray(0, 12);
    assert.throws(
      () => decodeTelemetryBytes(truncated, 'conn.log.gz'),
      (error: unknown) => error instanceof IngestError
        && /did not decompress/.test((error as Error).message)
        && /truncated or corrupt/.test((error as Error).message),
    );
  });

  it('refuses the compressed formats it does NOT open, naming each one', () => {
    const cases: ReadonlyArray<[string, number[], RegExp]> = [
      ['logs.zst', [0x28, 0xb5, 0x2f, 0xfd], /this is a zstd file/],
      ['logs.xz', [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], /this is a xz file/],
      ['logs.bz2', [0x42, 0x5a, 0x68, 0x39], /this is a bzip2 file/],
      ['logs.zip', [0x50, 0x4b, 0x03, 0x04], /this is a zip file/],
    ];
    for (const [name, magic, expected] of cases) {
      assert.throws(
        () => decodeTelemetryBytes(Uint8Array.from([...magic, 0, 0, 0, 0]), name),
        (error: unknown) => error instanceof IngestError
          && expected.test((error as Error).message)
          && /athanor decompresses gzip and nothing else/.test((error as Error).message),
        `${name} must be named for what it is`,
      );
    }
  });

  it('recognizes a tar (and a tar inside a gzip) and says to unpack it', () => {
    const tar = Buffer.alloc(512);
    tar.write('conn.log', 0);
    tar.write('ustar', 257);
    assert.throws(
      () => decodeTelemetryBytes(tar, 'logs.tar'),
      (error: unknown) => error instanceof IngestError
        && /this is a tar archive;/.test((error as Error).message),
    );
    assert.throws(
      () => decodeTelemetryBytes(gzipSync(tar), 'logs.tar.gz'),
      (error: unknown) => error instanceof IngestError
        && /tar archive \(inside the gzip\)/.test((error as Error).message)
        && /tar xf/.test((error as Error).message),
    );
  });

  it('refuses a UTF-16 export by its byte-order mark', () => {
    const utf16 = Buffer.from(`\uFEFF${CONN_LINE}`, 'utf16le');
    assert.throws(
      () => decodeTelemetryBytes(utf16, 'conn.log'),
      (error: unknown) => error instanceof IngestError
        && /UTF-16 \(byte-order mark\), not UTF-8/.test((error as Error).message),
    );
  });

  it('strips a UTF-8 BOM instead of dying on it', () => {
    assert.equal(stripBom('\uFEFF{}'), '{}');
    assert.equal(stripBom('{}'), '{}');

    const bomd = decodeTelemetryBytes(Buffer.from(`\uFEFF${CONN_LINE}`, 'utf-8'), 'conn.log');
    assert.equal(bomd, CONN_LINE);

    const records = parseJsonLines(`\uFEFF${CONN_LINE}`, 'conn.log');
    assert.equal(records.length, 1);
    assert.equal(records[0]!.record.uid, 'CJye6Pr4c4225XZIQx');
  });
});

describe('codecs — the folder scan applies all of it', () => {
  it('ingests a gzip\'d log, by name and by magic bytes alike', async () => {
    const named = await ingestFolder(scratch({
      'conn.log.gz': gzipSync(Buffer.from(CONN_LINE, 'utf-8')),
    }));
    assert.equal(named.events.length, 1);
    assert.deepEqual(named.files, [{
      file: 'conn.log.gz',
      classifiedAs: 'zeek/conn',
      classifiedBy: 'filename',
      events: 1,
    }], 'the trailing .gz is stripped before the filename rules run');

    // A rotated file whose name says nothing: the sniffer sees decompressed text.
    const sniffed = await ingestFolder(scratch({
      'telemetry-a.jsonl.gz': gzipSync(Buffer.from(CONN_LINE, 'utf-8')),
    }));
    assert.equal(sniffed.files[0]!.classifiedBy, 'content');
    assert.equal(sniffed.files[0]!.classifiedAs, 'zeek/conn');
  });

  it('refuses a compressed format it does not open, from inside the folder', async () => {
    const dir = scratch({ 'conn.log.zst': Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]) });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /conn\.log\.zst: this is a zstd file/.test((error as Error).message),
    );
  });

  it('refuses a TSV conn.log before classification can call it merely unrecognized', async () => {
    const dir = scratch({ 'telemetry.log': '#separator \\x09\n#fields\tts\tuid\n' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /TAB-SEPARATED Zeek log/.test((error as Error).message)
        && !/unrecognized telemetry file/.test((error as Error).message),
    );
  });

  it('ingests a BOM\'d Windows export', async () => {
    const dir = scratch({ 'conn.log': Buffer.from(`\uFEFF${CONN_LINE}`, 'utf-8') });
    const result = await ingestFolder(dir);
    assert.equal(result.events.length, 1);
  });
});

describe('codecs — gzip is transparent for every dialect', () => {
  // The strongest form of the claim: a folder of GZIPPED canon fixtures must produce
  // exactly the event stream the plain folder produces. Not "it parses" — identical,
  // field for field, id for id, in both the raw-dialect and the normalized lanes.
  const ROOT = repoRoot();

  /** Copies a fixture folder into a scratch dir with every file gzipped and `.gz`-suffixed. */
  function gzipFolder(source: string): string {
    const dir = mkdtempSync(join(tmpdir(), 'athanor-gz-'));
    for (const name of readdirSync(source)) {
      writeFileSync(join(dir, `${name}.gz`), gzipSync(readFileSync(join(source, name))));
    }
    return dir;
  }

  it('reproduces the canon raw folder from its gzipped copy', async () => {
    const plain = await ingestFolder(join(ROOT, 'fixtures', 'raw'));
    const gzipped = await ingestFolder(gzipFolder(join(ROOT, 'fixtures', 'raw')));

    assert.equal(gzipped.events.length, plain.events.length);
    assert.deepEqual(gzipped.byDialect, plain.byDialect, 'all four raw dialects survived');
    assert.deepEqual(gzipped.events, plain.events, 'gzip changes nothing about the stream');
    assert.deepEqual(
      gzipped.files.map((file) => [file.file, file.classifiedAs, file.events]),
      plain.files.map((file) => [`${file.file}.gz`, file.classifiedAs, file.events]),
      'each .gz classifies as the dialect its uncompressed name would',
    );
  });

  it('reproduces the 4104 lane from its gzipped copy', async () => {
    const plain = await ingestFolder(join(ROOT, 'fixtures', 'raw-aux'));
    const gzipped = await ingestFolder(gzipFolder(join(ROOT, 'fixtures', 'raw-aux')));
    assert.deepEqual(gzipped.events, plain.events);
  });

  it('reads a gzipped normalized events.json through the same admission rules', async () => {
    // The normalized lane reads the DECODED text rather than re-reading the file, so
    // `events.json.gz` is admitted (and its refusals counted) like the plain file.
    const source = mkdtempSync(join(tmpdir(), 'athanor-gz-src-'));
    const valid = {
      id: 'evt-00001',
      timestamp: '2026-03-09T12:00:30.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.20.30.41',
      dest_ip: '104.18.22.51',
      dest_port: 443,
      proto: 'tcp',
    };
    const { dest_ip: _dropped, ...incomplete } = valid;
    writeFileSync(join(source, 'events.json'), JSON.stringify([valid, incomplete]));

    const plain = await ingestFolder(source);
    const gzipped = await ingestFolder(gzipFolder(source));

    assert.equal(gzipped.normalized, true);
    assert.deepEqual(gzipped.events, plain.events);
    assert.deepEqual(gzipped.droppedRecordIndices, [1], 'the refusal is still counted');
  });
});
