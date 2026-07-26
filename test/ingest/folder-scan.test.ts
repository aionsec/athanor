// Unit — the folder scan (`ingestFolder`). Filename patterns first, first-line
// sniffing as the fallback, and hard errors for everything it cannot account for:
// silently skipping a file is silently losing evidence.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  classifyByName,
  classifyByRecord,
  IngestError,
  ingestFolder,
} from '../../src/ingest/index.js';

const CONN_LINE = '{"ts":1773057630.000000,"uid":"CJye6Pr4c4225XZIQx","id.orig_h":"10.20.30.41",'
  + '"id.resp_h":"104.18.22.51","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.099833,'
  + '"orig_bytes":878,"resp_bytes":308,"conn_state":"SF","history":"ShADad","orig_pkts":26,'
  + '"resp_pkts":10}\n';

const SSL_LINE = '{"ts":1773057630.000000,"uid":"CfprOrvEHSEv02Og63","id.orig_h":"10.20.30.41",'
  + '"id.resp_h":"193.42.33.81","id.resp_p":443,"server_name":"","version":"TLSv12",'
  + '"cipher":"TLS_AES_256_GCM_SHA384","subject":"CN=localhost","issuer":"CN=localhost",'
  + '"ja3":"72a589da586844d7f0818ce684948eea","ja3s":"b742b407517bac9536a77a7b0fee28e9"}\n';

const EID3_LINE = '{"EventID":3,"UtcTime":"2026-03-09 12:00:30.000","Computer":"10.20.30.41",'
  + '"ProcessGuid":"{f994d776}","ProcessId":2008,"Image":"bastion-sensor.exe",'
  + '"User":"NT AUTHORITY\\\\SYSTEM","Protocol":"tcp","SourceIp":"10.20.30.41","SourcePort":61692,'
  + '"DestinationIp":"104.18.22.51","DestinationPort":443}\n';

function scratch(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'athanor-ingest-'));
  for (const [name, body] of Object.entries(files)) {
    writeFileSync(join(dir, name), body, 'utf-8');
  }
  return dir;
}

describe('ingest/index — classification', () => {
  it('recognizes the canonical dialect filenames', () => {
    assert.equal(classifyByName('conn.log'), 'zeek/conn');
    assert.equal(classifyByName('/estate/2026-03-09/conn.log'), 'zeek/conn');
    assert.equal(classifyByName('ssl.log'), 'zeek/ssl');
    assert.equal(classifyByName('sysmon-eid1.jsonl'), 'sysmon/process_create');
    assert.equal(classifyByName('sysmon-eid3.jsonl'), 'sysmon/network_connect');
    assert.equal(classifyByName('powershell-4104.jsonl'), 'powershell/script_block');
    assert.equal(classifyByName('events.json'), 'normalized-events');
    assert.equal(classifyByName('mystery.jsonl'), undefined);
  });

  it('does not read a sysmon network_connect file as a Zeek conn.log', () => {
    assert.equal(classifyByName('sysmon-network_connect.jsonl'), 'sysmon/network_connect');
  });

  it('sniffs an unnamed file by its first record', () => {
    assert.equal(classifyByRecord(JSON.parse(CONN_LINE)), 'zeek/conn');
    assert.equal(classifyByRecord(JSON.parse(SSL_LINE)), 'zeek/ssl');
    assert.equal(classifyByRecord(JSON.parse(EID3_LINE)), 'sysmon/network_connect');
    assert.equal(classifyByRecord({ EventID: 1 }), 'sysmon/process_create');
    assert.equal(classifyByRecord({ ScriptBlockText: 'x' }), 'powershell/script_block');
    assert.equal(classifyByRecord({ nothing: true }), undefined);
  });
});

describe('ingest/index — folder scan', () => {
  it('ingests a mixed folder and merges it into one canon-ordered stream', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE, 'sysmon-eid3.jsonl': EID3_LINE });
    const result = await ingestFolder(dir);

    assert.equal(result.normalized, false);
    assert.deepEqual(result.byDialect, { 'zeek/conn': 1, 'sysmon/network_connect': 1 });
    // Same millisecond: the rank rule puts conn before the endpoint view.
    assert.deepEqual(result.events.map((event) => [event.id, event.source, event.event_type]), [
      ['evt-00001', 'zeek', 'conn'],
      ['evt-00002', 'sysmon', 'network_connect'],
    ]);
    assert.equal(result.equalTimestampGroups, 1);
    assert.deepEqual(result.ambiguities, []);
  });

  it('classifies by content when the filename says nothing', async () => {
    const dir = scratch({ 'telemetry-a.jsonl': SSL_LINE });
    const result = await ingestFolder(dir);

    assert.deepEqual(result.files, [{
      file: 'telemetry-a.jsonl',
      classifiedAs: 'zeek/ssl',
      classifiedBy: 'content',
      events: 1,
    }]);
  });

  it('skips dotfiles silently but REPORTS every subdirectory it passed over', async () => {
    // A folder of logs holding a `zeek/` subdirectory of more logs used to ingest the
    // top level, exit 0 and say nothing: partial telemetry with a green light. Skipping
    // is allowed to be legitimate; it is not allowed to be quiet. A dotfile is the one
    // exception — `.DS_Store` is not evidence.
    const dir = scratch({ 'conn.log': CONN_LINE, '.DS_Store': 'junk' });
    mkdirSync(join(dir, 'archive'));
    const result = await ingestFolder(dir);

    assert.equal(result.events.length, 1);
    assert.deepEqual(result.skipped, [{ name: 'archive', reason: 'subdirectory' }]);
  });

  it('follows a symlinked log instead of calling the folder empty', async () => {
    // `dirent.isFile()` is false for a symlink, so an estate that presents its logs as
    // links into an archive used to report "no files to ingest".
    const source = scratch({ 'conn.log': CONN_LINE });
    const dir = scratch({});
    symlinkSync(join(source, 'conn.log'), join(dir, 'conn.log'));

    const result = await ingestFolder(dir);
    assert.equal(result.events.length, 1);
    assert.deepEqual(result.skipped, []);
  });

  it('reports a broken symlink and a symlinked directory rather than dropping them', async () => {
    const source = scratch({ 'conn.log': CONN_LINE });
    const dir = scratch({ 'conn.log': CONN_LINE });
    symlinkSync(join(source, 'gone.log'), join(dir, 'dangling.log'));
    symlinkSync(source, join(dir, 'archive'));

    const result = await ingestFolder(dir);
    assert.equal(result.events.length, 1);
    assert.deepEqual(result.skipped, [
      { name: 'archive', reason: 'symlink to a directory' },
      { name: 'dangling.log', reason: 'broken symlink' },
    ]);
  });

  it('names what it passed over when that leaves nothing to ingest', async () => {
    const dir = scratch({});
    mkdirSync(join(dir, 'zeek'));
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /no files to ingest in .*\(skipped 1 entry: zeek \(subdirectory\)\)/
          .test((error as Error).message),
    );
  });

  it('accepts an already-normalized events.json folder via loadEvents', async () => {
    const dir = scratch({
      'events.json': JSON.stringify([{
        id: 'evt-00001',
        timestamp: '2026-03-09T12:00:30.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.20.30.41',
        dest_ip: '104.18.22.51',
        dest_port: 443,
        proto: 'tcp',
      }]),
    });
    const result = await ingestFolder(dir);

    assert.equal(result.normalized, true);
    assert.equal(result.events.length, 1);
    assert.equal(result.events[0]!.id, 'evt-00001', 'a normalized file keeps the ids it carries');
  });

  it('counts the records loadEvents refused instead of losing them in silence', async () => {
    // The two lanes have deliberately different postures, and this is the one that could
    // go wrong quietly: a raw lane hard-errors on ONE malformed line, while this lane can
    // discard any number of records and still exit 0. The loader keeps its admission
    // rules; the ACCOUNTING happens at the lane, so nothing is dropped in silence.
    const valid = (id: string) => ({
      id,
      timestamp: '2026-03-09T12:00:30.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.20.30.41',
      dest_ip: '104.18.22.51',
      dest_port: 443,
      proto: 'tcp',
    });
    const { dest_ip: _dropped, ...incomplete } = valid('evt-00003');
    const dir = scratch({
      'events.json': JSON.stringify([valid('evt-00001'), 'not a record', incomplete, valid('evt-00004')]),
    });

    const result = await ingestFolder(dir);

    assert.equal(result.normalized, true);
    assert.equal(result.events.length, 2);
    assert.deepEqual(result.droppedRecordIndices, [1, 2], 'both refusals are located by index');
  });

  it('locates refused records that carry no id, too', async () => {
    const dir = scratch({
      'events.json': JSON.stringify([
        { timestamp: '2026-03-09T12:00:30.000Z', source: 'zeek', event_type: 'conn' },
        {
          timestamp: '2026-03-09T12:00:31.000Z',
          source: 'zeek',
          event_type: 'conn',
          src_ip: '10.20.30.41',
          dest_ip: '104.18.22.51',
          dest_port: 443,
          proto: 'tcp',
        },
      ]),
    });

    const result = await ingestFolder(dir);
    assert.equal(result.events.length, 1);
    assert.equal(result.events[0]!.id, 'evt-synth-000002', 'the survivor keeps its synthetic id');
    assert.deepEqual(result.droppedRecordIndices, [0]);
  });

  it('reports no dropped records for a clean file or a raw lane', async () => {
    const raw = await ingestFolder(scratch({ 'conn.log': CONN_LINE }));
    assert.deepEqual(raw.droppedRecordIndices, []);
    assert.deepEqual(raw.skipped, []);
  });

  it('passes over a default-named config file instead of refusing the run', async () => {
    // A config sitting in the telemetry folder used to abort the whole ingest as an
    // unclassifiable file. Configuration is not evidence: skipping it loses nothing,
    // and the skip is reported like every other thing the scan passed over.
    const dir = scratch({ 'conn.log': CONN_LINE, 'athanor.yaml': 'emit_floors:\n  beacon: 0.2\n' });

    const result = await ingestFolder(dir);

    assert.equal(result.events.length, 1);
    assert.deepEqual(result.skipped, [{ name: 'athanor.yaml', reason: 'config file' }]);
  });

  it('passes over the file --config named, whatever it is called', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE, 'scenario.yaml': 'emit_floors:\n  beacon: 0.2\n' });

    const result = await ingestFolder(dir, { configPath: join(dir, 'scenario.yaml') });

    assert.equal(result.events.length, 1);
    assert.deepEqual(result.skipped, [{ name: 'scenario.yaml', reason: 'config file' }]);
  });

  it('still refuses a yaml that is neither the default name nor the named config', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE, 'scenario.yaml': 'emit_floors:\n  beacon: 0.2\n' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /a config file is not telemetry/.test((error as Error).message)
        && /--config/.test((error as Error).message),
    );
  });

  it('names the config file when passing over it leaves nothing to ingest', async () => {
    const dir = scratch({ 'athanor.yml': 'emit_floors:\n  beacon: 0.2\n' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /no files to ingest in .*\(skipped 1 entry: athanor\.yml \(config file\)\)/
          .test((error as Error).message),
    );
  });

  it('refuses to mix a normalized events file with raw dialect files', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE, 'events.json': '[]' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /mixes a normalized events file .* with raw dialect files/.test((error as Error).message),
    );
  });

  it('refuses an unrecognized file instead of skipping it', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE, 'notes.txt': 'hello\n' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /unrecognized telemetry file: .*notes\.txt/.test((error as Error).message),
    );
  });

  it('refuses an empty folder', async () => {
    const dir = scratch({});
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError && /no files to ingest in/.test((error as Error).message),
    );
  });

  it('refuses a folder of empty telemetry files', async () => {
    const dir = scratch({ 'conn.log': '', 'ssl.log': '\n' });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /no telemetry records found in/.test((error as Error).message),
    );
  });

  it('reports the offending file and line for a malformed record', async () => {
    const dir = scratch({ 'conn.log': `${CONN_LINE}{"ts":not-json}\n` });
    await assert.rejects(
      ingestFolder(dir),
      (error: unknown) => error instanceof IngestError
        && /conn\.log:2: malformed JSON line/.test((error as Error).message),
    );
  });

  it('refuses a path that is not a directory', async () => {
    const dir = scratch({ 'conn.log': CONN_LINE });
    await assert.rejects(
      ingestFolder(join(dir, 'conn.log')),
      (error: unknown) => error instanceof IngestError && /not a directory/.test((error as Error).message),
    );
  });
});
