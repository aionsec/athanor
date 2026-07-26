// Unit — Sysmon EID 1 / EID 3 JSONL parser. The first fixture of each pair is a REAL
// emitted line copied from fixtures/raw/; the rest cover the derivations (basename,
// the `-` unset token, the ECS `host.ip` shipper field) and the loud failures.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IngestError, parseJsonLines } from '../../src/ingest/codecs.js';
import {
  parseSysmonEid1Record,
  parseSysmonEid3Record,
  parseSysmonRecord,
} from '../../src/ingest/sysmon-jsonl.js';

const EID1_LINE = '{"EventID":1,"UtcTime":"2026-03-09 12:00:13.150","Computer":"10.20.30.41",'
  + '"host.ip":"10.20.30.41","ProcessGuid":"{5a7b2c4b-8847-4032-b0e5-ff2b41de93d9}",'
  + '"ProcessId":56772,"Image":"C:\\\\Windows\\\\System32\\\\services.exe","Description":"-",'
  + '"Product":"-","Company":"-","OriginalFileName":"services.exe",'
  + '"CommandLine":"\\"C:\\\\Windows\\\\System32\\\\services.exe\\"",'
  + '"CurrentDirectory":"C:\\\\Users\\\\SYSTEM\\\\","User":"NT AUTHORITY\\\\SYSTEM",'
  + '"IntegrityLevel":"System","Hashes":"MD5=9FB70829D5910B4ABEBECD4C9947F00F",'
  + '"ParentProcessGuid":"{00000000-0000-0000-0000-000000000000}","ParentProcessId":4,'
  + '"ParentImage":"C:\\\\Windows\\\\explorer.exe"}';

const EID3_LINE = '{"EventID":3,"UtcTime":"2026-03-09 12:00:30.001","Computer":"10.20.30.41",'
  + '"ProcessGuid":"{f994d776-f83a-288b-31ae-c16e2d3e9c81}","ProcessId":2008,'
  + '"Image":"bastion-sensor.exe","User":"NT AUTHORITY\\\\SYSTEM","Protocol":"tcp",'
  + '"SourceIp":"10.20.30.41","SourcePort":61692,"DestinationIp":"104.18.22.51",'
  + '"DestinationPort":443}';

function record(line: string, file = 'sysmon.jsonl') {
  return parseJsonLines(line, file)[0]!;
}

describe('ingest/sysmon-jsonl — EID 1 process_create', () => {
  it('maps a real emitted line to the exact normalized record', () => {
    const parsed = parseSysmonEid1Record(record(EID1_LINE, 'sysmon-eid1.jsonl'));

    assert.equal(parsed.dialect, 'sysmon/process_create');
    assert.equal(parsed.timestampMs, Date.parse('2026-03-09T12:00:13.150Z'));
    assert.deepEqual(parsed.event, {
      timestamp: '2026-03-09T12:00:13.150Z',
      source: 'sysmon',
      event_type: 'process_create',
      event_id: 1,
      host: '10.20.30.41',
      // ECS shipper metadata, not a Sysmon-native column.
      src_ip: '10.20.30.41',
      process_guid: '{5a7b2c4b-8847-4032-b0e5-ff2b41de93d9}',
      process_id: 56772,
      process_path: 'C:\\Windows\\System32\\services.exe',
      process_name: 'services.exe',
      description: null,
      product: null,
      company: null,
      original_file_name: 'services.exe',
      command_line: '"C:\\Windows\\System32\\services.exe"',
      current_directory: 'C:\\Users\\SYSTEM\\',
      user: 'NT AUTHORITY\\SYSTEM',
      integrity_level: 'System',
      // Sysmon's comma-joined wire string, verbatim — re-splitting it invents a shape.
      hashes: 'MD5=9FB70829D5910B4ABEBECD4C9947F00F',
      parent_process_guid: '{00000000-0000-0000-0000-000000000000}',
      parent_process_id: 4,
      parent_process_path: 'C:\\Windows\\explorer.exe',
      parent_process_name: 'explorer.exe',
      domain: 'traditional',
    });
  });

  it('derives both process names by Windows basename, not by node:path', () => {
    const parsed = parseSysmonEid1Record(record(EID1_LINE));
    assert.equal(parsed.event.process_name, 'services.exe');
    assert.equal(parsed.event.parent_process_name, 'explorer.exe');
  });

  it('omits src_ip when the shipper added no host.ip (a NetBIOS-only estate)', () => {
    const line = EID1_LINE.replace('"host.ip":"10.20.30.41",', '');
    const parsed = parseSysmonEid1Record(record(line));
    assert.equal('src_ip' in parsed.event, false);
  });

  it('reads an unset Hashes ("-") as absent, not as the literal string', () => {
    // The emitter never writes `-` there, so the canon says nothing about it — but a
    // real estate does, and a literal "-" would enter the LFA hash table as an entity
    // shared by every hash-less process on every host.
    const line = EID1_LINE.replace('"Hashes":"MD5=9FB70829D5910B4ABEBECD4C9947F00F"', '"Hashes":"-"');
    const parsed = parseSysmonEid1Record(record(line));
    assert.equal('hashes' in parsed.event, false);
  });

  it('rejects a record whose EventID is not 1', () => {
    assert.throws(
      () => parseSysmonEid1Record(record(EID3_LINE)),
      (error: unknown) => error instanceof IngestError
        && /expected Sysmon EventID 1, got 3/.test((error as Error).message),
    );
  });

  it('refuses a record missing a required column', () => {
    const line = EID1_LINE.replace('"CommandLine":"\\"C:\\\\Windows\\\\System32\\\\services.exe\\"",', '');
    assert.throws(
      () => parseSysmonEid1Record(record(line, 'sysmon-eid1.jsonl')),
      (error: unknown) => error instanceof IngestError
        && /sysmon-eid1\.jsonl:1: expected non-empty string field "CommandLine"/.test((error as Error).message),
    );
  });
});

describe('ingest/sysmon-jsonl — EID 3 network_connect', () => {
  it('maps a real emitted line to the exact normalized record', () => {
    const parsed = parseSysmonEid3Record(record(EID3_LINE, 'sysmon-eid3.jsonl'));

    assert.equal(parsed.dialect, 'sysmon/network_connect');
    assert.equal(parsed.timestampMs, Date.parse('2026-03-09T12:00:30.001Z'));
    assert.deepEqual(parsed.event, {
      timestamp: '2026-03-09T12:00:30.001Z',
      source: 'sysmon',
      event_type: 'network_connect',
      event_id: 3,
      host: '10.20.30.41',
      process_guid: '{f994d776-f83a-288b-31ae-c16e2d3e9c81}',
      process_id: 2008,
      process_name: 'bastion-sensor.exe',
      user: 'NT AUTHORITY\\SYSTEM',
      protocol: 'tcp',
      src_ip: '10.20.30.41',
      src_port: 61692,
      dest_ip: '104.18.22.51',
      dest_port: 443,
      domain: 'traditional',
    });
  });

  it('emits NO process_path — the normalized EID 3 contract has no such field', () => {
    const fullPath = EID3_LINE.replace(
      '"Image":"bastion-sensor.exe"',
      '"Image":"C:\\\\Windows\\\\System32\\\\bastion-sensor.exe"',
    );
    const parsed = parseSysmonEid3Record(record(fullPath));
    assert.equal('process_path' in parsed.event, false);
    assert.equal(parsed.event.process_name, 'bastion-sensor.exe', 'Image is still basenamed');
  });
});

describe('ingest/sysmon-jsonl — mixed-stream dispatch', () => {
  it('routes each line on its own EventID (real estates ship one mixed file)', () => {
    const records = parseJsonLines(`${EID1_LINE}\n${EID3_LINE}\n`, 'sysmon.jsonl');
    const parsed = records.map(parseSysmonRecord);
    assert.deepEqual(parsed.map((item) => item.dialect), [
      'sysmon/process_create',
      'sysmon/network_connect',
    ]);
  });

  it('refuses an EventID athanor does not ingest instead of dropping the line', () => {
    assert.throws(
      () => parseSysmonRecord(record('{"EventID":7,"UtcTime":"2026-03-09 12:00:13.150"}')),
      (error: unknown) => error instanceof IngestError
        && /unsupported Sysmon EventID 7/.test((error as Error).message),
    );
  });

  it('reports file:line on an unparseable UtcTime', () => {
    const line = EID3_LINE.replace('2026-03-09 12:00:30.001', '09/03/2026 12:00:30');
    assert.throws(
      () => parseSysmonRecord(record(line, 'sysmon-eid3.jsonl')),
      (error: unknown) => error instanceof IngestError
        && /sysmon-eid3\.jsonl:1: unparseable Sysmon "UtcTime"/.test((error as Error).message),
    );
  });
});
