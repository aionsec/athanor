import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadEvents } from '../../src/schema/events.js';
import type { TlsSslEvent } from '../../src/schema/events.js';
import {
  computeSniAnomalyScore,
  DEFAULT_TLS_ANOMALY_CONFIG,
} from '../../src/pipeline/score/tls-anomaly.js';

function writeTempJson(payload: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'hunt-events-load-'));
  const path = join(dir, 'events.json');
  writeFileSync(path, JSON.stringify(payload, null, 2), 'utf-8');
  return path;
}

describe('loadEvents runtime validation', () => {
  it('throws when root payload is not a JSON array', async () => {
    const path = writeTempJson({ hello: 'world' });
    await assert.rejects(
      loadEvents(path),
      /events file must contain a JSON array/,
    );
  });

  // Three claims about the normalized lane's admission rules, in one array: a valid record
  // with no `id` gets a synthesized one; a record of a KNOWN event type missing ONE required
  // field (here `sysmon/process_create` without `command_line`) is filtered out; and valid
  // id-bearing records keep their ids, in order.
  it('filters invalid records and synthesizes missing ids for valid events', async () => {
    const path = writeTempJson([
      {
        timestamp: '2026-04-10T12:00:00.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.0.0.5',
        dest_ip: '1.2.3.4',
        dest_port: 443,
        proto: 'tcp',
      },
      {
        id: 'bad-1',
        timestamp: '2026-04-10T12:01:00.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        event_id: 1,
        host: 'ws-01',
        process_name: 'x.exe',
        process_path: 'C:\\\\Temp\\\\x.exe',
        process_id: 1234,
        process_guid: '{AAA}',
        parent_process_name: 'explorer.exe',
        parent_process_path: 'C:\\\\Windows\\\\explorer.exe',
        parent_process_id: 900,
        parent_process_guid: '{BBB}',
        user: 'CORP\\\\alice',
        // command_line deliberately omitted — required by process_create
      },
      {
        id: 'nc-1',
        timestamp: '2026-04-10T12:02:00.000Z',
        source: 'sysmon',
        event_type: 'network_connect',
        event_id: 3,
        host: 'ws-01',
        src_ip: '10.0.0.5',
        src_port: 51000,
        dest_ip: '8.8.8.8',
        dest_port: 53,
        protocol: 'udp',
        process_name: 'svchost.exe',
        process_id: 1500,
        process_guid: '{CCC}',
        user: 'NT AUTHORITY\\\\SYSTEM',
      },
      {
        id: 'il-1',
        timestamp: '2026-04-10T12:03:00.000Z',
        source: 'sysmon',
        event_type: 'image_load',
        event_id: 7,
        host: 'ws-01',
        process_name: 'powershell.exe',
        image: 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
        process_id: 1600,
        process_guid: '{DDD}',
        image_loaded: 'C:\\\\Windows\\\\assembly\\\\System.Management.Automation.dll',
        signed: 'true',
        signature: 'Microsoft Windows',
        signature_status: 'Valid',
      },
    ]);

    const events = await loadEvents(path);
    assert.equal(events.length, 3);
    assert.match(events[0]!.id, /^evt-synth-\d{6}$/);
    assert.equal(events[1]!.id, 'nc-1');
    assert.equal(events[2]!.id, 'il-1');
  });
});

describe('loadEvents zeek-ssl ingest normalization', () => {
  // A raw beacon-path ssl record: zeek-ssl.ts writes the RAW zeek naming
  // (tls_server_name, tls_ja3, ...) but never the normalized keys the TLS scorer
  // reads (server_name, ja3_hash, ...). Ingest must fill the normalized aliases so
  // both ssl generators feed the scorer without per-generator dual-writes.
  const RAW_SSL_RECORD = {
    id: 'ssl-raw-1',
    timestamp: '2026-04-10T12:05:00.000Z',
    source: 'zeek',
    event_type: 'ssl',
    src_ip: '10.0.0.9',
    dest_ip: '203.0.113.44',
    dest_port: 443,
    tls_server_name: 'cdn.evil.example',
    tls_ja3: '72a589da586844d7f0818ce684948eea',
    tls_ja3s: 'b742b407517bac9536a77a7b0fee28e9',
    tls_subject: 'CN=evil',
    tls_issuer: 'CN=evil-ca',
    connection_to_ip: false,
  };

  it('fills the scorer-normalized keys from the raw zeek naming when absent', async () => {
    const path = writeTempJson([RAW_SSL_RECORD]);
    const events = await loadEvents(path);
    assert.equal(events.length, 1, 'the raw ssl record must pass ingest');
    const ssl = events[0] as unknown as Record<string, unknown>;
    assert.equal(ssl.server_name, 'cdn.evil.example', 'server_name must be filled from tls_server_name');
    assert.equal(ssl.ja3_hash, '72a589da586844d7f0818ce684948eea', 'ja3_hash must be filled from tls_ja3');
    assert.equal(ssl.ja3s_hash, 'b742b407517bac9536a77a7b0fee28e9', 'ja3s_hash must be filled from tls_ja3s');
    assert.equal(ssl.cert_subject, 'CN=evil', 'cert_subject must be filled from tls_subject');
    assert.equal(ssl.cert_issuer, 'CN=evil-ca', 'cert_issuer must be filled from tls_issuer');
  });

  it('yields a server_name the TLS scorer reads (no false sni_missing)', async () => {
    // Prove the fix "at the scorer": before normalization the scorer would hit the
    // !event.server_name branch (sni_missing_score); after ingest fills server_name
    // the same record is no longer scored as SNI-missing chaff.
    const path = writeTempJson([RAW_SSL_RECORD]);
    const events = await loadEvents(path);
    const ssl = events[0] as unknown as TlsSslEvent;
    assert.ok(ssl.server_name, 'scorer input must carry server_name after ingest');
    const sniScore = computeSniAnomalyScore(ssl, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.equal(sniScore, 0,
      `a resolved-SNI record must not score sni_missing; got ${sniScore}`);

    // Control: the same record WITHOUT server_name is scored sni_missing — this is
    // exactly the latent chaff the normalizer removes.
    const withoutSni = { ...ssl, server_name: undefined } as unknown as TlsSslEvent;
    assert.equal(
      computeSniAnomalyScore(withoutSni, DEFAULT_TLS_ANOMALY_CONFIG),
      DEFAULT_TLS_ANOMALY_CONFIG.sni_missing_score,
      'without server_name the scorer must fall back to sni_missing (control)',
    );
  });

  it('is fill-when-absent: never overwrites an explicit normalized value (backward-compat)', async () => {
    // The tls-anomaly generator dual-writes BOTH namings: server_name is present
    // (null for an omitted SNI) and tls_server_name is "". Fill-when-absent must
    // leave every committed fixture byte-identical — no null SNI promoted to a
    // value, no present hash overwritten.
    const dualWritten = {
      id: 'ssl-dual-1',
      timestamp: '2026-04-10T12:06:00.000Z',
      source: 'zeek',
      event_type: 'ssl',
      src_ip: '10.0.0.9',
      dest_ip: '203.0.113.44',
      dest_port: 443,
      server_name: null,
      tls_server_name: '',
      ja3_hash: 'aaaa1111bbbb2222cccc3333dddd4444',
      tls_ja3: 'ffffffffffffffffffffffffffffffff',
      cert_subject: 'CN=localhost',
      tls_subject: 'CN=other',
    };
    const path = writeTempJson([dualWritten]);
    const events = await loadEvents(path);
    const ssl = events[0] as unknown as Record<string, unknown>;
    assert.equal(ssl.server_name, null, 'an omitted SNI (server_name null) must stay null');
    assert.equal(ssl.ja3_hash, 'aaaa1111bbbb2222cccc3333dddd4444', 'an explicit ja3_hash must not be overwritten');
    assert.equal(ssl.cert_subject, 'CN=localhost', 'an explicit cert_subject must not be overwritten');
  });
});
