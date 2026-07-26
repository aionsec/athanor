import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runTlsAnomalyDistillation } from '../../../src/run/runners/tls-anomaly-distillation.js';
import { loadEvents } from '../../../src/schema/events.js';

function buildTlsEvent(idx: number): Record<string, unknown> {
  const base = Date.parse('2026-04-11T00:00:00.000Z');
  const timestamp = new Date(base + idx * 60 * 1000).toISOString();
  return {
    id: `evt-tls-${String(idx + 1).padStart(3, '0')}`,
    timestamp,
    source: 'zeek',
    event_type: 'ssl',
    src_ip: '10.10.10.42',
    dest_ip: '203.0.113.50',
    dest_port: 443,
    server_name: idx % 3 === 0 ? null : 'cdn.evil-example.com',
    tls_version: 'TLSv13',
    cipher: 'TLS_AES_128_GCM_SHA256',
    ja3_hash: '72a589da586844d7f0818ce684948eea',
    ja4_hash: null,
    ja3s_hash: null,
    ja4x_hash: null,
    sni_matches_cert: idx % 3 === 0 ? null : true,
    cert_subject: 'CN=cdn.evil-example.com',
    cert_issuer: 'CN=Self-Signed',
    cert_serial: '01',
    cert_not_before: '2026-04-01T00:00:00.000Z',
    cert_not_after: '2026-05-01T00:00:00.000Z',
    cert_self_signed: true,
    cert_expired: false,
    cert_validity_days: 30,
    cert_key_type: 'RSA',
    cert_key_length: 2048,
    cert_san_dns: ['cdn.evil-example.com'],
    cert_chain_length: 1,
    connection_to_ip: false,
  };
}

describe('runTlsAnomalyDistillation smoke', () => {
  it('emits TLS Anomaly candidates with Stage 4 enrichment populated', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'tls-anomaly-distillation-'));
    const eventsPath = join(dir, 'events.json');

    const tlsEvents = Array.from({ length: 12 }, (_, idx) => buildTlsEvent(idx));
    await writeFile(eventsPath, JSON.stringify(tlsEvents, null, 2));

    const out = runTlsAnomalyDistillation(await loadEvents(eventsPath));

    assert.ok(out.length >= 1);
    assert.equal(out[0].type, 'tls_anomaly');
    assert.equal(typeof out[0].enrichment.threat_intel_match, 'boolean');
    assert.equal(typeof out[0].enrichment.first_seen, 'string');
    assert.equal(typeof out[0].enrichment.business_hours_proportion, 'number');
    assert.equal(typeof out[0].enrichment.lots_match, 'boolean');
    assert.equal(typeof out[0].enrichment.missing_sni, 'boolean');
  });
});
