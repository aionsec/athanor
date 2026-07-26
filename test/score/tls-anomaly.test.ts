import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreTlsAnomalyCandidates,
  computeCertAnomalyScore,
  computeFingerprintAnomalyScore,
  computeSniAnomalyScore,
  resetCandidateCounter,
  DEFAULT_TLS_ANOMALY_CONFIG,
} from '../../src/pipeline/score/tls-anomaly.js';
import type { TlsSslEvent } from '../../src/schema/events.js';
import type { TlsAnomalyConfig } from '../../src/pipeline/score/tls-anomaly.js';

let tlsEventCounter = 0;

function makeTlsEvent(overrides: Partial<TlsSslEvent> = {}): TlsSslEvent {
  return {
    id: `evt-${String(++tlsEventCounter).padStart(5, '0')}`,
    timestamp: '2025-07-14T06:00:00.000Z',
    source: 'zeek',
    event_type: 'ssl',
    src_ip: '10.0.0.1',
    dest_ip: '185.143.223.47',
    dest_port: 443,
    server_name: null,
    tls_version: 'TLSv12',
    cipher: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    ja3_hash: null,
    ja4_hash: null,
    ja3s_hash: null,
    ja4x_hash: null,
    sni_matches_cert: null,
    cert_subject: null,
    cert_issuer: null,
    cert_serial: null,
    cert_not_before: null,
    cert_not_after: null,
    cert_self_signed: false,
    cert_expired: false,
    cert_validity_days: null,
    cert_key_type: null,
    cert_key_length: null,
    cert_san_dns: [],
    cert_chain_length: 0,
    connection_to_ip: false,
    ...overrides,
  } as TlsSslEvent;
}

function configWithKnownBad(overrides: Partial<TlsAnomalyConfig> = {}): TlsAnomalyConfig {
  return {
    ...DEFAULT_TLS_ANOMALY_CONFIG,
    known_bad_ja3: new Set(['badja3hash1234567890abcdef12345678']),
    known_bad_ja3s: new Set(['badja3shash1234567890abcdef1234567']),
    known_bad_ja3_ja3s_pairs: new Set(['badja3hash1234567890abcdef12345678|badja3shash1234567890abcdef1234567']),
    known_bad_ja4x: new Set(['badja4xhash12345678']),
    ...overrides,
  };
}

// ─── Dimension 1: Certificate Anomaly Score ─────────────────

// #1
describe('TLS Anomaly: cert self-signed to external → 0.40', () => {
  it('self_signed flag fires', () => {
    const e = makeTlsEvent({ cert_self_signed: true });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.40) < 0.001, `cert score ${score} should be 0.40`);
  });
});

// #2
describe('TLS Anomaly: cert self-signed + expired → 0.60', () => {
  it('additive sub-weights', () => {
    const e = makeTlsEvent({ cert_self_signed: true, cert_expired: true });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.60) < 0.001, `cert score ${score} should be 0.60`);
  });
});

// #3
describe('TLS Anomaly: cert self-signed + expired + short serial → 0.70', () => {
  it('three flags compound', () => {
    const e = makeTlsEvent({ cert_self_signed: true, cert_expired: true, cert_serial: '01' });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.70) < 0.001, `cert score ${score} should be 0.70`);
  });
});

// #4
describe('TLS Anomaly: cert four flags → 0.85', () => {
  it('self-signed + expired + short validity + short serial', () => {
    const e = makeTlsEvent({ cert_self_signed: true, cert_expired: true, cert_serial: '01', cert_validity_days: 3 });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.85) < 0.001, `cert score ${score} should be 0.85`);
  });
});

// #5
describe('TLS Anomaly: cert self-signed to internal → excluded', () => {
  it('RFC1918 dest produces 0', () => {
    const e = makeTlsEvent({ cert_self_signed: true, dest_ip: '10.0.1.50' });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.equal(score, 0);
  });
});

// #6
describe('TLS Anomaly: cert long validity (100+ years) → adds 0.15', () => {
  it('long validity flag', () => {
    const e = makeTlsEvent({ cert_self_signed: true, cert_validity_days: 36500 });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.55) < 0.001, `cert score ${score} should be 0.55 (0.40 + 0.15)`);
  });
});

// #7
describe('TLS Anomaly: cert short validity (< 7 days) → adds 0.15', () => {
  it('short validity flag', () => {
    const e = makeTlsEvent({ cert_self_signed: true, cert_validity_days: 3 });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.55) < 0.001, `cert score ${score} should be 0.55 (0.40 + 0.15)`);
  });
});

// #8
describe('TLS Anomaly: clean cert → 0', () => {
  it('no flags produce zero', () => {
    const e = makeTlsEvent({ cert_self_signed: false, cert_expired: false, cert_validity_days: 365, cert_serial: 'AABBCCDDEE' });
    const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.equal(score, 0);
  });
});

// ─── Dimension 2: Fingerprint Anomaly Score ─────────────────

// #9
describe('TLS Anomaly: JA3 known-bad → 0.90', () => {
  it('database lookup hit', () => {
    const e = makeTlsEvent({ ja3_hash: 'badja3hash1234567890abcdef12345678' });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    assert.ok(Math.abs(score - 0.90) < 0.001, `fp score ${score} should be 0.90`);
  });
});

// #10
describe('TLS Anomaly: JA3S known-bad → 0.80', () => {
  it('server fingerprint match', () => {
    const e = makeTlsEvent({ ja3s_hash: 'badja3shash1234567890abcdef1234567' });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    assert.ok(Math.abs(score - 0.80) < 0.001, `fp score ${score} should be 0.80`);
  });
});

// #11
describe('TLS Anomaly: JA3+JA3S pair → 0.95', () => {
  it('pair has highest specificity', () => {
    const e = makeTlsEvent({
      ja3_hash: 'badja3hash1234567890abcdef12345678',
      ja3s_hash: 'badja3shash1234567890abcdef1234567',
    });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    assert.ok(Math.abs(score - 0.95) < 0.001, `fp score ${score} should be 0.95`);
  });
});

// #12
describe('TLS Anomaly: JA4X known-bad → 0.95', () => {
  it('certificate generation match', () => {
    const e = makeTlsEvent({ ja4x_hash: 'badja4xhash12345678' });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    assert.ok(Math.abs(score - 0.95) < 0.001, `fp score ${score} should be 0.95`);
  });
});

// #13
describe('TLS Anomaly: no fingerprint matches → 0', () => {
  it('clean fingerprints produce zero', () => {
    const e = makeTlsEvent({ ja3_hash: 'cleanja3hash000000000000000000000' });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    assert.equal(score, 0);
  });
});

describe('TLS Anomaly: fingerprint matching is case-insensitive', () => {
  it('matches lowercase event hashes against uppercase feed values', () => {
    const e = makeTlsEvent({ ja3_hash: 'deadbeefcafeface1234567890abcdef' });
    const score = computeFingerprintAnomalyScore(e, {
      ...DEFAULT_TLS_ANOMALY_CONFIG,
      known_bad_ja3: new Set(['DEADBEEFCAFEFACE1234567890ABCDEF']),
    });
    assert.ok(Math.abs(score - 0.90) < 0.001, `fp score ${score} should be 0.90`);
  });
});

// #14
describe('TLS Anomaly: multiple fingerprint matches → max', () => {
  it('max not sum', () => {
    const e = makeTlsEvent({
      ja3_hash: 'badja3hash1234567890abcdef12345678',
      ja3s_hash: 'badja3shash1234567890abcdef1234567',
      ja4x_hash: 'badja4xhash12345678',
    });
    const score = computeFingerprintAnomalyScore(e, configWithKnownBad());
    // pair=0.95, ja4x=0.95, ja3=0.90, ja3s=0.80 → max=0.95
    assert.ok(Math.abs(score - 0.95) < 0.001, `fp score ${score} should be 0.95 (max, not sum)`);
  });
});

// ─── Dimension 3: SNI Anomaly Score ─────────────────────────

// #15
describe('TLS Anomaly: missing SNI → 0.50', () => {
  it('no server_name', () => {
    const e = makeTlsEvent({ server_name: null });
    const score = computeSniAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.50) < 0.001, `sni score ${score} should be 0.50`);
  });
});

// #16
describe('TLS Anomaly: SNI mismatch → 0.70', () => {
  it('SNI does not match cert', () => {
    const e = makeTlsEvent({ server_name: 'cdn.example.com', sni_matches_cert: false });
    const score = computeSniAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.70) < 0.001, `sni score ${score} should be 0.70`);
  });
});

// #17
describe('TLS Anomaly: SNI + connection to raw IP → 0.60', () => {
  it('SNI with IP destination', () => {
    const e = makeTlsEvent({ server_name: 'cdn.example.com', connection_to_ip: true });
    const score = computeSniAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.60) < 0.001, `sni score ${score} should be 0.60`);
  });
});

// #18
describe('TLS Anomaly: SNI present and matches → 0', () => {
  it('clean SNI', () => {
    const e = makeTlsEvent({ server_name: 'www.example.com', sni_matches_cert: true, connection_to_ip: false });
    const score = computeSniAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.equal(score, 0);
  });
});

// #19
describe('TLS Anomaly: empty string server_name → missing', () => {
  it('empty string treated as missing', () => {
    const e = makeTlsEvent({ server_name: '' });
    const score = computeSniAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.ok(Math.abs(score - 0.50) < 0.001, `sni score ${score} should be 0.50`);
  });
});

// ─── Composite: Max-of-Dimensions ───────────────────────────

// #20
describe('TLS Anomaly: composite — fingerprint dominates', () => {
  it('cert=0.40, fp=0.95, sni=0.50 → 0.95', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: true,
      ja3_hash: 'badja3hash1234567890abcdef12345678',
      ja3s_hash: 'badja3shash1234567890abcdef1234567',
      server_name: null,
    });
    const result = scoreTlsAnomalyCandidates([e], configWithKnownBad());
    assert.equal(result.length, 1);
    assert.ok(Math.abs(result[0].tls_anomaly_score - 0.95) < 0.001);
  });
});

// #21
describe('TLS Anomaly: composite — cert alone sufficient', () => {
  it('cert=0.70, fp=0, sni=0 → 0.70', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: true,
      cert_expired: true,
      cert_serial: '01',
      server_name: 'legit.com',
      sni_matches_cert: true,
    });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result.length, 1);
    assert.ok(Math.abs(result[0].tls_anomaly_score - 0.70) < 0.001);
  });
});

// #22
describe('TLS Anomaly: composite — SNI alone sufficient', () => {
  it('cert=0, fp=0, sni=0.50 → 0.50', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ server_name: null });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result.length, 1);
    assert.ok(Math.abs(result[0].tls_anomaly_score - 0.50) < 0.001);
  });
});

// #23
describe('TLS Anomaly: composite — fingerprint alone sufficient', () => {
  it('cert=0, fp=0.90, sni=0 → 0.90', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      ja3_hash: 'badja3hash1234567890abcdef12345678',
      server_name: 'legit.com',
      sni_matches_cert: true,
    });
    const result = scoreTlsAnomalyCandidates([e], configWithKnownBad());
    assert.equal(result.length, 1);
    assert.ok(Math.abs(result[0].tls_anomaly_score - 0.90) < 0.001);
  });
});

// #24
describe('TLS Anomaly: all dimensions zero → no candidate', () => {
  it('filtered', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: false,
      cert_expired: false,
      cert_validity_days: 365,
      cert_serial: 'AABBCCDDEE',
      server_name: 'legit.com',
      sni_matches_cert: true,
    });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result.length, 0);
  });
});

// #25
describe('TLS Anomaly: all dimensions below threshold → no candidate', () => {
  it('max=0.20 below 0.30', () => {
    resetCandidateCounter();
    // Create config with very low weights so cert_self_signed = 0.20, and ensure SNI/FP are clean
    const config: TlsAnomalyConfig = {
      ...DEFAULT_TLS_ANOMALY_CONFIG,
      cert_self_signed_weight: 0.20,
      cert_expired_weight: 0.05,
      cert_short_validity_weight: 0.05,
      cert_long_validity_weight: 0.05,
      cert_short_serial_weight: 0.05,
    };
    const e = makeTlsEvent({ cert_self_signed: true, server_name: 'legit.com', sni_matches_cert: true });
    const result = scoreTlsAnomalyCandidates([e], config);
    assert.equal(result.length, 0);
  });
});

// ─── Filtering and Thresholds ───────────────────────────────

// #26
describe('TLS Anomaly: boundary — 0.29 filtered', () => {
  it('below min_dimension_score', () => {
    resetCandidateCounter();
    // Use custom weight 0.29 for self-signed, and ensure SNI/FP are clean
    const customConfig: TlsAnomalyConfig = { ...DEFAULT_TLS_ANOMALY_CONFIG, cert_self_signed_weight: 0.29 };
    const e = makeTlsEvent({ cert_self_signed: true, server_name: 'legit.com', sni_matches_cert: true });
    const result = scoreTlsAnomalyCandidates([e], customConfig);
    assert.equal(result.length, 0);
  });
});

// #27
describe('TLS Anomaly: boundary — 0.31 emitted', () => {
  it('just above min_dimension_score', () => {
    resetCandidateCounter();
    const customConfig: TlsAnomalyConfig = { ...DEFAULT_TLS_ANOMALY_CONFIG, cert_self_signed_weight: 0.31 };
    const e = makeTlsEvent({ cert_self_signed: true, server_name: 'legit.com', sni_matches_cert: true });
    const result = scoreTlsAnomalyCandidates([e], customConfig);
    assert.equal(result.length, 1);
  });
});

// #28
describe('TLS Anomaly: RFC1918 exclusion — all ranges', () => {
  it('10.x, 172.16.x, 192.168.x all excluded', () => {
    for (const ip of ['10.0.0.1', '172.16.5.1', '192.168.1.1']) {
      const e = makeTlsEvent({ cert_self_signed: true, dest_ip: ip });
      const score = computeCertAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
      assert.equal(score, 0, `self-signed to ${ip} should be excluded`);
    }
  });
});

// ─── Entity Key and Grouping ────────────────────────────────

// #29
describe('TLS Anomaly: different dest_ips → separate candidates', () => {
  it('entity key includes dest_ip', () => {
    resetCandidateCounter();
    const e1 = makeTlsEvent({ id: 'e1', dest_ip: '185.143.223.47', cert_self_signed: true });
    const e2 = makeTlsEvent({ id: 'e2', dest_ip: '203.0.113.50', cert_self_signed: true });
    const result = scoreTlsAnomalyCandidates([e1, e2]);
    assert.equal(result.length, 2);
  });
});

// #30
describe('TLS Anomaly: different dest_ports → separate candidates', () => {
  it('entity key includes dest_port', () => {
    resetCandidateCounter();
    const e1 = makeTlsEvent({ id: 'e1', dest_port: 443, cert_self_signed: true });
    const e2 = makeTlsEvent({ id: 'e2', dest_port: 8443, cert_self_signed: true });
    const result = scoreTlsAnomalyCandidates([e1, e2]);
    assert.equal(result.length, 2);
  });
});

// #31
describe('TLS Anomaly: same tuple multiple connections → single candidate', () => {
  it('grouped correctly', () => {
    resetCandidateCounter();
    const events = Array.from({ length: 5 }, (_, i) => makeTlsEvent({
      id: `e${i}`,
      timestamp: new Date(Date.parse('2025-07-14T06:00:00Z') + i * 60000).toISOString(),
      cert_self_signed: true,
    }));
    const result = scoreTlsAnomalyCandidates(events);
    assert.equal(result.length, 1);
    assert.equal(result[0].total_tls_connections, 5);
  });
});

// #32
describe('TLS Anomaly: cert rotation → takes worst cert score', () => {
  it('max across connections', () => {
    resetCandidateCounter();
    const bad = makeTlsEvent({ id: 'bad', cert_self_signed: true, cert_expired: true }); // cert=0.60
    const clean = makeTlsEvent({ id: 'clean', cert_self_signed: false, cert_expired: false, cert_validity_days: 365, cert_serial: 'AABBCCDD' }); // cert=0
    const result = scoreTlsAnomalyCandidates([bad, clean]);
    assert.equal(result.length, 1);
    assert.ok(result[0].cert_anomaly_score >= 0.59, `cert dimension should be ~0.60 from worst cert, got ${result[0].cert_anomaly_score}`);
  });
});

// ─── Informational Fields ───────────────────────────────────

// #33
describe('TLS Anomaly: cert fields populated', () => {
  it('subject, issuer from bestEntry', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: true,
      cert_subject: 'CN=evil.example.com',
      cert_issuer: 'CN=evil.example.com',
    });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].cert_subject, 'CN=evil.example.com');
    assert.equal(result[0].cert_issuer, 'CN=evil.example.com');
  });
});

// #34
describe('TLS Anomaly: cert_validity_days populated', () => {
  it('validity from event', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true, cert_validity_days: 365 });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].cert_validity_days, 365);
  });
});

// #35
describe('TLS Anomaly: fingerprint hashes populated', () => {
  it('ja3, ja4, ja3s, ja4x from event', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true, ja3_hash: 'abc', ja4_hash: 'def', ja3s_hash: 'ghi', ja4x_hash: 'jkl' });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].ja3_hash, 'abc');
    assert.equal(result[0].ja4_hash, 'def');
    assert.equal(result[0].ja3s_hash, 'ghi');
    assert.equal(result[0].ja4x_hash, 'jkl');
  });
});

// #36
describe('TLS Anomaly: TLS version and cipher populated', () => {
  it('handshake fields', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true, tls_version: 'TLSv13', cipher: 'TLS_AES_256_GCM_SHA384' });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].tls_version, 'TLSv13');
    assert.equal(result[0].cipher_suite, 'TLS_AES_256_GCM_SHA384');
  });
});

// #37
describe('TLS Anomaly: server_name populated', () => {
  it('SNI field present', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true, server_name: 'evil.com' });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].server_name, 'evil.com');
  });
});

// #38
describe('TLS Anomaly: session_count = total_tls_connections', () => {
  it('alias correct', () => {
    resetCandidateCounter();
    const events = [makeTlsEvent({ id: 'e1', cert_self_signed: true }), makeTlsEvent({ id: 'e2', cert_self_signed: true })];
    const result = scoreTlsAnomalyCandidates(events);
    assert.equal(result[0].session_count, result[0].total_tls_connections);
    assert.equal(result[0].total_tls_connections, 2);
  });
});

// #39
describe('TLS Anomaly: connection_to_ip boolean', () => {
  it('set correctly', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true, connection_to_ip: true });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].connection_to_ip, true);
  });
});

// ─── Standard Tests ─────────────────────────────────────────

// #40
describe('TLS Anomaly: evidence trail', () => {
  it('event IDs preserved', () => {
    resetCandidateCounter();
    const events = [makeTlsEvent({ id: 'evt-00001', cert_self_signed: true }), makeTlsEvent({ id: 'evt-00002', cert_self_signed: true })];
    const result = scoreTlsAnomalyCandidates(events);
    assert.equal(result[0].evidence.constituent_event_ids.length, 2);
    assert.ok(result[0].evidence.constituent_event_ids.includes('evt-00001'));
  });
});

// #41
describe('TLS Anomaly: attribution null', () => {
  it('null before correlation', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result[0].process_name, null);
    assert.equal(result[0].process_id, null);
  });
});

// #42
describe('TLS Anomaly: sort order', () => {
  it('sorted by tls_anomaly_score descending', () => {
    resetCandidateCounter();
    const high = makeTlsEvent({ id: 'h', dest_ip: '1.2.3.4', cert_self_signed: true, cert_expired: true, cert_serial: '01' }); // cert=0.70
    const low = makeTlsEvent({ id: 'l', dest_ip: '5.6.7.8', server_name: null }); // sni=0.50
    const result = scoreTlsAnomalyCandidates([low, high]);
    assert.equal(result.length, 2);
    assert.ok(result[0].tls_anomaly_score >= result[1].tls_anomaly_score);
  });
});

// #43
describe('TLS Anomaly: score bounded [0, 1]', () => {
  it('all dimensions within range', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: true, cert_expired: true, cert_serial: '01', cert_validity_days: 2,
      ja3_hash: 'badja3hash1234567890abcdef12345678',
      server_name: null,
    });
    const result = scoreTlsAnomalyCandidates([e], configWithKnownBad());
    assert.equal(result.length, 1);
    const c = result[0];
    assert.ok(c.tls_anomaly_score >= 0 && c.tls_anomaly_score <= 1);
    assert.ok(c.cert_anomaly_score >= 0 && c.cert_anomaly_score <= 1);
    assert.ok(c.fingerprint_anomaly_score >= 0 && c.fingerprint_anomaly_score <= 1);
    assert.ok(c.sni_anomaly_score >= 0 && c.sni_anomaly_score <= 1);
  });
});

// #44
describe('TLS Anomaly: candidate ID format', () => {
  it('TLS prefix', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({ cert_self_signed: true });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.match(result[0].candidate_id, /^TLS-[0-9a-f]{16}$/);
  });
});

// ─── C2 Profile Integration Tests ───────────────────────────

// #45
describe('TLS Anomaly: Cobalt Strike default profile', () => {
  it('self-signed + known JA3S → high score', () => {
    resetCandidateCounter();
    const csJa3s = 'b742b407517bac9536a77a7b0fee28e9';
    const config = configWithKnownBad({ known_bad_ja3s: new Set([csJa3s]) });
    const e = makeTlsEvent({
      cert_self_signed: true,
      cert_serial: '8BB00EE',
      ja3s_hash: csJa3s,
      server_name: null,
    });
    const result = scoreTlsAnomalyCandidates([e], config);
    assert.equal(result.length, 1);
    assert.ok(result[0].tls_anomaly_score >= 0.80, `CS default should score high, got ${result[0].tls_anomaly_score}`);
    assert.ok(result[0].ja3s_known_bad);
  });
});

// #46
describe('TLS Anomaly: Sliver-style random cert + JA4X match', () => {
  it('JA4X catches despite clean cert', () => {
    resetCandidateCounter();
    const sliverJa4x = 'sliver_ja4x_fingerprint_1234';
    const config = configWithKnownBad({ known_bad_ja4x: new Set([sliverJa4x]) });
    const e = makeTlsEvent({
      cert_self_signed: false,
      cert_expired: false,
      cert_validity_days: 365,
      cert_serial: 'AABBCCDDEE',
      ja4x_hash: sliverJa4x,
      server_name: 'cdn.legitimate.com',
      sni_matches_cert: true,
    });
    const result = scoreTlsAnomalyCandidates([e], config);
    assert.equal(result.length, 1);
    assert.ok(result[0].tls_anomaly_score >= 0.95, `Sliver JA4X should score 0.95, got ${result[0].tls_anomaly_score}`);
    assert.equal(result[0].cert_anomaly_score, 0);
    assert.ok(result[0].ja4x_known_bad);
  });
});

// #47
describe('TLS Anomaly: legitimate traffic → no candidate', () => {
  it('valid LE cert + clean JA3 + matching SNI → filtered', () => {
    resetCandidateCounter();
    const e = makeTlsEvent({
      cert_self_signed: false,
      cert_expired: false,
      cert_validity_days: 90,
      cert_serial: 'AABBCCDDEEFF0011',
      cert_subject: 'CN=www.example.com',
      cert_issuer: "CN=Let's Encrypt Authority X3",
      cert_san_dns: ['www.example.com'],
      cert_chain_length: 2,
      server_name: 'www.example.com',
      sni_matches_cert: true,
      ja3_hash: 'e7d705a3286e19ea42f587b344ee6865',
      connection_to_ip: false,
    });
    const result = scoreTlsAnomalyCandidates([e]);
    assert.equal(result.length, 0);
  });
});

// ─── Known-bad empty sets ───────────────────────────────────

describe('TLS Anomaly: empty known-bad sets → fingerprint always 0', () => {
  it('fingerprint dimension produces 0', () => {
    const e = makeTlsEvent({ ja3_hash: 'someja3hash', ja3s_hash: 'someja3shash' });
    const score = computeFingerprintAnomalyScore(e, DEFAULT_TLS_ANOMALY_CONFIG);
    assert.equal(score, 0);
  });
});

// ─── P1-2: Sparse events (missing x509 fields) ─────────────

describe('TLS Anomaly: sparse ssl event without x509 data', () => {
  it('all required output keys present with contract defaults', () => {
    resetCandidateCounter();
    // Intentionally sparse: only ssl.log fields, no cert_* fields at all
    const sparse = {
      id: 'evt-sparse',
      timestamp: '2025-07-14T06:00:00.000Z',
      source: 'zeek' as const,
      event_type: 'ssl' as const,
      src_ip: '10.0.0.1',
      dest_ip: '185.143.223.47',
      dest_port: 443,
      server_name: null,
      // All cert fields intentionally omitted (undefined)
    } as unknown as import('../../src/schema/events.js').TlsSslEvent;

    const result = scoreTlsAnomalyCandidates([sparse]);
    // Missing SNI → sni_anomaly = 0.50 → candidate emitted
    assert.equal(result.length, 1);
    const c = result[0];

    // Verify all required fields are present (not undefined) with contract defaults
    assert.equal(c.cert_subject, null);
    assert.equal(c.cert_issuer, null);
    assert.equal(c.cert_serial, null);
    assert.equal(c.cert_validity_days, null);
    assert.equal(c.cert_not_before, null);
    assert.equal(c.cert_not_after, null);
    assert.equal(c.cert_self_signed, false);
    assert.equal(c.cert_expired, false);
    assert.equal(c.cert_key_type, null);
    assert.equal(c.cert_key_length, null);
    assert.deepEqual(c.cert_san_dns, []);
    assert.equal(c.cert_chain_length, 0);
    assert.equal(c.ja3_hash, null);
    assert.equal(c.ja4_hash, null);
    assert.equal(c.ja3s_hash, null);
    assert.equal(c.ja4x_hash, null);
    assert.equal(c.server_name, null);
    assert.equal(c.sni_matches_cert, null);
    assert.equal(c.connection_to_ip, false);
    assert.equal(c.tls_version, null);
    assert.equal(c.cipher_suite, null);

    // Verify no undefined values in NDJSON output
    const json = JSON.stringify(c);
    const parsed = JSON.parse(json);
    for (const key of Object.keys(c)) {
      assert.ok(key in parsed, `Key ${key} missing from NDJSON output (was undefined)`);
    }
  });
});
