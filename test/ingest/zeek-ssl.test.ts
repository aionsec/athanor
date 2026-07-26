// Unit — zeek ssl.log parser (the pre-joined ssl+x509 shape). The first fixture is a
// REAL emitted line copied from fixtures/raw/ssl.log; the rest are the variations the
// canon does not exercise (a populated SNI, unset fingerprints, a bare handshake).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IngestError, parseJsonLines } from '../../src/ingest/codecs.js';
import { parseZeekSslRecord } from '../../src/ingest/zeek-ssl.js';

const CANON_LINE = '{"ts":1773064840.267000,"uid":"CfprOrvEHSEv02Og63","id.orig_h":"10.20.30.41",'
  + '"id.resp_h":"193.42.33.81","id.resp_p":443,"server_name":"","version":"TLSv12",'
  + '"cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","subject":"CN=localhost","issuer":"CN=localhost",'
  + '"ja3":"72a589da586844d7f0818ce684948eea","ja3s":"b742b407517bac9536a77a7b0fee28e9",'
  + '"ja4":"t13d1516h2_8daaf6152771_02713d6af862","ja4x":"-","sni_matches_cert":false,'
  + '"connection_to_ip":true,"established":"T","cert_serial":"01",'
  + '"cert_not_before":"2026-03-08T14:00:30.000Z","cert_not_after":"2026-04-08T14:00:30.000Z",'
  + '"cert_validity_days":31,"cert_self_signed":true,"cert_expired":false,"cert_key_type":"rsa",'
  + '"cert_key_length":2048,"cert_san_dns":[],"cert_chain_length":1}';

function parseOne(line: string) {
  const records = parseJsonLines(line, 'ssl.log');
  return parseZeekSslRecord(records[0]!);
}

describe('ingest/zeek-ssl', () => {
  it('maps a real emitted ssl.log line to the exact normalized record', () => {
    const parsed = parseOne(CANON_LINE);

    assert.equal(parsed.dialect, 'zeek/ssl');
    assert.equal(parsed.timestampMs, 1_773_064_840_267);
    assert.deepEqual(parsed.event, {
      timestamp: '2026-03-09T14:00:40.267Z',
      source: 'zeek',
      event_type: 'ssl',
      // ssl.log has no proto/service column — the dialect implies both.
      proto: 'tcp',
      service: 'ssl',
      src_ip: '10.20.30.41',
      dest_ip: '193.42.33.81',
      dest_port: 443,
      // Carried VERBATIM: the canon ssl uids do not join to conn uids, and that
      // failed join is exactly what makes TLS-001 `unavailable`.
      zeek_uid: 'CfprOrvEHSEv02Og63',
      tls_server_name: '',
      server_name: null,
      tls_version: 'TLSv12',
      cipher: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      tls_ja3: '72a589da586844d7f0818ce684948eea',
      ja3_hash: '72a589da586844d7f0818ce684948eea',
      tls_ja3s: 'b742b407517bac9536a77a7b0fee28e9',
      ja3s_hash: 'b742b407517bac9536a77a7b0fee28e9',
      ja4_hash: 't13d1516h2_8daaf6152771_02713d6af862',
      ja4x_hash: null,
      tls_subject: 'CN=localhost',
      cert_subject: 'CN=localhost',
      tls_issuer: 'CN=localhost',
      cert_issuer: 'CN=localhost',
      sni_matches_cert: false,
      connection_to_ip: true,
      established: 'T',
      cert_serial: '01',
      cert_not_before: '2026-03-08T14:00:30.000Z',
      cert_not_after: '2026-04-08T14:00:30.000Z',
      cert_validity_days: 31,
      cert_self_signed: true,
      cert_expired: false,
      cert_key_type: 'rsa',
      cert_key_length: 2048,
      cert_san_dns: [],
      cert_chain_length: 1,
      domain: 'traditional',
    });
  });

  it('fills the scorer-normalized aliases in the PARSER (the schema stays untouched)', () => {
    const parsed = parseOne('{"ts":1773064840.267000,"id.orig_h":"10.0.0.9","id.resp_h":"203.0.113.44",'
      + '"id.resp_p":443,"server_name":"cdn.evil.example","ja3":"aaaa","ja3s":"bbbb",'
      + '"subject":"CN=evil","issuer":"CN=evil-ca"}');

    assert.equal(parsed.event.server_name, 'cdn.evil.example', 'a populated SNI is not nulled');
    assert.equal(parsed.event.tls_server_name, 'cdn.evil.example');
    assert.equal(parsed.event.ja3_hash, 'aaaa');
    assert.equal(parsed.event.ja3s_hash, 'bbbb');
    assert.equal(parsed.event.cert_subject, 'CN=evil');
    assert.equal(parsed.event.cert_issuer, 'CN=evil-ca');
  });

  it("maps every unset string column to null, not to an omission (the TLS contract is `| null`)", () => {
    const parsed = parseOne('{"ts":1773064840.267000,"id.orig_h":"10.0.0.9","id.resp_h":"203.0.113.44",'
      + '"id.resp_p":443,"server_name":"","version":"-","cipher":"-","subject":"-","issuer":"-",'
      + '"ja3":"-","ja3s":"-","ja4":"-","ja4x":"-","cert_serial":"-","cert_key_type":"-"}');

    for (const key of [
      'server_name', 'tls_version', 'cipher', 'tls_ja3', 'ja3_hash', 'tls_ja3s', 'ja3s_hash',
      'ja4_hash', 'ja4x_hash', 'tls_subject', 'cert_subject', 'tls_issuer', 'cert_issuer',
      'cert_serial', 'cert_key_type',
    ]) {
      assert.equal(parsed.event[key], null, `${key} must decode to null`);
    }
    assert.equal(parsed.event.tls_server_name, '', 'the raw SNI keeps its empty-string form');
  });

  it('invents no certificate facts for a handshake with no x509 block', () => {
    const parsed = parseOne('{"ts":1773064840.267000,"id.orig_h":"10.0.0.9","id.resp_h":"203.0.113.44",'
      + '"id.resp_p":443,"server_name":"good.example"}');

    for (const key of [
      'cert_validity_days', 'cert_self_signed', 'cert_expired', 'cert_key_length',
      'cert_san_dns', 'cert_chain_length', 'sni_matches_cert', 'connection_to_ip', 'established',
    ]) {
      assert.equal(key in parsed.event, false, `${key} must not be defaulted into existence`);
    }
  });

  it('refuses a wrongly-typed column rather than coercing it', () => {
    assert.throws(
      () => parseOne('{"ts":1773064840.267000,"id.orig_h":"10.0.0.9","id.resp_h":"203.0.113.44",'
        + '"id.resp_p":"443"}'),
      (error: unknown) => error instanceof IngestError
        && /ssl\.log:1: expected finite number field "id\.resp_p"/.test((error as Error).message),
    );
    assert.throws(
      () => parseOne('{"ts":1773064840.267000,"id.orig_h":"10.0.0.9","id.resp_h":"203.0.113.44",'
        + '"id.resp_p":443,"cert_san_dns":"a.example"}'),
      (error: unknown) => error instanceof IngestError
        && /expected string\[\] field "cert_san_dns"/.test((error as Error).message),
    );
  });
});
