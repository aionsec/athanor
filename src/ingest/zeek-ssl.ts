/**
 * Zeek `ssl.log` (JSON lines, this repo's documented pre-joined ssl+x509 shape)
 * → normalized `TlsSslEvent`.
 *
 * The exact inverse of the renderer that writes the sample dataset's `ssl.log`. Raw
 * ssl.log carries
 * ONE name per value while the normalized record dual-writes the raw name and the
 * name the TLS-anomaly scorer reads; ingest re-derives the second name. Those alias
 * fills live HERE, in the parser — `normalizeZeekSslRecord` in `src/schema/events.ts`
 * is deliberately untouched (plan §"Global Constraints").
 *
 *   ts                  → timestamp
 *   uid                 → zeek_uid                (carried VERBATIM — the canon ssl uids
 *                                                  do not join to conn uids, and that failed
 *                                                  join is what makes TLS-001 `unavailable`)
 *   id.orig_h/resp_h/resp_p → src_ip / dest_ip / dest_port
 *   server_name         → tls_server_name  +  server_name  ('' → null)
 *   version             → tls_version
 *   cipher              → cipher
 *   subject             → tls_subject  +  cert_subject
 *   issuer              → tls_issuer   +  cert_issuer
 *   ja3                 → tls_ja3      +  ja3_hash
 *   ja3s                → tls_ja3s     +  ja3s_hash
 *   ja4 / ja4x          → ja4_hash / ja4x_hash
 *   sni_matches_cert, connection_to_ip, established → verbatim
 *   cert_*              → verbatim (the pre-joined x509 block, already normalized names)
 *   (dialect)           → source 'zeek', event_type 'ssl', proto 'tcp', service 'ssl',
 *                         domain 'traditional'
 *
 * Unset decoding: a `-` (or absent) STRING field becomes `null`, not an omission —
 * the TLS contract declares these `string | null`, and the scorer distinguishes
 * "x509 said nothing" from "no such column". Numbers/booleans/arrays are omitted
 * when absent rather than defaulted, so ingest never invents certificate facts.
 */

import { compact, isoFromMs, type RawRecord, RecordReader, ZEEK_UNSET } from './codecs.js';
import type { ParsedEvent } from './merge.js';

export const ZEEK_SSL_DIALECT = 'zeek/ssl';

export function parseZeekSslRecord(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const timestampMs = reader.zeekTimestampMs();

  // The raw SNI is an empty string when the handshake carried none; the normalized
  // twin is null. Both names are written, exactly as the canon record carries them.
  const rawServerName = reader.optionalString('server_name') ?? '';
  const ja3 = reader.unsetAwareString('ja3', ZEEK_UNSET) ?? null;
  const ja3s = reader.unsetAwareString('ja3s', ZEEK_UNSET) ?? null;
  const subject = reader.unsetAwareString('subject', ZEEK_UNSET) ?? null;
  const issuer = reader.unsetAwareString('issuer', ZEEK_UNSET) ?? null;

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'zeek',
    event_type: 'ssl',
    // zeek ssl.log has no proto/service column — the dialect implies both.
    proto: 'tcp',
    service: 'ssl',
    src_ip: reader.requiredString('id.orig_h'),
    dest_ip: reader.requiredString('id.resp_h'),
    dest_port: reader.requiredNumber('id.resp_p'),
    zeek_uid: reader.optionalString('uid'),

    tls_server_name: rawServerName,
    server_name: rawServerName.length > 0 ? rawServerName : null,
    tls_version: reader.unsetAwareString('version', ZEEK_UNSET) ?? null,
    cipher: reader.unsetAwareString('cipher', ZEEK_UNSET) ?? null,
    tls_ja3: ja3,
    ja3_hash: ja3,
    tls_ja3s: ja3s,
    ja3s_hash: ja3s,
    ja4_hash: reader.unsetAwareString('ja4', ZEEK_UNSET) ?? null,
    ja4x_hash: reader.unsetAwareString('ja4x', ZEEK_UNSET) ?? null,
    tls_subject: subject,
    cert_subject: subject,
    tls_issuer: issuer,
    cert_issuer: issuer,
    sni_matches_cert: reader.optionalBoolean('sni_matches_cert'),
    connection_to_ip: reader.optionalBoolean('connection_to_ip'),
    established: reader.optionalScalar('established'),

    cert_serial: reader.unsetAwareString('cert_serial', ZEEK_UNSET) ?? null,
    cert_not_before: reader.unsetAwareString('cert_not_before', ZEEK_UNSET) ?? null,
    cert_not_after: reader.unsetAwareString('cert_not_after', ZEEK_UNSET) ?? null,
    cert_validity_days: reader.optionalNumber('cert_validity_days'),
    cert_self_signed: reader.optionalBoolean('cert_self_signed'),
    cert_expired: reader.optionalBoolean('cert_expired'),
    cert_key_type: reader.unsetAwareString('cert_key_type', ZEEK_UNSET) ?? null,
    cert_key_length: reader.optionalNumber('cert_key_length'),
    cert_san_dns: reader.optionalStringArray('cert_san_dns'),
    cert_chain_length: reader.optionalNumber('cert_chain_length'),
    domain: 'traditional',
  });

  return { dialect: ZEEK_SSL_DIALECT, timestampMs, event, origin: reader.label };
}

export function parseZeekSsl(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parseZeekSslRecord);
}
