/**
 * Zeek `conn.log` (JSON lines) → normalized `ConnLogEvent`.
 *
 * The exact inverse of the renderer that writes the sample dataset's `conn.log`.
 * Field map:
 *
 *   ts          → timestamp        (epoch seconds → ISO; ms = round(ts * 1000))
 *   uid         → zeek_uid
 *   id.orig_h   → src_ip
 *   id.orig_p   → src_port         (absent in emitted canon — a real estate has it)
 *   id.resp_h   → dest_ip
 *   id.resp_p   → dest_port
 *   proto       → proto
 *   service     → service          ('-' / '' → field omitted, Zeek's unset convention)
 *   duration    → duration
 *   orig_bytes  → orig_bytes + bytes_sent      (the normalized record carries both names)
 *   resp_bytes  → resp_bytes + bytes_received
 *   conn_state  → conn_state
 *   history     → history
 *   orig_pkts   → orig_pkts
 *   resp_pkts   → resp_pkts
 *   (dialect)   → source 'zeek', event_type 'conn', domain 'traditional'
 */

import { compact, isoFromMs, type RawRecord, RecordReader, ZEEK_UNSET } from './codecs.js';
import type { ParsedEvent } from './merge.js';

export const ZEEK_CONN_DIALECT = 'zeek/conn';

export function parseZeekConnRecord(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const timestampMs = reader.zeekTimestampMs();

  const origBytes = reader.optionalNumber('orig_bytes');
  const respBytes = reader.optionalNumber('resp_bytes');

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'zeek',
    event_type: 'conn',
    src_ip: reader.requiredString('id.orig_h'),
    src_port: reader.optionalNumber('id.orig_p'),
    dest_ip: reader.requiredString('id.resp_h'),
    dest_port: reader.requiredNumber('id.resp_p'),
    proto: reader.requiredString('proto'),
    service: reader.unsetAwareString('service', ZEEK_UNSET),
    duration: reader.optionalNumber('duration'),
    orig_bytes: origBytes,
    resp_bytes: respBytes,
    // `bytes_sent` / `bytes_received` are the names the data-transfer scorer reads;
    // the raw log carries one name per value, so ingest re-derives the alias.
    bytes_sent: origBytes,
    bytes_received: respBytes,
    conn_state: reader.optionalString('conn_state'),
    history: reader.optionalString('history'),
    orig_pkts: reader.optionalNumber('orig_pkts'),
    resp_pkts: reader.optionalNumber('resp_pkts'),
    zeek_uid: reader.optionalString('uid'),
    domain: 'traditional',
  });

  return { dialect: ZEEK_CONN_DIALECT, timestampMs, event, origin: reader.label };
}

export function parseZeekConn(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parseZeekConnRecord);
}
