// Unit — zeek conn.log parser. Inline micro-fixtures are REAL emitted lines (copied
// from fixtures/raw/conn.log) plus the real-estate variations the canon does not
// exercise: an `id.orig_p`, and a `-` service.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IngestError, parseJsonLines } from '../../src/ingest/codecs.js';
import { parseZeekConn, parseZeekConnRecord } from '../../src/ingest/zeek-conn.js';

const CANON_LINE = '{"ts":1773057630.000000,"uid":"CJye6Pr4c4225XZIQx","id.orig_h":"10.20.30.41",'
  + '"id.resp_h":"104.18.22.51","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.099833,'
  + '"orig_bytes":878,"resp_bytes":308,"conn_state":"SF","history":"ShADad","orig_pkts":26,'
  + '"resp_pkts":10}';

function parseOne(line: string) {
  const records = parseJsonLines(line, 'conn.log');
  assert.equal(records.length, 1);
  return parseZeekConnRecord(records[0]!);
}

describe('ingest/zeek-conn', () => {
  it('maps a real emitted conn.log line to the exact normalized record', () => {
    const parsed = parseOne(CANON_LINE);

    assert.equal(parsed.dialect, 'zeek/conn');
    assert.equal(parsed.timestampMs, 1_773_057_630_000);
    assert.deepEqual(parsed.event, {
      timestamp: '2026-03-09T12:00:30.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.20.30.41',
      dest_ip: '104.18.22.51',
      dest_port: 443,
      proto: 'tcp',
      service: 'ssl',
      duration: 0.099833,
      orig_bytes: 878,
      resp_bytes: 308,
      // The alias pair the data-transfer scorer reads — re-derived, never carried.
      bytes_sent: 878,
      bytes_received: 308,
      conn_state: 'SF',
      history: 'ShADad',
      orig_pkts: 26,
      resp_pkts: 10,
      zeek_uid: 'CJye6Pr4c4225XZIQx',
      domain: 'traditional',
    });
  });

  it('decodes sub-second ts exactly (round(ts * 1000), never float drift)', () => {
    assert.equal(parseOne('{"ts":1773057630.500000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
      + '"id.resp_p":443,"proto":"tcp"}').timestampMs, 1_773_057_630_500);
    assert.equal(parseOne('{"ts":1773057630.999000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
      + '"id.resp_p":443,"proto":"tcp"}').event.timestamp, '2026-03-09T12:00:30.999Z');
  });

  it("omits service on Zeek's unset token (a field with no value is not a field)", () => {
    const parsed = parseOne('{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
      + '"id.resp_p":443,"proto":"tcp","service":"-"}');
    assert.equal('service' in parsed.event, false);
  });

  it('tolerates id.orig_p — real estates log it, the canon renderer omits it', () => {
    const parsed = parseOne('{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.orig_p":51000,'
      + '"id.resp_h":"1.2.3.4","id.resp_p":443,"proto":"tcp"}');
    assert.equal(parsed.event.src_port, 51000);

    const without = parseOne('{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
      + '"id.resp_p":443,"proto":"tcp"}');
    assert.equal('src_port' in without.event, false, 'no src_port is invented when the log has none');
  });

  it('omits the byte aliases when the log carries no byte counts', () => {
    const parsed = parseOne('{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
      + '"id.resp_p":443,"proto":"tcp"}');
    for (const key of ['orig_bytes', 'resp_bytes', 'bytes_sent', 'bytes_received']) {
      assert.equal(key in parsed.event, false, `${key} must not be invented`);
    }
  });

  it('parses a multi-line body and reports file:line on a malformed line', () => {
    const body = `${CANON_LINE}\n${CANON_LINE}\n`;
    assert.equal(parseZeekConn(parseJsonLines(body, 'conn.log')).length, 2);

    assert.throws(
      () => parseJsonLines(`${CANON_LINE}\n{"ts":1773,\n`, 'conn.log'),
      (error: unknown) => error instanceof IngestError && /conn\.log:2: malformed JSON line/.test((error as Error).message),
    );
  });

  it('refuses a line missing a required column instead of emitting a hollow event', () => {
    assert.throws(
      () => parseOne('{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.resp_p":443,"proto":"tcp"}'),
      (error: unknown) => error instanceof IngestError
        && /conn\.log:1: expected non-empty string field "id\.resp_h"/.test((error as Error).message),
    );
    assert.throws(
      () => parseOne('{"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4","id.resp_p":443,"proto":"tcp"}'),
      (error: unknown) => error instanceof IngestError && /expected numeric zeek "ts"/.test((error as Error).message),
    );
  });

  it('names the Zeek option behind an ISO timestamp instead of just refusing it', () => {
    // `json_timestamps = JSON::TS_ISO8601` is a one-line change in someone's
    // local.zeek, and the whole estate's logs then read as unparseable.
    assert.throws(
      () => parseOne(
        '{"ts":"2026-03-09T12:00:30.000000Z","id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
        + '"id.resp_p":443,"proto":"tcp"}',
      ),
      (error: unknown) => error instanceof IngestError
        && /JSON::TS_ISO8601/.test((error as Error).message)
        && /JSON::TS_EPOCH/.test((error as Error).message),
    );
  });

  it('names a quoted number for what it is, not just as the wrong type', () => {
    // Shippers that render every column as a string are a whole-file property; met
    // one field at a time, it reads as a mystery.
    assert.throws(
      () => parseOne(
        '{"ts":1773057630.000000,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4",'
        + '"id.resp_p":"443","proto":"tcp"}',
      ),
      (error: unknown) => error instanceof IngestError
        && /expected finite number field "id\.resp_p", got "443"/.test((error as Error).message)
        && /NUMBER written as a string/.test((error as Error).message)
        && /docs\/extending\.md/.test((error as Error).message),
    );
  });
});
