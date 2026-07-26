import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa beacon dimensions', () => {
  it('populates domain, userAgent, ja3 and leaves placeholders empty', () => {
    const events = [
      { timestamp: '2026-04-11T00:00:00.000Z', source: 'zeek', event_type: 'dns', src_ip: 'WS01', query: 'api.example.com' },
      { timestamp: '2026-04-11T00:01:00.000Z', source: 'zeek', event_type: 'http', src_ip: 'WS01', http_host: 'api.example.com', http_user_agent: 'ua-1' },
      { timestamp: '2026-04-11T00:02:00.000Z', source: 'zeek', event_type: 'ssl', src_ip: 'WS01', ja3_hash: 'ja3-a' },
      { timestamp: '2026-04-11T00:03:00.000Z', source: 'zeek', event_type: 'http', src_ip: 'WS02', http_host: 'cdn.example.com', http_user_agent: 'ua-1' },
      { timestamp: '2026-04-11T00:04:00.000Z', source: 'zeek', event_type: 'ssl', src_ip: 'WS02', ja3_hash: 'ja3-b' },
    ];

    const tables = precomputeLfa(events as never[]);

    assert.equal(tables.domain.get('api.example.com'), 1);
    assert.equal(tables.domain.get('cdn.example.com'), 1);
    assert.equal(tables.userAgent.get('ua-1'), 2);
    assert.equal(tables.ja3.get('ja3-a'), 1);
    assert.equal(tables.ja3.get('ja3-b'), 1);

    assert.equal(tables.process.size, 0);
    assert.equal(tables.hash.size, 0);
    assert.equal(tables.commandLine.size, 0);
    assert.equal(tables.parentChildPair.size, 0);
    assert.equal(tables.scriptBlockHash.size, 0);
    assert.equal(tables.authPair.size, 0);
  });
});
