import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa hash frequency', () => {
  it('counts unique hosts per SHA-256 across object and string hash fields', () => {
    const hashA = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const hashB = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

    const events = [
      {
        timestamp: '2026-04-12T00:00:00.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS01',
        hashes: `MD5=1,SHA256=${hashA},IMPHASH=2`,
      },
      {
        timestamp: '2026-04-12T00:00:10.000Z',
        source: 'sysmon',
        event_type: 'image_load',
        host: 'WS02',
        hashes: { SHA256: hashA.toLowerCase(), MD5: '3' },
      },
      {
        timestamp: '2026-04-12T00:00:20.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS03',
        sha256: hashB.toLowerCase(),
      },
    ];

    const tables = precomputeLfa(events as never[]);

    assert.equal(tables.totalHosts, 3);
    assert.equal(tables.hash.get(hashA.toLowerCase()), 2);
    assert.equal(tables.hash.get(hashB.toLowerCase()), 1);
    assert.equal(prevalence(tables.hash, hashA.toLowerCase(), tables.totalHosts), 2 / 3);
    assert.equal(prevalence(tables.hash, hashB.toLowerCase(), tables.totalHosts), 1 / 3);
    assert.equal(rarity(tables.hash, hashA.toLowerCase(), tables.totalHosts), 1 - (2 / 3));
    assert.equal(rarity(tables.hash, hashB.toLowerCase(), tables.totalHosts), 1 - (1 / 3));
  });
});
