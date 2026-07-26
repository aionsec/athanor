import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa destination frequency', () => {
  it('counts unique hosts per destination', () => {
    const events = [
      { timestamp: '2026-04-11T00:00:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS01', dest_ip: '8.8.8.8' },
      { timestamp: '2026-04-11T00:01:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS01', dest_ip: '1.1.1.1' },
      { timestamp: '2026-04-11T00:02:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS02', dest_ip: '8.8.8.8' },
      { timestamp: '2026-04-11T00:03:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS03', dest_ip: '9.9.9.9' },
    ];

    const tables = precomputeLfa(events as never[]);

    assert.equal(tables.totalHosts, 3);
    assert.equal(tables.destination.get('8.8.8.8'), 2);
    assert.equal(tables.destination.get('1.1.1.1'), 1);
    assert.equal(tables.destination.get('9.9.9.9'), 1);
    assert.equal(prevalence(tables.destination, '8.8.8.8', tables.totalHosts), 2 / 3);
    assert.equal(prevalence(tables.destination, '9.9.9.9', tables.totalHosts), 1 / 3);
    assert.equal(rarity(tables.destination, '8.8.8.8', tables.totalHosts), 1 - (2 / 3));
    assert.equal(rarity(tables.destination, '9.9.9.9', tables.totalHosts), 1 - (1 / 3));
  });
});
