import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa precompute integration', () => {
  it('is deterministic and skips malformed entries', () => {
    const events = [
      { timestamp: '2026-04-11T00:00:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS01', dest_ip: '8.8.8.8' },
      { timestamp: '2026-04-11T00:01:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS02', dest_ip: '8.8.8.8' },
      { timestamp: '2026-04-11T00:02:00.000Z', source: 'zeek', event_type: 'http', src_ip: 'WS02', http_user_agent: 'ua-2' },
      { timestamp: '2026-04-11T00:03:00.000Z', source: 'zeek', event_type: 'ssl', src_ip: 'WS03', ja3_hash: 'ja3-c' },
      { timestamp: '2026-04-11T00:03:30.000Z', source: 'powershell', event_type: 'script_block', host: 'WS03', script_block_text: 'Write-Host hello' },
      { timestamp: '2026-04-11T00:04:00.000Z', source: 'zeek', event_type: 'conn', src_ip: 'WS04' }, // malformed missing dest_ip
      { source: 'zeek', event_type: 'conn', src_ip: 'WS05', dest_ip: '9.9.9.9' }, // malformed missing timestamp
    ];

    const first = precomputeLfa(events as never[]);
    const second = precomputeLfa(events as never[]);

    const snapshot = (value: ReturnType<typeof precomputeLfa>) => ({
      totalHosts: value.totalHosts,
      destination: [...value.destination.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      process: [...value.process.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      commandLine: [...value.commandLine.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      hash: [...value.hash.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      parentChildPair: [...value.parentChildPair.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      scriptBlockHash: [...value.scriptBlockHash.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      domain: [...value.domain.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      userAgent: [...value.userAgent.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      ja3: [...value.ja3.entries()].sort((a, b) => a[0].localeCompare(b[0])),
    });

    assert.deepEqual(snapshot(first), snapshot(second));
    assert.equal(first.totalHosts, 4);
    assert.equal(first.destination.get('8.8.8.8'), 2);
    assert.equal(first.destination.has('9.9.9.9'), false);
  });
});
