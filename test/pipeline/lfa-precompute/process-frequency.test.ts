import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa process frequency', () => {
  it('counts unique hosts per normalized process name', () => {
    const events = [
      {
        timestamp: '2026-04-12T00:00:00.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS01',
        process_name: 'cmd.exe',
      },
      {
        timestamp: '2026-04-12T00:01:00.000Z',
        source: 'sysmon',
        event_type: 'process_access',
        host: 'WS01',
        source_image: 'C:\\Windows\\System32\\RUNDLL32.EXE',
      },
      {
        timestamp: '2026-04-12T00:02:00.000Z',
        source: 'sysmon',
        event_type: 'process_access',
        host: 'WS02',
        source_image: 'C:\\Windows\\System32\\rundll32.exe',
      },
      {
        timestamp: '2026-04-12T00:03:00.000Z',
        source: 'sysmon',
        event_type: 'image_load',
        host: 'WS03',
        image: '/usr/bin/python3',
      },
    ];

    const tables = precomputeLfa(events as never[]);

    assert.equal(tables.totalHosts, 3);
    assert.equal(tables.process.get('cmd.exe'), 1);
    assert.equal(tables.process.get('rundll32.exe'), 2);
    assert.equal(tables.process.get('python3'), 1);
    assert.equal(prevalence(tables.process, 'rundll32.exe', tables.totalHosts), 2 / 3);
    assert.equal(prevalence(tables.process, 'cmd.exe', tables.totalHosts), 1 / 3);
    assert.equal(rarity(tables.process, 'rundll32.exe', tables.totalHosts), 1 - (2 / 3));
    assert.equal(rarity(tables.process, 'cmd.exe', tables.totalHosts), 1 - (1 / 3));
  });
});
