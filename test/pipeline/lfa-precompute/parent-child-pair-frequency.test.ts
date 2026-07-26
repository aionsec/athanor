import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa parent-child-pair frequency', () => {
  it('counts unique hosts per normalized (parent, child) process pair', () => {
    const events = [
      {
        timestamp: '2026-04-12T00:00:00.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS01',
        parent_process_name: 'WINWORD.EXE',
        process_name: 'powershell.exe',
      },
      {
        timestamp: '2026-04-12T00:00:10.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS02',
        parent_process_path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        process_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      },
      {
        timestamp: '2026-04-12T00:00:20.000Z',
        source: 'sysmon',
        event_type: 'create_remote_thread',
        host: 'WS03',
        source_image: 'C:\\Windows\\System32\\rundll32.exe',
        target_image: 'C:\\Windows\\explorer.exe',
      },
      {
        timestamp: '2026-04-12T00:00:30.000Z',
        source: 'sysmon',
        event_type: 'create_remote_thread',
        host: 'WS03',
        source_image: 'C:\\Windows\\System32\\RUNDLL32.EXE',
        target_image: 'C:\\Windows\\Explorer.EXE',
      },
    ];

    const tables = precomputeLfa(events as never[]);

    const officeToPowerShell = 'winword.exe\x1fpowershell.exe';
    const rundllToExplorer = 'rundll32.exe\x1fexplorer.exe';

    assert.equal(tables.totalHosts, 3);
    assert.equal(tables.parentChildPair.get(officeToPowerShell), 2);
    assert.equal(tables.parentChildPair.get(rundllToExplorer), 1);
    assert.equal(prevalence(tables.parentChildPair, officeToPowerShell, tables.totalHosts), 2 / 3);
    assert.equal(prevalence(tables.parentChildPair, rundllToExplorer, tables.totalHosts), 1 / 3);
    assert.equal(rarity(tables.parentChildPair, officeToPowerShell, tables.totalHosts), 1 - (2 / 3));
    assert.equal(rarity(tables.parentChildPair, rundllToExplorer, tables.totalHosts), 1 - (1 / 3));
  });
});
