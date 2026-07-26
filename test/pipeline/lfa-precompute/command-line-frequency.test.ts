import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa command line frequency', () => {
  it('counts unique hosts per normalized (process_name, command_line) tuple', () => {
    const events = [
      {
        timestamp: '2026-04-12T00:00:00.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS01',
        process_name: 'PowerShell.EXE',
        command_line: '  powershell.exe   -NoP -w hidden  ',
      },
      {
        timestamp: '2026-04-12T00:00:05.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS02',
        source_image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        command_line: 'powershell.exe -nop -w hidden',
      },
      {
        timestamp: '2026-04-12T00:00:10.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'WS03',
        process_name: 'cmd.exe',
        command_line: 'cmd.exe /c whoami',
      },
    ];

    const tables = precomputeLfa(events as never[]);

    const psEntity = 'powershell.exe\x1fpowershell.exe -nop -w hidden';
    const cmdEntity = 'cmd.exe\x1fcmd.exe /c whoami';

    assert.equal(tables.totalHosts, 3);
    assert.equal(tables.commandLine.get(psEntity), 2);
    assert.equal(tables.commandLine.get(cmdEntity), 1);
    assert.equal(prevalence(tables.commandLine, psEntity, tables.totalHosts), 2 / 3);
    assert.equal(prevalence(tables.commandLine, cmdEntity, tables.totalHosts), 1 / 3);
    assert.equal(rarity(tables.commandLine, psEntity, tables.totalHosts), 1 - (2 / 3));
    assert.equal(rarity(tables.commandLine, cmdEntity, tables.totalHosts), 1 - (1 / 3));
  });
});
