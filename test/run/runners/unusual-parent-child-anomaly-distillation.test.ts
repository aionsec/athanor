import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runUnusualParentChildAnomalyDistillation } from '../../../src/run/runners/unusual-parent-child-anomaly-distillation.js';
import { loadEvents } from '../../../src/schema/events.js';

const BASE_TS = Date.parse('2026-04-15T00:00:00.000Z');

function ts(offsetSec: number): string {
  return new Date(BASE_TS + offsetSec * 1000).toISOString();
}

function makeProcessCreateEvent(opts: {
  id: string;
  offsetSec: number;
  processName: string;
  processPath: string;
  processId: number;
  processGuid: string;
  parentProcessName: string;
  parentProcessPath: string;
  parentProcessId: number;
  parentProcessGuid: string;
  commandLine: string;
}): Record<string, unknown> {
  return {
    id: opts.id,
    timestamp: ts(opts.offsetSec),
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: 'wkstn-01.corp.local',
    process_name: opts.processName,
    process_path: opts.processPath,
    process_id: opts.processId,
    process_guid: opts.processGuid,
    parent_process_name: opts.parentProcessName,
    parent_process_path: opts.parentProcessPath,
    parent_process_id: opts.parentProcessId,
    parent_process_guid: opts.parentProcessGuid,
    user: 'CORP\\analyst',
    integrity_level: 'Medium',
    original_file_name: opts.processName,
    description: opts.processName,
    product: 'Microsoft Windows',
    company: 'Microsoft Corporation',
    command_line: opts.commandLine,
  };
}

describe('runUnusualParentChildAnomalyDistillation smoke', () => {
  it('emits unusual_parent_child_anomaly candidates with expected Stage 4 enrichment labels', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'unusual-parent-child-anomaly-distillation-'));
    const eventsPath = join(dir, 'events.json');

    const parentGuid = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}';
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-parent',
        offsetSec: 0,
        processName: 'WINWORD.EXE',
        processPath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        processId: 3300,
        processGuid: parentGuid,
        parentProcessName: 'explorer.exe',
        parentProcessPath: 'C:\\Windows\\explorer.exe',
        parentProcessId: 1200,
        parentProcessGuid: '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}',
        commandLine: 'WINWORD.EXE invoice.docm',
      }),
      makeProcessCreateEvent({
        id: 'evt-upc-child',
        offsetSec: 2,
        processName: 'powershell.exe',
        processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        processId: 4400,
        processGuid: '{cccccccc-cccc-cccc-cccc-cccccccccccc}',
        parentProcessName: 'WINWORD.EXE',
        parentProcessPath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        parentProcessId: 3300,
        parentProcessGuid: parentGuid,
        commandLine: 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA',
      }),
    ];
    await writeFile(eventsPath, JSON.stringify(events, null, 2));

    const out = runUnusualParentChildAnomalyDistillation(await loadEvents(eventsPath));

    assert.ok(out.length >= 1);
    const candidate = out.find((entry) => entry.type === 'unusual_parent_child_anomaly');
    assert.ok(candidate, 'Expected at least one unusual_parent_child_anomaly candidate');

    assert.equal(typeof candidate.enrichment.first_seen, 'string');
    assert.equal(typeof candidate.enrichment.business_hours_proportion, 'number');
    assert.equal(typeof candidate.enrichment.parent_child_pair_rarity, 'number');
    assert.equal(typeof candidate.enrichment.process_rarity, 'number');

    assert.equal(candidate.enrichment.command_line_rarity, undefined);
    assert.equal(candidate.enrichment.script_block_hash_rarity, undefined);
    assert.equal(candidate.enrichment.destination_rarity, undefined);
  });
});
