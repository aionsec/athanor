import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPowerShellInvocationAnomalyDistillation } from '../../../src/run/runners/powershell-invocation-anomaly-distillation.js';
import { loadEvents } from '../../../src/schema/events.js';

function buildProcessCreateEvent(idx: number): Record<string, unknown> {
  const base = Date.parse('2026-04-12T00:00:00.000Z');
  const timestamp = new Date(base + idx * 90 * 1000).toISOString();
  const seq = String(idx + 1).padStart(3, '0');
  const guid = `{11111111-1111-1111-1111-111111111${seq}}`;

  return {
    id: `evt-psi-proc-${seq}`,
    timestamp,
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: 'ws01.corp.local',
    process_name: 'svchost32.exe',
    process_path: 'C:\\Users\\Public\\svchost32.exe',
    process_id: 4100 + idx,
    process_guid: guid,
    parent_process_name: 'winword.exe',
    parent_process_path: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    parent_process_id: 3044,
    parent_process_guid: '{22222222-2222-2222-2222-222222222222}',
    user: 'CORP\\analyst',
    integrity_level: 'Medium',
    original_file_name: 'PowerShell.EXE',
    description: 'Windows PowerShell',
    product: 'Microsoft Windows',
    company: 'Microsoft Corporation',
    command_line: 'svchost32.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA',
  };
}

function buildImageLoadEvent(idx: number): Record<string, unknown> {
  const base = Date.parse('2026-04-12T00:00:00.000Z');
  const timestamp = new Date(base + idx * 90 * 1000 + 10 * 1000).toISOString();
  const seq = String(idx + 1).padStart(3, '0');
  const guid = `{11111111-1111-1111-1111-111111111${seq}}`;

  return {
    id: `evt-psi-img-${seq}`,
    timestamp,
    source: 'sysmon',
    event_type: 'image_load',
    event_id: 7,
    host: 'ws01.corp.local',
    process_name: 'svchost32.exe',
    image: 'C:\\Users\\Public\\svchost32.exe',
    process_id: 4100 + idx,
    process_guid: guid,
    image_loaded: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\System.Management.Automation.dll',
    signed: 'true',
    signature: 'Microsoft Corporation',
    signature_status: 'Valid',
  };
}

describe('runPowerShellInvocationAnomalyDistillation smoke', () => {
  it('emits powershell_invocation_anomaly candidates with Stage 4 enrichment populated', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'powershell-invocation-anomaly-distillation-'));
    const eventsPath = join(dir, 'events.json');

    const events = [
      buildProcessCreateEvent(0),
      buildImageLoadEvent(0),
      buildProcessCreateEvent(1),
      buildImageLoadEvent(1),
      buildProcessCreateEvent(2),
      buildImageLoadEvent(2),
    ];
    await writeFile(eventsPath, JSON.stringify(events, null, 2));

    const out = runPowerShellInvocationAnomalyDistillation(await loadEvents(eventsPath));

    assert.ok(out.length >= 1);
    const candidate = out.find((entry) => entry.type === 'powershell_invocation_anomaly');
    assert.ok(candidate, 'Expected at least one powershell_invocation_anomaly candidate');

    assert.equal(typeof candidate.enrichment.first_seen, 'string');
    assert.equal(typeof candidate.enrichment.business_hours_proportion, 'number');
    assert.equal(typeof candidate.enrichment.command_line_rarity, 'number');
    assert.equal(typeof candidate.enrichment.parent_child_pair_rarity, 'number');
    if (candidate.enrichment.script_block_hash_rarity !== undefined) {
      assert.equal(typeof candidate.enrichment.script_block_hash_rarity, 'number');
    }

    assert.equal(candidate.enrichment.threat_intel_match, undefined);
    assert.equal(candidate.enrichment.lots_match, undefined);
    assert.equal(candidate.enrichment.destination_rarity, undefined);
  });
});
