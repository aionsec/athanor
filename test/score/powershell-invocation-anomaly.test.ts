import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ImageLoadEvent, ProcessCreateEvent, TelemetryEvent } from '../../src/schema/events.js';
import {
  DEFAULT_POWERSHELL_INVOCATION_CONFIG,
  loadPowerShellParentHardExclusionsFile,
  resetCandidateCounter,
  scorePowerShellInvocationAnomalyCandidates,
  type PowerShellInvocationConfig,
} from '../../src/pipeline/score/powershell-invocation-anomaly.js';

const BASE_TS = Date.parse('2025-07-14T06:00:00.000Z');

function ts(offsetSec: number): string {
  return new Date(BASE_TS + offsetSec * 1000).toISOString();
}

function makeProcessCreateEvent(opts: {
  id: string;
  offsetSec?: number;
  host?: string;
  processName?: string;
  processPath?: string;
  processId?: number;
  processGuid?: string;
  parentProcessName?: string;
  parentProcessPath?: string;
  parentProcessGuid?: string;
  originalFileName?: string | null;
  description?: string | null;
  company?: string | null;
  commandLine?: string;
}): ProcessCreateEvent {
  return {
    id: opts.id,
    timestamp: ts(opts.offsetSec ?? 0),
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: opts.host ?? 'wkstn-01.corp.local',
    process_name: opts.processName ?? 'dropper.exe',
    process_path: opts.processPath ?? 'C:\\Users\\Public\\dropper.exe',
    process_id: opts.processId ?? 4242,
    process_guid: opts.processGuid ?? '{11111111-1111-1111-1111-111111111111}',
    parent_process_name: opts.parentProcessName ?? 'winword.exe',
    parent_process_path: opts.parentProcessPath ?? 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    parent_process_id: 3312,
    parent_process_guid: opts.parentProcessGuid ?? '{22222222-2222-2222-2222-222222222222}',
    user: 'CORP\\alice',
    integrity_level: 'Medium',
    original_file_name: opts.originalFileName ?? null,
    description: opts.description ?? null,
    product: 'Microsoft Windows',
    company: opts.company ?? null,
    command_line: opts.commandLine ?? 'dropper.exe -NoProfile',
  };
}

function makeImageLoadEvent(opts: {
  id: string;
  offsetSec?: number;
  host?: string;
  processGuid?: string;
  imageLoaded?: string;
}): ImageLoadEvent {
  return {
    id: opts.id,
    timestamp: ts(opts.offsetSec ?? 0),
    source: 'sysmon',
    event_type: 'image_load',
    event_id: 7,
    host: opts.host ?? 'wkstn-01.corp.local',
    process_name: 'dropper.exe',
    image: 'C:\\Users\\Public\\dropper.exe',
    process_id: 4242,
    process_guid: opts.processGuid ?? '{11111111-1111-1111-1111-111111111111}',
    image_loaded: opts.imageLoaded ?? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\System.Management.Automation.dll',
    signed: 'true',
    signature: 'Microsoft Windows',
    signature_status: 'Valid',
  };
}

function withConfig(overrides: Partial<PowerShellInvocationConfig>): PowerShellInvocationConfig {
  return {
    ...DEFAULT_POWERSHELL_INVOCATION_CONFIG,
    ...overrides,
  };
}

describe('PowerShell Invocation scorer: core scoring', () => {
  it('computes max-of-dimensions and tie-breaks dominant dimension rename > custom_host > parent > commandline', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-1',
        originalFileName: 'PowerShell.EXE',
        commandLine: 'dropper.exe -NoProfile -STA -WindowStyle Hidden -Enc SQBFAFgA',
      }),
      makeImageLoadEvent({ id: 'evt-2', offsetSec: 2 }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events);
    assert.equal(candidate.rename_suspicion, 1.0);
    assert.equal(candidate.commandline_suspicion, 1.0);
    assert.equal(candidate.powershell_invocation_anomaly_score, 1.0);
    assert.equal(candidate.dominant_dimension, 'rename');
  });

  it('honors min_dimension_score suppression threshold', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-3',
        processName: 'powershell.exe',
        processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        parentProcessName: 'cmd.exe',
        parentProcessPath: 'C:\\Windows\\System32\\cmd.exe',
        originalFileName: 'PowerShell.EXE',
        commandLine: 'powershell.exe -EncodedCommand SQBFAFgA',
      }),
    ];
    const strict = withConfig({ min_dimension_score: 0.50 });
    const permissive = withConfig({ min_dimension_score: 0.30 });
    assert.equal(scorePowerShellInvocationAnomalyCandidates(events, strict).length, 0);
    assert.equal(scorePowerShellInvocationAnomalyCandidates(events, permissive).length, 1);
  });

  it('emits encoded-command entropy and cmdline length for an -EncodedCommand invocation', () => {
    resetCandidateCounter();
    const commandLine = 'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-enc-1',
        originalFileName: 'PowerShell.EXE',
        commandLine,
      }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events);
    assert.notEqual(candidate.encoded_command_entropy, null);
    assert.ok((candidate.encoded_command_entropy as number) > 0);
    assert.equal(candidate.cmdline_length, commandLine.length);
  });

  it('emits null encoded-command entropy when no encoded command is present', () => {
    resetCandidateCounter();
    const commandLine = 'dropper.exe -Version 2 -Command whoami';
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-enc-2',
        commandLine,
      }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events);
    assert.equal(candidate.encoded_command_entropy, null);
    assert.equal(candidate.cmdline_length, commandLine.length);
  });

  it('is deterministic across repeated runs after counter reset', () => {
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-4',
        commandLine: 'dropper.exe -Version 2 -Command whoami',
      }),
    ];
    resetCandidateCounter();
    const first = scorePowerShellInvocationAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    resetCandidateCounter();
    const second = scorePowerShellInvocationAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    assert.deepEqual(second, first);
  });
});

describe('PowerShell Invocation scorer: EID7 correlation and data quality', () => {
  it('correlates EID7 image load within the configured window', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({ id: 'evt-5' }),
      makeImageLoadEvent({ id: 'evt-6', offsetSec: 20 }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events, withConfig({
      custom_host_correlation_window_ms: 30_000,
    }));
    assert.equal(candidate.sma_dll_loaded, true);
    assert.equal(candidate.evidence.constituent_event_ids.length, 2);
    assert.equal(candidate.time_window_start, ts(0));
    assert.equal(candidate.time_window_end, ts(20));
  });

  it('uses min/max timestamps across constituent evidence when correlated image_load is earlier', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({ id: 'evt-6a' }),
      makeImageLoadEvent({ id: 'evt-6b', offsetSec: -5 }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events, withConfig({
      custom_host_correlation_window_ms: 30_000,
    }));

    assert.equal(candidate.sma_dll_loaded, true);
    assert.equal(candidate.evidence.constituent_event_ids.length, 2);
    assert.equal(candidate.time_window_start, ts(-5));
    assert.equal(candidate.time_window_end, ts(0));
  });

  it('does not correlate EID7 image load outside the window', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({ id: 'evt-7' }),
      makeImageLoadEvent({ id: 'evt-8', offsetSec: 40 }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events, withConfig({
      custom_host_correlation_window_ms: 30_000,
    }));
    assert.equal(candidate.sma_dll_loaded, false);
    assert.equal(candidate.custom_host_suspicion, 0.0);
    assert.equal(candidate.data_quality_flags.includes('custom_host_uncheckable'), false);
    assert.equal(candidate.time_window_start, ts(0));
    assert.equal(candidate.time_window_end, ts(0));
  });

  it('flags custom_host_uncheckable when no image_load telemetry exists', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-9',
        commandLine: 'dropper.exe -Version 2 -Command whoami',
      }),
    ];
    const [candidate] = scorePowerShellInvocationAnomalyCandidates(events);
    assert.equal(candidate.data_quality_flags.includes('custom_host_uncheckable'), true);
  });
});

describe('PowerShell Invocation scorer: pre-filters', () => {
  it('drops hard-excluded parent path before scoring', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-10',
        parentProcessName: 'ccmexec.exe',
        parentProcessPath: 'C:\\Windows\\CCM\\ccmexec.exe',
        commandLine: 'powershell.exe -Version 2',
      }),
    ];
    const result = scorePowerShellInvocationAnomalyCandidates(events);
    assert.equal(result.length, 0);
  });

  it('does not drop basename spoof outside trusted path', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-11',
        parentProcessName: 'ccmexec.exe',
        parentProcessPath: 'C:\\Users\\Public\\ccmexec.exe',
        commandLine: 'dropper.exe -Version 2',
      }),
    ];
    const result = scorePowerShellInvocationAnomalyCandidates(events);
    assert.equal(result.length, 1);
  });

  it('drops vendor whitelist matches before scoring', () => {
    resetCandidateCounter();
    const events: TelemetryEvent[] = [
      makeProcessCreateEvent({
        id: 'evt-12',
        parentProcessPath: 'C:\\Program Files\\AzureConnectedMachineAgent\\1.0\\gc_worker.exe',
        commandLine: 'powershell.exe -Version 2',
      }),
    ];
    const cfg = withConfig({
      vendor_pairs: [
        {
          parent_process_path_pattern: 'c:\\program files\\azureconnectedmachineagent\\*\\gc_worker.exe',
          command_line_pattern: '*powershell*',
        },
      ],
    });
    const result = scorePowerShellInvocationAnomalyCandidates(events, cfg);
    assert.equal(result.length, 0);
  });
});

describe('PowerShell Invocation scorer: config validation', () => {
  it('rejects unanchored hard exclusion regex patterns', () => {
    const dir = mkdtempSync(join(tmpdir(), 'psi-hard-exclusions-'));
    const path = join(dir, 'bad-hard-exclusions.json');
    writeFileSync(path, JSON.stringify([{ source: 'bad', regex: 'C:\\\\Windows\\\\CCM\\\\.*' }], null, 2), 'utf-8');

    assert.throws(
      () => loadPowerShellParentHardExclusionsFile(path),
      /Unanchored hard-exclusion regex/,
    );
  });
});
