import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ProcessCreateEvent } from '../../src/schema/events.js';
import {
  DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG,
  resetCandidateCounter,
  scoreUnusualParentChildAnomalyCandidates,
  type UnusualParentChildAnomalyConfig,
} from '../../src/pipeline/score/unusual-parent-child-anomaly.js';
import { loadUnusualParentChildWhitelistFile } from '../../src/pipeline/score/unusual-parent-child-anomaly-taxonomy.js';

const BASE_TS = Date.parse('2026-04-15T00:00:00.000Z');

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
  parentProcessId?: number;
  parentProcessGuid?: string;
  commandLine?: string;
}): ProcessCreateEvent {
  return {
    id: opts.id,
    timestamp: ts(opts.offsetSec ?? 0),
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: opts.host ?? 'wkstn-01.corp.local',
    process_name: opts.processName ?? 'powershell.exe',
    process_path: opts.processPath ?? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    process_id: opts.processId ?? 4200,
    process_guid: opts.processGuid ?? '{11111111-1111-1111-1111-111111111111}',
    parent_process_name: opts.parentProcessName ?? 'WINWORD.EXE',
    parent_process_path: opts.parentProcessPath ?? 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    parent_process_id: opts.parentProcessId ?? 3312,
    parent_process_guid: opts.parentProcessGuid ?? '{22222222-2222-2222-2222-222222222222}',
    user: 'CORP\\alice',
    integrity_level: 'Medium',
    original_file_name: 'PowerShell.EXE',
    description: 'Windows PowerShell',
    product: 'Microsoft Windows',
    company: 'Microsoft Corporation',
    command_line: opts.commandLine ?? 'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA',
  };
}

function withConfig(overrides: Partial<UnusualParentChildAnomalyConfig> = {}): UnusualParentChildAnomalyConfig {
  return {
    ...DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG,
    taxonomy: new Map(
      Array.from(DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG.taxonomy.entries()).map(([key, entries]) => ([
        key,
        [...entries],
      ])),
    ),
    whitelist: [...DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG.whitelist],
    suspicious_children: new Set(DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG.suspicious_children),
    ...overrides,
  };
}

describe('Unusual Parent-Child scorer: core scoring contract', () => {
  it('emits candidate for suspicious office -> powershell pair with critical score', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({ id: 'evt-upc-1' }),
    ];

    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidate.type, 'unusual_parent_child_anomaly');
    assert.equal(candidate.tier, 'critical');
    assert.equal(candidate.parent_category, 'office');
    assert.equal(candidate.child_category, 'powershell');
    assert.equal(candidate.parent_child_tradecraft_tier, 0.95);
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.95);
    assert.equal(candidate.has_suspicious_commandline_flag, true);
  });

  it('suppresses low-score rows below min_emit_score', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-2',
        processName: 'cmd.exe',
        processPath: 'C:\\Windows\\System32\\cmd.exe',
        parentProcessName: 'svchost.exe',
        parentProcessPath: 'C:\\Windows\\System32\\svchost.exe',
        commandLine: 'cmd.exe /c whoami',
      }),
    ];

    const strict = withConfig({ min_emit_score: 0.30 });
    const permissive = withConfig({ min_emit_score: 0.20 });

    assert.equal(scoreUnusualParentChildAnomalyCandidates(events, strict).length, 0);
    assert.equal(scoreUnusualParentChildAnomalyCandidates(events, permissive).length, 1);
  });

  it('emits unknown fallback score when taxonomy parent-child pair is missing', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-3',
        processName: 'cmd.exe',
        processPath: 'C:\\Windows\\System32\\cmd.exe',
        parentProcessName: 'customparent.exe',
        parentProcessPath: 'C:\\Users\\Public\\customparent.exe',
        commandLine: 'cmd.exe /c dir',
      }),
    ];

    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidate.tier, 'unknown');
    assert.equal(candidate.parent_category, 'unknown');
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.3);
  });
});

describe('Unusual Parent-Child scorer: whitelist and path strictness', () => {
  it('marks whitelist matches as benign and emits only with permissive gate', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-4',
        processName: 'cmd.exe',
        processPath: 'C:\\Windows\\System32\\cmd.exe',
        parentProcessName: 'ccmexec.exe',
        parentProcessPath: 'C:\\Windows\\CCM\\ccmexec.exe',
        commandLine: 'cmd.exe /c whoami',
      }),
    ];

    assert.equal(scoreUnusualParentChildAnomalyCandidates(events).length, 0);

    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events, withConfig({ min_emit_score: 0.0 }));
    assert.equal(candidate.tier, 'benign');
    assert.equal(candidate.parent_category, 'whitelisted');
    assert.equal(candidate.parent_child_tradecraft_tier, 0);
    assert.equal(candidate.data_quality_flags.includes('whitelist_matched'), true);
  });

  it('does not whitelist basename spoofed path outside trusted regex', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-5',
        processName: 'cmd.exe',
        processPath: 'C:\\Windows\\System32\\cmd.exe',
        parentProcessName: 'ccmexec.exe',
        parentProcessPath: 'C:\\Users\\Public\\ccmexec.exe',
        commandLine: 'cmd.exe /c whoami',
      }),
    ];

    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.notEqual(candidate.tier, 'benign');
    assert.equal(candidate.data_quality_flags.includes('whitelist_matched'), false);
  });

  it('does not emit when child process is outside suspicious child set', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-6',
        processName: 'notepad.exe',
        processPath: 'C:\\Windows\\System32\\notepad.exe',
        commandLine: 'notepad.exe',
      }),
    ];

    assert.equal(scoreUnusualParentChildAnomalyCandidates(events).length, 0);
  });
});

describe('Unusual Parent-Child scorer: parent lookup and determinism', () => {
  it('populates grandparent context from parent process_create event', () => {
    resetCandidateCounter();
    const parent = makeProcessCreateEvent({
      id: 'evt-upc-parent',
      offsetSec: -15,
      processName: 'WINWORD.EXE',
      processPath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
      processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}',
      parentProcessName: 'explorer.exe',
      parentProcessPath: 'C:\\Windows\\explorer.exe',
      parentProcessGuid: '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}',
      commandLine: 'WINWORD.EXE invoice.docm',
    });
    const child = makeProcessCreateEvent({
      id: 'evt-upc-child',
      processGuid: '{cccccccc-cccc-cccc-cccc-cccccccccccc}',
      parentProcessName: 'WINWORD.EXE',
      parentProcessPath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
      parentProcessGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}',
    });

    const [candidate] = scoreUnusualParentChildAnomalyCandidates([parent, child]);
    assert.equal(candidate.grandparent_image, 'C:\\Windows\\explorer.exe');
    assert.equal(candidate.grandparent_process_guid, '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}');
    assert.equal(candidate.data_quality_flags.includes('parent_guid_missing'), false);
  });

  it('flags parent_guid_missing when parent process_create is absent', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-7',
        parentProcessGuid: '{deadbeef-dead-beef-dead-beefdeadbeef}',
      }),
    ];

    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidate.grandparent_image, null);
    assert.equal(candidate.grandparent_process_guid, null);
    assert.equal(candidate.data_quality_flags.includes('parent_guid_missing'), true);
  });

  it('is deterministic after counter reset', () => {
    const events = [
      makeProcessCreateEvent({ id: 'evt-upc-8' }),
    ];

    resetCandidateCounter();
    const first = scoreUnusualParentChildAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    resetCandidateCounter();
    const second = scoreUnusualParentChildAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    assert.deepEqual(second, first);
  });
});

describe('Unusual Parent-Child scorer: node supply-chain additions', () => {
  it('scores node.exe -> powershell.exe as high (0.85) from the taxonomy', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-node-1',
        parentProcessName: 'node.exe',
        parentProcessPath: 'C:\\Program Files\\nodejs\\node.exe',
        processName: 'powershell.exe',
        processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      }),
    ];
    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.ok(candidate, 'expected a candidate for node.exe -> powershell.exe');
    assert.equal(candidate.tier, 'high');
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.85);
  });

  it('emits for an unknown-basename child executed from the npm cache path via path rule (0.85)', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-npmcache-1',
        parentProcessName: 'powershell.exe',
        parentProcessPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        processName: 'node-bridge.exe',
        processPath: 'C:\\Users\\priya.nair\\AppData\\Local\\npm-cache\\_tmp\\node-bridge.exe',
        commandLine: 'node-bridge.exe',
      }),
    ];
    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.ok(candidate, 'expected a candidate via suspicious-child path rule');
    assert.equal(candidate.tier, 'high');
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.85);
  });

  it('does not emit for an unknown child basename on a non-suspicious path', () => {
    resetCandidateCounter();
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-benign-1',
        parentProcessName: 'powershell.exe',
        parentProcessPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        processName: 'some-helper.exe',
        processPath: 'C:\\Program Files\\SomeVendor\\some-helper.exe',
        commandLine: 'some-helper.exe',
      }),
    ];
    assert.equal(scoreUnusualParentChildAnomalyCandidates(events).length, 0);
  });

  it('taxonomy pair wins over path rule when both match', () => {
    resetCandidateCounter();
    // winword.exe -> cmd.exe is a critical (0.95) taxonomy row and cmd.exe is in the default
    // suspicious-children set; put the child on an npm-cache path so both mechanisms match —
    // the taxonomy score (0.95) must win over the path rule (0.85).
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-both-1',
        parentProcessName: 'winword.exe',
        parentProcessPath: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe',
        processName: 'cmd.exe',
        processPath: 'C:\\Users\\x\\AppData\\Local\\npm-cache\\_tmp\\cmd.exe',
        commandLine: 'cmd.exe /c whoami',
      }),
    ];
    const [candidate] = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidate.tier, 'critical');
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.95);
  });

  it('still suppresses a basename-gated whitelisted pair (whitelist unchanged off the path rule)', () => {
    resetCandidateCounter();
    // Regression guard for the path-rule whitelist bypass: the SAME whitelisted parent
    // (standard-path powershell.exe, rule B10) that emits when the child runs from the
    // npm cache must remain whitelist-suppressed when the basename-gated child sits on
    // an ordinary path.
    const events = [
      makeProcessCreateEvent({
        id: 'evt-upc-wl-guard-1',
        parentProcessName: 'powershell.exe',
        parentProcessPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        processName: 'cmd.exe',
        processPath: 'C:\\Windows\\System32\\cmd.exe',
        commandLine: 'cmd.exe /c whoami',
      }),
    ];
    assert.equal(scoreUnusualParentChildAnomalyCandidates(events).length, 0);
  });
});

describe('Unusual Parent-Child scorer: spawn-signature aggregation', () => {
  const NPM_CACHE_IMAGE = 'C:\\Users\\priya.nair\\AppData\\Local\\npm-cache\\_tmp\\node-bridge.exe';

  function makeSpawnObservation(opts: {
    id: string;
    offsetSec: number;
    host: string;
    processGuid: string;
    processId: number;
    processPath?: string;
  }): ProcessCreateEvent {
    return makeProcessCreateEvent({
      id: opts.id,
      offsetSec: opts.offsetSec,
      host: opts.host,
      parentProcessName: 'powershell.exe',
      parentProcessPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      processName: 'node-bridge.exe',
      processPath: opts.processPath ?? NPM_CACHE_IMAGE,
      processId: opts.processId,
      processGuid: opts.processGuid,
      commandLine: 'node-bridge.exe',
    });
  }

  it('collapses duplicate spawn signatures (host-string variants) into one candidate keeping the primary verbatim', () => {
    resetCandidateCounter();
    const events = [
      makeSpawnObservation({
        id: 'evt-upc-agg-1',
        offsetSec: 0,
        host: 'wkstn-01.corp.local',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000001}',
        processId: 5001,
      }),
      makeSpawnObservation({
        id: 'evt-upc-agg-2',
        offsetSec: 30,
        host: '10.10.20.15',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000002}',
        processId: 5002,
      }),
    ];

    const candidates = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidates.length, 1);

    const [candidate] = candidates;
    // Primary = earliest observation; all fields stay the primary's verbatim.
    assert.equal(candidate.host, 'wkstn-01.corp.local');
    assert.equal(candidate.process_guid, '{aaaaaaaa-aaaa-aaaa-aaaa-000000000001}');
    assert.equal(candidate.process_id, 5001);
    assert.equal(candidate.unusual_parent_child_anomaly_score, 0.85);
    // Detection fires at first occurrence: the window is the primary's own, not widened.
    assert.equal(candidate.time_window_start, ts(0));
    assert.equal(candidate.time_window_end, ts(0));
    // Corroborating observations merge into evidence, chronological.
    assert.deepEqual(candidate.evidence.constituent_event_ids, ['evt-upc-agg-1', 'evt-upc-agg-2']);
  });

  it('keeps a distinct signature (different image path) untouched alongside a collapsed group', () => {
    resetCandidateCounter();
    const events = [
      makeSpawnObservation({
        id: 'evt-upc-agg-3',
        offsetSec: 0,
        host: 'wkstn-01.corp.local',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000003}',
        processId: 5003,
      }),
      makeSpawnObservation({
        id: 'evt-upc-agg-4',
        offsetSec: 30,
        host: '10.10.20.15',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000004}',
        processId: 5004,
      }),
      makeSpawnObservation({
        id: 'evt-upc-agg-5',
        offsetSec: 60,
        host: 'wkstn-02.corp.local',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000005}',
        processId: 5005,
        processPath: 'C:\\Users\\bob.smith\\AppData\\Local\\npm-cache\\_tmp\\node-bridge.exe',
      }),
    ];

    const candidates = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidates.length, 2);

    const collapsed = candidates.find(
      (candidate) => candidate.process_guid === '{aaaaaaaa-aaaa-aaaa-aaaa-000000000003}',
    );
    const distinct = candidates.find(
      (candidate) => candidate.process_guid === '{aaaaaaaa-aaaa-aaaa-aaaa-000000000005}',
    );
    assert.ok(collapsed, 'expected the collapsed group led by the earliest observation');
    assert.ok(distinct, 'expected the distinct-signature candidate to survive untouched');
    assert.deepEqual(collapsed.evidence.constituent_event_ids, ['evt-upc-agg-3', 'evt-upc-agg-4']);
    assert.deepEqual(distinct.evidence.constituent_event_ids, ['evt-upc-agg-5']);
    assert.equal(distinct.time_window_start, ts(60));
    assert.equal(distinct.time_window_end, ts(60));
  });

  it('does not collapse the same parent/child/image signature across different users', () => {
    resetCandidateCounter();
    const events = [
      makeSpawnObservation({
        id: 'evt-upc-agg-6',
        offsetSec: 0,
        host: 'wkstn-01.corp.local',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000006}',
        processId: 5006,
      }),
      {
        ...makeSpawnObservation({
          id: 'evt-upc-agg-7',
          offsetSec: 30,
          host: 'wkstn-01.corp.local',
          processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000007}',
          processId: 5007,
        }),
        user: 'CORP\\bob',
      },
    ];

    const candidates = scoreUnusualParentChildAnomalyCandidates(events);
    assert.equal(candidates.length, 2);
    for (const candidate of candidates) {
      assert.equal(candidate.evidence.constituent_event_ids.length, 1);
    }
  });

  it('aggregation is deterministic: same input twice yields identical output, ids included', () => {
    const events = [
      makeSpawnObservation({
        id: 'evt-upc-agg-8',
        offsetSec: 0,
        host: 'wkstn-01.corp.local',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000008}',
        processId: 5008,
      }),
      makeSpawnObservation({
        id: 'evt-upc-agg-9',
        offsetSec: 30,
        host: '10.10.20.15',
        processGuid: '{aaaaaaaa-aaaa-aaaa-aaaa-000000000009}',
        processId: 5009,
      }),
    ];

    resetCandidateCounter();
    const first = scoreUnusualParentChildAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    resetCandidateCounter();
    const second = scoreUnusualParentChildAnomalyCandidates(events).map((candidate) => JSON.stringify(candidate));
    assert.deepEqual(second, first);
  });
});

describe('Unusual Parent-Child scorer: config validation', () => {
  it('rejects unanchored whitelist regex rows', () => {
    const dir = mkdtempSync(join(tmpdir(), 'upc-whitelist-'));
    const path = join(dir, 'whitelist.csv');
    writeFileSync(
      path,
      [
        'id,parent_path_regex,parent_basename,parent_command_line_regex,rationale',
        'B1,C:\\\\Windows\\\\CCM\\\\ccmexec\\.exe,ccmexec.exe,,Missing anchors',
      ].join('\n'),
      'utf-8',
    );

    assert.throws(
      () => loadUnusualParentChildWhitelistFile(path),
      /Unanchored whitelist regex/,
    );
  });
});
