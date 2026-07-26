import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { attributeCandidates } from '../../../src/pipeline/attribute/index.js';
import type { PreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';

function mkBaseCandidate(type: string, evidenceIds: string[]) {
  return {
    candidate_id: 'CID-001',
    type,
    time_window_start: '2026-03-09T14:00:00.000Z',
    time_window_end: '2026-03-09T14:01:00.000Z',
    process_name: null,
    process_id: null,
    enrichment: {},
    evidence: { constituent_event_ids: evidenceIds },
  } as unknown as PreEnrichmentCandidate;
}

describe('attributeCandidates', () => {
  it('stamps full attribution from conn -> network_connect -> process_create', () => {
    const events: Array<Record<string, unknown>> = [
      {
        id: 'evt-proc-1',
        timestamp: '2026-03-09T14:00:28.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'DEV-WS03',
        process_guid: '{proc-1}',
        process_name: 'svchost-health.exe',
        process_path: 'C:\\Users\\jane\\AppData\\Local\\Temp\\svchost-health.exe',
        process_id: 5006,
        parent_process_guid: '{proc-parent}',
        parent_process_name: 'powershell.exe',
        parent_process_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        user: 'CORP\\jane',
      },
      {
        id: 'evt-eid3-1',
        timestamp: '2026-03-09T14:00:30.005Z',
        source: 'sysmon',
        event_type: 'network_connect',
        host: 'DEV-WS03',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        process_guid: '{proc-1}',
        process_name: 'svchost-health.exe',
        process_id: 5006,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-conn-1',
        timestamp: '2026-03-09T14:00:30.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        zeek_uid: 'C001',
      },
    ];

    const candidates = [mkBaseCandidate('beacon', ['evt-conn-1'])];
    const result = attributeCandidates(candidates, events);

    assert.equal(result.length, 1);
    const attributed = result[0] as Record<string, unknown>;
    assert.equal(attributed.process_name, 'svchost-health.exe');
    assert.equal(attributed.process_id, 5006);

    const block = attributed.attribution as Record<string, unknown>;
    assert.equal(block.confidence, 'full');
    assert.equal(block.host, 'DEV-WS03');
    assert.equal(block.process_guid, '{proc-1}');
    assert.deepEqual(block.data_quality_flags, []);
  });

  it('resolves ssl evidence through zeek_uid back to conn before EID3 join', () => {
    const events: Array<Record<string, unknown>> = [
      {
        id: 'evt-proc-1',
        timestamp: '2026-03-09T14:00:28.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        host: 'DEV-WS03',
        process_guid: '{proc-1}',
        process_name: 'svchost-health.exe',
        process_id: 5006,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-eid3-1',
        timestamp: '2026-03-09T14:00:30.005Z',
        source: 'sysmon',
        event_type: 'network_connect',
        host: 'DEV-WS03',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        process_guid: '{proc-1}',
        process_name: 'svchost-health.exe',
        process_id: 5006,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-conn-1',
        timestamp: '2026-03-09T14:00:30.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        zeek_uid: 'C001',
      },
      {
        id: 'evt-ssl-1',
        timestamp: '2026-03-09T14:00:30.030Z',
        source: 'zeek',
        event_type: 'ssl',
        zeek_uid: 'C001',
      },
    ];

    const candidates = [mkBaseCandidate('tls_anomaly', ['evt-ssl-1'])];
    const result = attributeCandidates(candidates, events);

    const block = (result[0] as Record<string, unknown>).attribution as Record<string, unknown>;
    assert.equal(block.confidence, 'full');
    assert.equal(block.host, 'DEV-WS03');
    assert.equal(block.process_name, 'svchost-health.exe');
  });

  it('keeps outputs unchanged when the run has no network_connect telemetry', () => {
    const events: Array<Record<string, unknown>> = [
      {
        id: 'evt-conn-1',
        timestamp: '2026-03-09T14:00:30.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
      },
    ];

    const candidates = [mkBaseCandidate('beacon', ['evt-conn-1'])];
    const result = attributeCandidates(candidates, events);

    assert.deepEqual(result, candidates);
  });

  it('marks partial_multi_process when evidence maps to multiple process GUIDs', () => {
    const events: Array<Record<string, unknown>> = [
      {
        id: 'evt-proc-1',
        timestamp: '2026-03-09T14:00:28.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        process_guid: '{proc-1}',
        process_name: 'proc-a.exe',
        process_id: 5001,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-proc-2',
        timestamp: '2026-03-09T14:00:29.000Z',
        source: 'sysmon',
        event_type: 'process_create',
        process_guid: '{proc-2}',
        process_name: 'proc-b.exe',
        process_id: 5002,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-eid3-1',
        timestamp: '2026-03-09T14:00:30.005Z',
        source: 'sysmon',
        event_type: 'network_connect',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        process_guid: '{proc-1}',
        process_name: 'proc-a.exe',
        process_id: 5001,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-eid3-2',
        timestamp: '2026-03-09T14:00:31.005Z',
        source: 'sysmon',
        event_type: 'network_connect',
        src_ip: '10.42.10.45',
        src_port: 49601,
        dest_ip: '185.225.73.217',
        dest_port: 443,
        process_guid: '{proc-2}',
        process_name: 'proc-b.exe',
        process_id: 5002,
        user: 'CORP\\jane',
      },
      {
        id: 'evt-conn-1',
        timestamp: '2026-03-09T14:00:30.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.42.10.45',
        src_port: 49600,
        dest_ip: '185.225.73.217',
        dest_port: 443,
      },
      {
        id: 'evt-conn-2',
        timestamp: '2026-03-09T14:00:31.000Z',
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.42.10.45',
        src_port: 49601,
        dest_ip: '185.225.73.217',
        dest_port: 443,
      },
    ];

    const candidates = [mkBaseCandidate('beacon', ['evt-conn-1', 'evt-conn-2'])];
    const result = attributeCandidates(candidates, events);

    const block = (result[0] as Record<string, unknown>).attribution as Record<string, unknown>;
    assert.equal(block.confidence, 'partial_multi_process');
    assert.deepEqual(block.data_quality_flags, ['multi_process_match']);
  });
});
