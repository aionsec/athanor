import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { enrichEvents } from '../../../src/enrich-events/index.js';

describe('enrich-events integration', () => {
  it('stamps only applicable Stage-2 enrichment keys and remains idempotent', () => {
    const events = [
      {
        id: 'evt-1',
        timestamp: '2026-04-13T13:00:00.000Z', // Monday
        source: 'zeek',
        event_type: 'conn',
        src_ip: '10.0.0.1',
        dest_ip: '8.8.8.8',
        dest_port: 443,
        proto: 'tcp',
      },
      {
        id: 'evt-2',
        timestamp: '2026-04-12T13:00:00.000Z', // Sunday
        source: 'sysmon',
        event_type: 'process_create',
        src_ip: '10.0.0.2',
        host: 'WKSTN-01',
        event_id: 1,
        process_name: 'powershell.exe',
        process_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        process_id: 4242,
        process_guid: '{232650E5-CB4B-6CAE-0863-D26A9236A364}',
        parent_process_name: 'explorer.exe',
        parent_process_path: 'C:\\Windows\\explorer.exe',
        parent_process_id: 1111,
        parent_process_guid: '{132650E5-CB4B-6CAE-0863-D26A9236A111}',
        command_line: 'powershell.exe -enc AAAA',
        user: 'CORP\\analyst',
      },
    ];

    const once = enrichEvents(events);
    const twice = enrichEvents<(typeof events)[number]>(once);

    assert.equal(typeof once[0].enrichment, 'object');
    assert.equal(typeof once[1].enrichment, 'object');
    assert.deepEqual(
      Object.keys(once[0].enrichment).sort((left, right) => left.localeCompare(right)),
      ['business_hours'],
    );
    assert.deepEqual(
      Object.keys(once[1].enrichment).sort((left, right) => left.localeCompare(right)),
      ['account_type', 'business_hours', 'filesec_match', 'lolbas_match', 'persistence_path_class', 'security_tool_name'],
    );
    assert.equal(once[0].enrichment.business_hours, true);
    assert.equal(once[1].enrichment.business_hours, false);
    assert.equal(once[0].enrichment.lolbas_match, undefined);
    assert.equal(once[1].enrichment.lolbas_match, null);
    assert.equal(once[1].enrichment.filesec_match, null);
    assert.equal(once[1].enrichment.persistence_path_class, null);
    assert.equal(once[1].enrichment.security_tool_name, null);
    assert.equal(once[1].enrichment.account_type, null);
    assert.deepEqual(twice, once);
  });
});
