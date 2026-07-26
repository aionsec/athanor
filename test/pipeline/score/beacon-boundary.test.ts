import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { ConnLogEvent } from '../../../src/schema/events.js';
import { scoreBeaconCandidates, resetCandidateCounter } from '../../../src/pipeline/score/beacon.js';
import { isPreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';

function makeConn(i: number): ConnLogEvent {
  const ts = new Date(Date.parse('2026-04-11T00:00:00.000Z') + i * 60_000).toISOString();
  return {
    id: `evt-${String(i + 1).padStart(5, '0')}`,
    timestamp: ts,
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.1',
    dest_ip: '8.8.8.8',
    dest_port: 443,
    proto: 'tcp',
    duration: 0.12,
    orig_bytes: 100,
    resp_bytes: 120,
  };
}

describe('Beacon scorer boundary contract', () => {
  it('emits PreEnrichmentCandidate shape with empty enrichment', () => {
    resetCandidateCounter();
    const events = Array.from({ length: 130 }, (_, idx) => makeConn(idx));
    const candidates = scoreBeaconCandidates(events);

    assert.ok(candidates.length > 0, 'expected at least one beacon candidate');
    for (const candidate of candidates) {
      assert.equal(isPreEnrichmentCandidate(candidate), true);
      assert.deepEqual(candidate.enrichment, {});
    }
  });
});
