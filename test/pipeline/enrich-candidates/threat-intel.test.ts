import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyLfaTables } from '../../../src/pipeline/types/lfa-tables.js';
import type { PreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';
import { enrichCandidates } from '../../../src/pipeline/enrich-candidates/index.js';

function beaconCandidate(destIp: string, id: string): PreEnrichmentCandidate {
  return {
    candidate_id: id,
    type: 'beacon',
    time_window_start: '2026-04-11T00:00:00.000Z',
    time_window_end: '2026-04-11T01:00:00.000Z',
    src_ip: '10.0.0.5',
    dest_ip: destIp,
    dest_port: 443,
    process_name: null,
    process_id: null,
    enrichment: {},
    evidence: {
      constituent_event_ids: ['evt-1'],
    },
  } as unknown as PreEnrichmentCandidate;
}

describe('enrichCandidates threat intel', () => {
  it('stamps threat_intel_match true/false for Beacon candidates', () => {
    const candidates = [
      beaconCandidate('203.0.113.10', 'BCN-1'),
      beaconCandidate('198.51.100.25', 'BCN-2'),
    ];

    const enriched = enrichCandidates(candidates, createEmptyLfaTables(1), {
      candidateType: 'beacon',
      threatIntelFeed: {
        ips: new Set(['203.0.113.10']),
        domains: new Set(),
        hashes: new Set(),
      },
    });

    assert.equal(enriched[0].enrichment.threat_intel_match, true);
    assert.equal(enriched[1].enrichment.threat_intel_match, false);
  });
});
