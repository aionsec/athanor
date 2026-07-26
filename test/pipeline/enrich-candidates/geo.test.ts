import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyLfaTables } from '../../../src/pipeline/types/lfa-tables.js';
import type { PreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';
import { enrichCandidates } from '../../../src/pipeline/enrich-candidates/index.js';

const beacon = {
  candidate_id: 'BCN-1',
  type: 'beacon',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  src_ip: '10.0.0.5',
  dest_ip: '198.51.100.25',
  dest_port: 443,
  process_name: null,
  process_id: null,
  enrichment: {},
  evidence: {
    constituent_event_ids: ['evt-1'],
  },
} as unknown as PreEnrichmentCandidate;

describe('enrichCandidates geo', () => {
  it('stamps geo_country and geo_asn for mapped destination IPs', () => {
    const enriched = enrichCandidates([beacon], createEmptyLfaTables(1), {
      candidateType: 'beacon',
      geoDb: new Map([
        ['198.51.100.25', { country: 'US', asn: 'AS13335' }],
      ]),
    });

    assert.equal(enriched[0].enrichment.geo_country, 'US');
    assert.equal(enriched[0].enrichment.geo_asn, 'AS13335');
  });
});
