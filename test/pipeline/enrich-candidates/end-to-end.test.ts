import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { PostEnrichmentEvent } from '../../../src/pipeline/types/post-enrichment-event.js';
import type { PreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';
import { createEmptyLfaTables } from '../../../src/pipeline/types/lfa-tables.js';
import { enrichCandidates } from '../../../src/pipeline/enrich-candidates/index.js';

const candidate = {
  candidate_id: 'BCN-1',
  type: 'beacon',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  src_ip: '10.0.0.5',
  dest_ip: '203.0.113.10',
  dest_port: 443,
  process_name: null,
  process_id: null,
  enrichment: {},
  evidence: { constituent_event_ids: ['evt-1'] },
} as unknown as PreEnrichmentCandidate;

const events: PostEnrichmentEvent[] = [
  {
    id: 'evt-1',
    timestamp: '2026-04-11T00:00:00.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.5',
    dest_ip: '203.0.113.10',
    dest_port: 443,
    proto: 'tcp',
    enrichment: { business_hours: true },
  } as unknown as PostEnrichmentEvent,
];

describe('enrichCandidates end to end', () => {
  it('is idempotent when run repeatedly on its own output', () => {
    const lfa = createEmptyLfaTables(2);
    lfa.destination.set('203.0.113.10', 1);

    const first = enrichCandidates([candidate], lfa, {
      candidateType: 'beacon',
      events,
      threatIntelFeed: {
        ips: new Set(['203.0.113.10']),
        domains: new Set(),
        hashes: new Set(),
      },
      geoDb: new Map([
        ['203.0.113.10', { country: 'US', asn: 'AS64500' }],
      ]),
    });

    const second = enrichCandidates(first as unknown as PreEnrichmentCandidate[], lfa, {
      candidateType: 'beacon',
      events,
      threatIntelFeed: {
        ips: new Set(['203.0.113.10']),
        domains: new Set(),
        hashes: new Set(),
      },
      geoDb: new Map([
        ['203.0.113.10', { country: 'US', asn: 'AS64500' }],
      ]),
    });

    assert.deepEqual(second, first);
  });
});
