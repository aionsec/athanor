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
  time_window_end: '2026-04-11T02:00:00.000Z',
  src_ip: '10.0.0.5',
  dest_ip: '198.51.100.25',
  dest_port: 443,
  process_name: null,
  process_id: null,
  enrichment: {},
  evidence: {
    constituent_event_ids: ['evt-1', 'evt-2', 'evt-3'],
  },
} as unknown as PreEnrichmentCandidate;

const events: PostEnrichmentEvent[] = [
  {
    id: 'evt-1',
    timestamp: '2026-04-11T00:00:00.000Z',
    source: 'zeek',
    event_type: 'http',
    src_ip: '10.0.0.5',
    dest_ip: '198.51.100.25',
    http_host: 'api.bad.example',
    http_user_agent: 'beacon-ua',
    enrichment: { business_hours: true },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-2',
    timestamp: '2026-04-11T00:05:00.000Z',
    source: 'zeek',
    event_type: 'ssl',
    src_ip: '10.0.0.5',
    dest_ip: '198.51.100.25',
    ja3_hash: 'ja3-abc',
    server_name: null,
    enrichment: { business_hours: false },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-3',
    timestamp: '2026-04-11T00:06:00.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.5',
    dest_ip: '198.51.100.25',
    dest_port: 443,
    proto: 'tcp',
    enrichment: { business_hours: true },
  } as unknown as PostEnrichmentEvent,
];

describe('enrichCandidates rarity + event-derived labels', () => {
  it('stamps rarity, first_seen, business_hours_proportion, lots_match, missing_sni', () => {
    const lfa = createEmptyLfaTables(4);
    lfa.destination.set('198.51.100.25', 1);
    lfa.domain.set('api.bad.example', 2);
    lfa.userAgent.set('beacon-ua', 1);
    lfa.ja3.set('ja3-abc', 3);

    const enriched = enrichCandidates([candidate], lfa, {
      candidateType: 'beacon',
      events,
      lotsSet: new Set(['api.bad.example']),
    });

    const item = enriched[0].enrichment;
    assert.deepEqual(item.destination_frequency, {
      entity: '198.51.100.25',
      host_count: 1,
      population_host_count: 4,
      prevalence: 0.25,
      rarity_score: 0.75,
      rarity_bucket: 'uncommon',
    });
    assert.equal(item.destination_rarity, 0.75);
    assert.deepEqual(item.domain_frequency, {
      entity: 'api.bad.example',
      host_count: 2,
      population_host_count: 4,
      prevalence: 0.5,
      rarity_score: 0.5,
      rarity_bucket: 'common',
    });
    assert.equal(item.domain_rarity, 0.5);
    assert.deepEqual(item.user_agent_frequency, {
      entity: 'beacon-ua',
      host_count: 1,
      population_host_count: 4,
      prevalence: 0.25,
      rarity_score: 0.75,
      rarity_bucket: 'uncommon',
    });
    assert.equal(item.user_agent_rarity, 0.75);
    assert.deepEqual(item.ja3_frequency, {
      entity: 'ja3-abc',
      host_count: 3,
      population_host_count: 4,
      prevalence: 0.75,
      rarity_score: 0.25,
      rarity_bucket: 'common',
    });
    assert.equal(item.ja3_rarity, 0.25);
    assert.equal(item.business_hours_proportion, 2 / 3);
    assert.equal(item.first_seen, '2026-04-11T00:00:00.000Z');
    assert.equal(item.lots_match, true);
    assert.equal(item.missing_sni, true);
  });
});
