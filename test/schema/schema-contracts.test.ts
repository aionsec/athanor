import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { BeaconCandidate } from '../../src/schema/candidates.js';
import {
  isPreEnrichmentEvent,
  isPostEnrichmentEvent,
  isPreEnrichmentCandidate,
  isPostEnrichmentCandidate,
} from '../../src/pipeline/types/index.js';
import type { PreEnrichmentCandidate } from '../../src/pipeline/types/pre-enrichment-candidate.js';

// compile-time guard: non-empty enrichment must not satisfy PreEnrichmentCandidate
const _invalidPreCandidate: PreEnrichmentCandidate = {
  ...(null as unknown as BeaconCandidate),
  // @ts-expect-error pre-enrichment candidate must have empty enrichment object
  enrichment: { threat_intel_match: true },
};

const _validPreCandidate: PreEnrichmentCandidate = {
  ...(null as unknown as BeaconCandidate),
  enrichment: {},
};

void _invalidPreCandidate;
void _validPreCandidate;

describe('pipeline schema contracts', () => {
  it('accepts normalized event as PreEnrichmentEvent', () => {
    const event = {
      id: 'evt-1',
      timestamp: '2026-04-11T00:00:00.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
      dest_port: 443,
      proto: 'tcp',
    };
    assert.equal(isPreEnrichmentEvent(event), true);
    assert.equal(isPostEnrichmentEvent(event), false);
  });

  it('accepts post-enrichment event when enrichment object exists', () => {
    const event = {
      id: 'evt-2',
      timestamp: '2026-04-11T00:00:00.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
      dest_port: 443,
      proto: 'tcp',
      enrichment: {
        business_hours: true,
      },
    };

    assert.equal(isPreEnrichmentEvent(event), true);
    assert.equal(isPostEnrichmentEvent(event), true);
  });

  it('accepts pre/post candidate contract boundaries', () => {
    const preCandidate = {
      candidate_id: 'BCN-1111111111111111',
      type: 'beacon',
      time_window_start: '2026-04-11T00:00:00.000Z',
      time_window_end: '2026-04-11T01:00:00.000Z',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
      dest_port: 443,
      regularity: 1,
      mean_interval_sec: 60,
      std_interval_sec: 1,
      jitter_mad: 0.1,
      bytes_out_consistency: 1,
      bytes_in_consistency: 1,
      bytes_out_total: 1000,
      bytes_in_total: 800,
      bytes_ratio: 1.25,
      duration_consistency: 1,
      consecutive_hours: 2,
      session_count: 20,
      time_span_hours: 2,
      histogram_cv: 1,
      bimodal_score: 0,
      histogram_score: 1,
      beacon_score: 0.95,
      process_name: null,
      process_id: null,
      enrichment: {},
      evidence: {
        constituent_event_ids: ['evt-1'],
      },
    };

    const postCandidate = {
      ...preCandidate,
      enrichment: {
        threat_intel_match: true,
      },
    };

    assert.equal(isPreEnrichmentCandidate(preCandidate), true);
    assert.equal(isPostEnrichmentCandidate(preCandidate), true);
    assert.equal(isPreEnrichmentCandidate(postCandidate), false);
    assert.equal(isPostEnrichmentCandidate(postCandidate), true);
  });
});
