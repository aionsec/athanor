import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { stampProtocolMismatch } from '../../../src/pipeline/enrich-candidates/protocol-mismatch.js';
import type { PostEnrichmentEvent } from '../../../src/pipeline/types/post-enrichment-event.js';

function makeEnrichment(): Record<string, unknown> {
  return {};
}

function makeCandidate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'beacon',
    dest_port: 443,
    enrichment: {},
    ...overrides,
  };
}

function makeConnEvent(overrides: Record<string, unknown> = {}): PostEnrichmentEvent {
  return {
    id: 'evt-1',
    timestamp: '2026-04-19T00:00:00.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.10',
    dest_ip: '203.0.113.1',
    dest_port: 443,
    proto: 'tcp',
    enrichment: {},
    ...overrides,
  } as unknown as PostEnrichmentEvent;
}

describe('protocol mismatch stamper', () => {
  it('stamps false when observed and expected services match', () => {
    const enrichment = makeEnrichment();
    const candidate = makeCandidate({ protocol_service: 'https' });

    stampProtocolMismatch(enrichment, candidate, [makeConnEvent()]);

    assert.equal(enrichment.protocol_mismatch, false);
  });

  it('stamps true when observed and expected services differ', () => {
    const enrichment = makeEnrichment();
    const candidate = makeCandidate();

    stampProtocolMismatch(
      enrichment,
      candidate,
      [makeConnEvent({ service: 'dns' })],
    );

    assert.equal(enrichment.protocol_mismatch, true);
  });

  it('stamps null when no expected service can be resolved from destination port', () => {
    const enrichment = makeEnrichment();
    const candidate = makeCandidate({ dest_port: 9999, protocol_service: 'http' });

    stampProtocolMismatch(enrichment, candidate, [makeConnEvent({ dest_port: 9999, service: 'http' })]);

    assert.equal(enrichment.protocol_mismatch, null);
  });

  it('stamps null when expected service exists but observed service is unresolved', () => {
    const enrichment = makeEnrichment();
    const candidate = makeCandidate({ dest_port: 443 });

    stampProtocolMismatch(enrichment, candidate, [makeConnEvent({ service: '-', proto: 'tcp' })]);

    assert.equal(enrichment.protocol_mismatch, null);
  });

  it('uses event-type fallback when conn service is unavailable', () => {
    const enrichment = makeEnrichment();
    const candidate = makeCandidate({ type: 'dns_anomaly', dest_port: 53 });

    const dnsEvent = {
      id: 'evt-2',
      timestamp: '2026-04-19T00:05:00.000Z',
      source: 'zeek',
      event_type: 'dns',
      src_ip: '10.0.0.10',
      dest_ip: '8.8.8.8',
      dest_port: 53,
      query: 'example.com',
      enrichment: {},
    } as unknown as PostEnrichmentEvent;

    stampProtocolMismatch(enrichment, candidate, [dnsEvent]);

    assert.equal(enrichment.protocol_mismatch, false);
  });
});
