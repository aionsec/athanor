import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { enrichEvents } from '../../src/enrich-events/index.js';

describe('enrich-events passthrough contract', () => {
  it('does not mutate non-enrichment event fields', () => {
    const original = {
      id: 'evt-1',
      timestamp: '2026-04-13T13:00:00.000Z',
      source: 'zeek',
      event_type: 'conn',
      src_ip: '10.0.0.1',
      dest_ip: '8.8.8.8',
      dest_port: 443,
      proto: 'tcp',
    };

    const [enriched] = enrichEvents([original]);
    assert.deepEqual({ ...enriched, enrichment: undefined }, { ...original, enrichment: undefined });
    assert.notEqual(enriched, original);
  });
});
