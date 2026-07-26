import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sha256HexForDeterministicIdentity } from '../../src/lib/deterministic-identity.js';

describe('sha256HexForDeterministicIdentity', () => {
  it('stays stable across object key order', () => {
    const first = sha256HexForDeterministicIdentity({
      type: 'beacon',
      dest_ip: '203.0.113.10',
      src_ip: '10.0.0.1',
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
    });

    const second = sha256HexForDeterministicIdentity({
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
      src_ip: '10.0.0.1',
      dest_ip: '203.0.113.10',
      type: 'beacon',
    });

    assert.equal(first, second);
  });

  it('stays stable across array order', () => {
    const first = sha256HexForDeterministicIdentity({
      evidence: { constituent_event_ids: ['evt-1', 'evt-2'] },
      corroborating_sources: [
        { source: 'feed-a', tier: 'T1' },
        { source: 'feed-b', tier: 'T2' },
      ],
    });

    const second = sha256HexForDeterministicIdentity({
      corroborating_sources: [
        { tier: 'T2', source: 'feed-b' },
        { tier: 'T1', source: 'feed-a' },
      ],
      evidence: { constituent_event_ids: ['evt-2', 'evt-1'] },
    });

    assert.equal(first, second);
  });
});
