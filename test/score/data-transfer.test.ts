import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scoreDataTransferCandidates, resetCandidateCounter } from '../../src/pipeline/score/data-transfer.js';
import type { ConnLogEvent } from '../../src/schema/events.js';

function deterministicJitterUnit(index: number): number {
  const sequence = [-0.8, -0.4, 0, 0.4, 0.8];
  return sequence[index % sequence.length];
}

function makeConnEntries(
  count: number,
  opts: {
    srcIp?: string;
    destIp?: string;
    destPort?: number;
    origBytes?: number;
    respBytes?: number;
    origBytesJitter?: number;
    respBytesJitter?: number;
    intervalSec?: number;
    service?: string;
  } = {},
): ConnLogEvent[] {
  const {
    srcIp = '10.0.0.1', destIp = '192.168.1.1', destPort = 443,
    origBytes = 50000, respBytes = 5000, origBytesJitter = 0, respBytesJitter = 0,
    intervalSec = 60, service = 'ssl',
  } = opts;
  const entries: ConnLogEvent[] = [];
  const baseTime = new Date('2025-07-14T06:00:00Z').getTime();
  for (let i = 0; i < count; i++) {
    const jitterUnit = deterministicJitterUnit(i);
    const obJ = origBytes * (origBytesJitter / 100) * jitterUnit;
    const rbJ = respBytes * (respBytesJitter / 100) * jitterUnit;
    entries.push({
      id: `evt-${String(i + 1).padStart(5, '0')}`,
      timestamp: new Date(baseTime + i * intervalSec * 1000).toISOString(),
      source: 'zeek',
      event_type: 'conn',
      src_ip: srcIp,
      dest_ip: destIp,
      dest_port: destPort,
      proto: 'tcp',
      orig_bytes: Math.max(0, Math.round(origBytes + obJ)),
      resp_bytes: Math.max(0, Math.round(respBytes + rbJ)),
      duration: 1.5,
      service,
    } as ConnLogEvent);
  }
  return entries;
}

describe('Data Transfer: PCR aggregate', () => {
  it('upload-heavy → positive PCR', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result.length, 1);
    assert.ok(result[0].pcr_aggregate > 0.9);
    assert.ok(result[0].pcr_aggregate_raw > 0.9);
  });

  it('download-heavy below threshold → no candidate', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 1000, respBytes: 100000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result.length, 0);
  });

  it('download-heavy above threshold → PCR clipped to 0', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(100, { origBytes: 20000, respBytes: 100000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result.length, 1);
    assert.ok(result[0].pcr_aggregate_raw < 0);
    assert.equal(result[0].pcr_aggregate, 0);
  });

  it('symmetric → PCR near 0', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(100, { origBytes: 50000, respBytes: 50000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result.length, 1);
    assert.ok(Math.abs(result[0].pcr_aggregate_raw) < 0.1);
  });
});

describe('Data Transfer: PCR consistency', () => {
  it('consistent upload → high consistency', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(50, {
      origBytes: 100000, respBytes: 1000,
      origBytesJitter: 2, respBytesJitter: 2,
    });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].pcr_consistency > 0.9,
      `consistency ${result[0].pcr_consistency} should be > 0.9`);
  });
});

describe('Data Transfer: volume normalization', () => {
  it('above cap → 1.0', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(200, { origBytes: 1048576, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result[0].bytes_out_total_norm, 1);
  });

  it('below cap → proportional', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(20, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].bytes_out_total_norm > 0 && result[0].bytes_out_total_norm < 0.05);
  });
});

describe('Data Transfer: burstiness', () => {
  it('one dominant connection → high', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(20, { origBytes: 1000, respBytes: 500 });
    entries[0].orig_bytes = 5000000;
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].burstiness > 0.9);
  });

  it('even distribution → low', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(50, {
      origBytes: 100000, respBytes: 1000, origBytesJitter: 5,
    });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].burstiness < 0.1);
  });
});

describe('Data Transfer: composite score', () => {
  it('strong exfil → high', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(10, { origBytes: 20000000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].data_transfer_score > 0.8);
  });

  it('download-heavy → low despite volume', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(100, { origBytes: 20000, respBytes: 500000 });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].data_transfer_score < 0.5);
  });

  it('bounded [0, 1]', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(50, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].data_transfer_score >= 0 && result[0].data_transfer_score <= 1);
  });

  it('upload beats symmetric', () => {
    resetCandidateCounter();
    const upload = makeConnEntries(50, { origBytes: 100000, respBytes: 1000 });
    const uploadR = scoreDataTransferCandidates(upload);

    resetCandidateCounter();
    const sym = makeConnEntries(50, { origBytes: 100000, respBytes: 100000 });
    const symR = scoreDataTransferCandidates(sym);

    assert.ok(uploadR[0].data_transfer_score > symR[0].data_transfer_score);
  });
});

describe('Data Transfer: minimum threshold', () => {
  it('below 1MB → no candidate', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(5, { origBytes: 10000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result.length, 0);
  });
});

describe('Data Transfer: entity key', () => {
  it('different dest_ips → separate candidates', () => {
    resetCandidateCounter();
    const e1 = makeConnEntries(30, { destIp: '1.2.3.4', origBytes: 100000, respBytes: 1000 });
    const e2 = makeConnEntries(30, { destIp: '5.6.7.8', origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates([...e1, ...e2]);
    assert.equal(result.length, 2);
  });
});

describe('Data Transfer: informational fields', () => {
  it('transfer rate computed', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].transfer_rate_bps > 0);
  });

  it('protocol distribution populated', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000, service: 'ssl' });
    const result = scoreDataTransferCandidates(entries);
    assert.ok(result[0].protocol_distribution['ssl'] > 0);
  });

  it('deviation null without baseline', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result[0].bytes_out_deviation, null);
  });
});

describe('Data Transfer: evidence and attribution', () => {
  it('event IDs preserved', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result[0].evidence.constituent_event_ids.length, 30);
  });

  it('attribution null', () => {
    resetCandidateCounter();
    const entries = makeConnEntries(30, { origBytes: 100000, respBytes: 1000 });
    const result = scoreDataTransferCandidates(entries);
    assert.equal(result[0].process_name, null);
    assert.equal(result[0].process_id, null);
  });
});

describe('Data Transfer: sort order', () => {
  it('sorted by score descending', () => {
    resetCandidateCounter();
    const high = makeConnEntries(50, { destIp: '1.1.1.1', origBytes: 500000, respBytes: 1000 });
    const low = makeConnEntries(50, { destIp: '2.2.2.2', origBytes: 50000, respBytes: 50000 });
    const result = scoreDataTransferCandidates([...high, ...low]);
    assert.equal(result.length, 2);
    assert.ok(result[0].data_transfer_score >= result[1].data_transfer_score);
  });
});
