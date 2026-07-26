import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDataTransferDistillation } from '../../../src/run/runners/data-transfer-distillation.js';
import { loadEvents } from '../../../src/schema/events.js';

function buildConnEvent(idx: number): Record<string, unknown> {
  const base = Date.parse('2026-04-11T00:00:00.000Z');
  const timestamp = new Date(base + idx * 15 * 60 * 1000).toISOString();
  return {
    id: `evt-conn-${String(idx + 1).padStart(3, '0')}`,
    timestamp,
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.10.10.42',
    dest_ip: '203.0.113.77',
    dest_port: 443,
    proto: 'tcp',
    service: 'ssl',
    conn_state: 'SF',
    duration: 1200,
    orig_bytes: 2_000_000,
    resp_bytes: 50_000,
  };
}

describe('runDataTransferDistillation smoke', () => {
  it('emits Data Transfer candidates with Stage 4 enrichment populated', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'data-transfer-distillation-'));
    const eventsPath = join(dir, 'events.json');

    const connEvents = Array.from({ length: 8 }, (_, idx) => buildConnEvent(idx));
    await writeFile(eventsPath, JSON.stringify(connEvents, null, 2));

    const out = runDataTransferDistillation(await loadEvents(eventsPath));

    assert.ok(out.length >= 1);
    assert.equal(out[0].type, 'data_transfer');
    assert.equal(typeof out[0].enrichment.destination_rarity, 'number');
    assert.equal(typeof out[0].enrichment.business_hours_proportion, 'number');
    assert.equal(typeof out[0].enrichment.first_seen, 'string');
    assert.equal(typeof out[0].enrichment.threat_intel_match, 'boolean');
  });
});
