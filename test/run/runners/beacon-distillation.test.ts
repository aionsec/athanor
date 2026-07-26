import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runBeaconDistillation } from '../../../src/run/runners/beacon-distillation.js';
import { enrichEventsForRun } from '../../../src/run/runner-factory.js';
import { loadThreatIntelFeedForDataset } from '../../../src/pipeline/enrich-candidates/threat-intel-loader.js';
import { loadEvents } from '../../../src/schema/events.js';

function buildConnEvent(idx: number, destIp = '203.0.113.10'): Record<string, unknown> {
  const base = Date.parse('2026-04-11T00:00:00.000Z');
  const timestamp = new Date(base + idx * 15 * 60 * 1000).toISOString();
  return {
    id: `evt-conn-${String(idx + 1).padStart(3, '0')}`,
    timestamp,
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.10.10.5',
    dest_ip: destIp,
    dest_port: 443,
    proto: 'tcp',
    duration: 10,
    orig_bytes: 2048,
    resp_bytes: 4096,
  };
}

// A `feed.json` in the alternative indicator-list shape: flat entries keyed on
// `normalized_value` + `match_type`, which is what indicator exports commonly look like.
// See `threat-intel-loader.ts`.
function buildIntelFeed(ip: string): Array<Record<string, unknown>> {
  return [
    {
      normalized_value: ip,
      match_type: 'ioc_ip',
      match_subclass: null,
      source: 'Mandiant',
      source_tier: 'T1_commercial',
      per_indicator_confidence: 90,
      first_seen: '2026-03-05T00:00:00.000Z',
      valid_from: '2026-03-05T00:00:00.000Z',
      valid_until: null,
      tags: ['c2', 'test-fixture'],
      context: 'beacon distillation variant feed test',
      tlp: 'AMBER',
      originating_org: 'Mandiant',
    },
  ];
}

describe('runBeaconDistillation smoke', () => {
  it('emits Beacon candidates with Stage 4 enrichment populated', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'beacon-distillation-'));
    const eventsPath = join(dir, 'events.json');

    const connEvents = Array.from({ length: 12 }, (_, idx) => buildConnEvent(idx));
    const extraEvents = [
      {
        id: 'evt-http-001',
        timestamp: '2026-04-11T00:20:00.000Z',
        source: 'zeek',
        event_type: 'http',
        src_ip: '10.10.10.5',
        dest_ip: '203.0.113.10',
        dest_port: 443,
        http_host: 'api.bad.example',
        http_uri: '/beacon',
        http_user_agent: 'beacon-test-ua',
      },
      {
        id: 'evt-ssl-001',
        timestamp: '2026-04-11T00:25:00.000Z',
        source: 'zeek',
        event_type: 'ssl',
        src_ip: '10.10.10.5',
        dest_ip: '203.0.113.10',
        dest_port: 443,
        server_name: null,
        ja3_hash: 'ja3-test',
      },
    ];

    await writeFile(eventsPath, JSON.stringify([...connEvents, ...extraEvents], null, 2));

    const out = runBeaconDistillation(await loadEvents(eventsPath));

    assert.ok(out.length >= 1);
    assert.equal(out[0].type, 'beacon');
    assert.equal(typeof out[0].enrichment.destination_rarity, 'number');
    assert.equal(typeof out[0].enrichment.business_hours_proportion, 'number');
    assert.equal(typeof out[0].enrichment.first_seen, 'string');
  });

  // The hoisted stage-2 pass has to be output-neutral, or it is not an optimization.
  // `runPipeline` enriches once and hands every per-type runner the same array through
  // `withEnrichedEvents`; this asserts that doing so is indistinguishable from letting the
  // runner enrich the events itself.
  it('withContext returns identical output for self-enriched and pre-enriched events', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'beacon-distillation-preload-'));
    const eventsPath = join(dir, 'events.json');

    const connEvents = Array.from({ length: 12 }, (_, idx) => buildConnEvent(idx));
    await writeFile(eventsPath, JSON.stringify(connEvents, null, 2));

    const events = await loadEvents(eventsPath);
    const selfEnriched = runBeaconDistillation.withContext(events);
    const preEnriched = runBeaconDistillation.withEnrichedEvents(enrichEventsForRun(events));

    assert.deepEqual(preEnriched.candidates, selfEnriched.candidates);
    assert.deepEqual(preEnriched.events, selfEnriched.events);
    assert.deepEqual([...preEnriched.applicableLabels], [...selfEnriched.applicableLabels]);
  });

  // The runner takes events, not a dataset path, so a caller that wants a non-default
  // indicator feed resolves it and hands it in through the `threatIntelFeed` option. One
  // resolved feed, shared across every runner in a run.
  it('uses adjacent feed.json to stamp Stage-4 threat_intel_match', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'beacon-distillation-feed-'));
    const eventsPath = join(dir, 'events.json');
    const feedPath = join(dir, 'feed.json');
    const iocIp = '185.225.73.217';

    const connEvents = Array.from({ length: 12 }, (_, idx) => buildConnEvent(idx, iocIp));
    await writeFile(eventsPath, JSON.stringify(connEvents, null, 2), 'utf-8');
    await writeFile(feedPath, JSON.stringify(buildIntelFeed(iocIp), null, 2), 'utf-8');

    const out = runBeaconDistillation.withContext(await loadEvents(eventsPath), {
      threatIntelFeed: loadThreatIntelFeedForDataset(eventsPath),
    }).candidates;

    // TYPE-ONLY: of the five candidate interfaces only `UnusualParentChildAnomalyCandidate`
    // declares a literal `type`, so TypeScript cannot narrow the union to `BeaconCandidate`
    // from a `type === 'beacon'` test alone. Hence the cast on `dest_ip`.
    const candidate = out.find((entry) => entry.type === 'beacon'
      && (entry as { dest_ip?: unknown }).dest_ip === iocIp);
    assert.ok(candidate, 'expected at least one beacon candidate on IOC destination');
    assert.equal(candidate.enrichment.threat_intel_match, true);
  });
});
