// The schema surface a student reads: which stage-4 labels a candidate can carry.
//
// The enrichment surface, pinned against drift in BOTH directions.
// `CandidateEnrichment` once kept two fields
// (`configured_sync_account_match`, `configured_replication_allowlist_match`) whose
// label specs, stamper bindings and only producing candidate type had all been
// deleted, so nothing could ever set them; meanwhile two label specs (`hash_rarity`,
// `hash_frequency`) survive with no candidate type declaring them applicable.
//
// The rule settled here, and pinned so it cannot drift again: the type advertises
// exactly the labels the SPEC declares. A field with no spec is a promise no code
// path can keep — a student who branches on it writes dead code that reads as live —
// so it goes. A spec with no current consumer stays, because a spec is a definition
// rather than a promise: the stamper still writes it the moment a candidate type
// declares the label, which the last case here proves by doing it.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { CandidateEnrichment } from '../../src/schema/candidates.js';
import type { EnrichmentLabel } from '../../src/pipeline/enrich-candidates/applicability.js';
import { stampRarity } from '../../src/pipeline/enrich-candidates/rarity-stamper.js';
import {
  STAGE4_APPLICABILITY_BY_CANDIDATE,
  STAGE4_ENRICHMENT_LABEL_SPECS,
} from '../../src/pipeline/spec/enrichment-spec.js';
import { createEmptyLfaTables } from '../../src/pipeline/types/lfa-tables.js';

/**
 * Every field `CandidateEnrichment` declares, written out.
 *
 * `satisfies Record<keyof CandidateEnrichment, true>` makes this exhaustive at COMPILE
 * time — adding a field to the interface without adding it here fails `tsc`, and
 * naming a field the interface does not have fails too. The runtime case below then
 * ties the list to the spec, so neither surface can move without the other.
 */
const ENRICHMENT_FIELDS = {
  threat_intel_match: true,
  geo_country: true,
  geo_asn: true,
  destination_frequency: true,
  destination_rarity: true,
  first_seen: true,
  business_hours_proportion: true,
  lots_match: true,
  missing_sni: true,
  process_frequency: true,
  process_rarity: true,
  hash_frequency: true,
  hash_rarity: true,
  command_line_frequency: true,
  command_line_rarity: true,
  parent_child_pair_frequency: true,
  parent_child_pair_rarity: true,
  script_block_hash_frequency: true,
  script_block_hash_rarity: true,
  domain_frequency: true,
  domain_rarity: true,
  user_agent_frequency: true,
  user_agent_rarity: true,
  ja3_frequency: true,
  ja3_rarity: true,
  protocol_mismatch: true,
} satisfies Record<keyof CandidateEnrichment, true>;

describe('CandidateEnrichment is exactly the declared stage-4 label set', () => {
  it('advertises no field the spec cannot produce, and hides none it can', () => {
    assert.deepEqual(
      Object.keys(ENRICHMENT_FIELDS).sort(),
      Object.keys(STAGE4_ENRICHMENT_LABEL_SPECS).sort(),
      'a field with no label spec is unsettable forever; a label with no field is unwritable',
    );
  });

  it('has dropped the two fields whose specs were deleted with their candidate type', () => {
    for (const gone of ['configured_sync_account_match', 'configured_replication_allowlist_match']) {
      assert.equal(Object.hasOwn(ENRICHMENT_FIELDS, gone), false);
      assert.equal(Object.hasOwn(STAGE4_ENRICHMENT_LABEL_SPECS, gone), false);
    }
  });
});

describe('hash_rarity / hash_frequency are dormant, not dead', () => {
  it('is declared applicable by no candidate type athanor carries', () => {
    const applicable = Object.values(STAGE4_APPLICABILITY_BY_CANDIDATE).flat() as string[];
    assert.equal(applicable.includes('hash_rarity'), false);
    assert.equal(applicable.includes('hash_frequency'), false);
  });

  it('is stamped the moment a candidate type declares it — spec, binding and stamper intact', () => {
    const lfaTables = createEmptyLfaTables();
    lfaTables.totalHosts = 10;
    lfaTables.hash.set('MD5=9FB70829D5910B4ABEBECD4C9947F00F', 1);

    const enrichment: CandidateEnrichment = {};
    stampRarity(
      enrichment,
      { hashes: 'MD5=9FB70829D5910B4ABEBECD4C9947F00F' },
      lfaTables,
      {
        processNames: [],
        hashValues: ['MD5=9FB70829D5910B4ABEBECD4C9947F00F'],
        commandLineValues: [],
        parentChildPairValues: [],
        scriptBlockValues: [],
        domains: [],
        userAgents: [],
        ja3Hashes: [],
      },
      new Set<EnrichmentLabel>(['hash_rarity', 'hash_frequency']),
    );

    assert.equal(enrichment.hash_rarity, 0.9, '1 host in 10 → rarity 0.9');
    assert.equal(enrichment.hash_frequency?.entity, 'MD5=9FB70829D5910B4ABEBECD4C9947F00F');
    assert.equal(enrichment.hash_frequency?.host_count, 1);

    // The converse: without the label, nothing is stamped. That is why no run today
    // carries these fields, and why keeping the spec costs nothing.
    const dormant: CandidateEnrichment = {};
    stampRarity(
      dormant,
      { hashes: 'MD5=9FB70829D5910B4ABEBECD4C9947F00F' },
      lfaTables,
      {
        processNames: [],
        hashValues: ['MD5=9FB70829D5910B4ABEBECD4C9947F00F'],
        commandLineValues: [],
        parentChildPairValues: [],
        scriptBlockValues: [],
        domains: [],
        userAgents: [],
        ja3Hashes: [],
      },
      new Set<EnrichmentLabel>(),
    );
    assert.equal(Object.hasOwn(dormant, 'hash_rarity'), false);
    assert.equal(Object.hasOwn(dormant, 'hash_frequency'), false);
  });
});
