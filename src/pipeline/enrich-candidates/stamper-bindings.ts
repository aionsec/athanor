import {
  ACTIVE_STAGE4_ENRICHMENT_LABELS,
  type Stage4EnrichmentLabel,
} from '../spec/enrichment-spec.js';

export type Stage4StamperBinding =
  | 'threat_intel'
  | 'geo'
  | 'rarity'
  | 'first_seen'
  | 'business_hours'
  | 'lots'
  | 'missing_sni'
  | 'protocol_mismatch'
  | 'native';

export const STAGE4_STAMPER_BINDINGS = {
  threat_intel_match: 'threat_intel',
  geo_country: 'geo',
  geo_asn: 'geo',
  destination_rarity: 'rarity',
  destination_frequency: 'rarity',
  process_rarity: 'rarity',
  process_frequency: 'rarity',
  hash_rarity: 'rarity',
  hash_frequency: 'rarity',
  command_line_rarity: 'rarity',
  command_line_frequency: 'rarity',
  parent_child_pair_rarity: 'rarity',
  parent_child_pair_frequency: 'rarity',
  script_block_hash_rarity: 'rarity',
  script_block_hash_frequency: 'rarity',
  first_seen: 'first_seen',
  business_hours_proportion: 'business_hours',
  lots_match: 'lots',
  missing_sni: 'missing_sni',
  domain_rarity: 'rarity',
  domain_frequency: 'rarity',
  user_agent_rarity: 'rarity',
  user_agent_frequency: 'rarity',
  ja3_rarity: 'rarity',
  ja3_frequency: 'rarity',
  protocol_mismatch: 'protocol_mismatch',
} as const satisfies Record<Stage4EnrichmentLabel, Stage4StamperBinding>;

export function assertActiveStage4StamperCoverage(): void {
  const missingBindings = ACTIVE_STAGE4_ENRICHMENT_LABELS.filter(
    (label) => STAGE4_STAMPER_BINDINGS[label] === undefined,
  );

  if (missingBindings.length > 0) {
    throw new Error(
      `[enrich-candidates] Missing stamper binding for active Stage 4 label(s): ${missingBindings.join(', ')}`,
    );
  }
}
