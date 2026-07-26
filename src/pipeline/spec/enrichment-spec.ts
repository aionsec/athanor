import type { CandidateType } from '../../schema/candidates.js';
import {
  STAGE2_APPLICABILITY_BY_EVENT_KEY,
  STAGE2_LABEL_CONTRACTS_BY_LABEL,
  type Stage2EventEnrichmentLabel,
} from '../../enrich-events/index.js';

export type EnrichmentValueType = 'boolean' | 'number' | 'string' | 'enum' | 'object';

export interface Stage2EnrichmentLabelSpec {
  stage: 'stage2_event';
  label: Stage2EventEnrichmentLabel;
  required: boolean;
  valueType: 'boolean' | 'string' | 'enum';
  nullable: boolean;
  enumValues?: readonly string[];
  rationaleRef: string;
}

export interface Stage2EventEnrichmentContract {
  eventKey: string;
  labels: readonly Stage2EventEnrichmentLabel[];
}

export interface Stage4EnrichmentLabelSpec {
  stage: 'stage4_candidate';
  valueType: EnrichmentValueType;
  nullable: boolean;
  status: 'active' | 'planned';
  rationaleRef: string;
}

export const STAGE2_ENRICHMENT_SPEC: readonly Stage2EnrichmentLabelSpec[] = (
  Object.entries(STAGE2_LABEL_CONTRACTS_BY_LABEL) as Array<
    [Stage2EventEnrichmentLabel, (typeof STAGE2_LABEL_CONTRACTS_BY_LABEL)[Stage2EventEnrichmentLabel]]
  >
).map(([label, contract]) => ({
  stage: 'stage2_event',
  label,
  required: true,
  valueType: contract.valueType,
  nullable: contract.nullable,
  ...('enumValues' in contract ? { enumValues: contract.enumValues } : {}),
  rationaleRef: 'docs/design.md#stage-2-event-enrichment',
}));

export const STAGE2_EVENT_ENRICHMENT_CONTRACTS: readonly Stage2EventEnrichmentContract[] = (
  Object.entries(STAGE2_APPLICABILITY_BY_EVENT_KEY) as Array<[string, readonly Stage2EventEnrichmentLabel[]]>
).map(([eventKey, labels]) => ({
  eventKey,
  labels,
}));

export const STAGE4_ENRICHMENT_LABEL_SPECS = {
  threat_intel_match: {
    stage: 'stage4_candidate',
    valueType: 'boolean',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  geo_country: {
    stage: 'stage4_candidate',
    valueType: 'string',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  geo_asn: {
    stage: 'stage4_candidate',
    valueType: 'string',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  destination_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  destination_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  process_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  process_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  hash_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  hash_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  command_line_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  command_line_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  parent_child_pair_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  parent_child_pair_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  script_block_hash_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  script_block_hash_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  first_seen: {
    stage: 'stage4_candidate',
    valueType: 'string',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  business_hours_proportion: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  lots_match: {
    stage: 'stage4_candidate',
    valueType: 'boolean',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  missing_sni: {
    stage: 'stage4_candidate',
    valueType: 'boolean',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
  domain_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  domain_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  user_agent_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  user_agent_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  ja3_rarity: {
    stage: 'stage4_candidate',
    valueType: 'number',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  ja3_frequency: {
    stage: 'stage4_candidate',
    valueType: 'object',
    nullable: false,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-3c-local-frequency-analysis',
  },
  protocol_mismatch: {
    stage: 'stage4_candidate',
    valueType: 'boolean',
    nullable: true,
    status: 'active',
    rationaleRef: 'docs/design.md#stage-4-candidate-enrichment',
  },
} as const satisfies Record<string, Stage4EnrichmentLabelSpec>;

export type Stage4EnrichmentLabel = keyof typeof STAGE4_ENRICHMENT_LABEL_SPECS;

export const STAGE4_CANDIDATE_TYPES = [
  'beacon',
  'data_transfer',
  'tls_anomaly',
  'powershell_invocation_anomaly',
  'unusual_parent_child_anomaly',
] as const satisfies readonly CandidateType[];

export type Stage4CandidateType = (typeof STAGE4_CANDIDATE_TYPES)[number];

export const STAGE4_APPLICABILITY_BY_CANDIDATE = {
  beacon: [
    'threat_intel_match',
    'geo_country',
    'geo_asn',
    'destination_rarity',
    'destination_frequency',
    'first_seen',
    'business_hours_proportion',
    'lots_match',
    'missing_sni',
    'domain_rarity',
    'domain_frequency',
    'user_agent_rarity',
    'user_agent_frequency',
    'ja3_rarity',
    'ja3_frequency',
    'protocol_mismatch',
  ],
  data_transfer: [
    'threat_intel_match',
    'geo_country',
    'geo_asn',
    'destination_rarity',
    'destination_frequency',
    'first_seen',
    'business_hours_proportion',
    'lots_match',
    'user_agent_rarity',
    'user_agent_frequency',
    'protocol_mismatch',
  ],
  tls_anomaly: [
    'threat_intel_match',
    'geo_country',
    'geo_asn',
    'destination_rarity',
    'destination_frequency',
    'first_seen',
    'business_hours_proportion',
    'lots_match',
    'missing_sni',
    'domain_rarity',
    'domain_frequency',
    'ja3_rarity',
    'ja3_frequency',
    'protocol_mismatch',
  ],
  powershell_invocation_anomaly: [
    'command_line_rarity',
    'command_line_frequency',
    'parent_child_pair_rarity',
    'parent_child_pair_frequency',
    'script_block_hash_rarity',
    'script_block_hash_frequency',
    'first_seen',
    'business_hours_proportion',
  ],
  unusual_parent_child_anomaly: [
    'parent_child_pair_rarity',
    'parent_child_pair_frequency',
    'process_rarity',
    'process_frequency',
    'first_seen',
    'business_hours_proportion',
  ],
} as const satisfies Record<Stage4CandidateType, readonly Stage4EnrichmentLabel[]>;

export const ACTIVE_STAGE4_ENRICHMENT_LABELS: readonly Stage4EnrichmentLabel[] = (
  Object.entries(STAGE4_ENRICHMENT_LABEL_SPECS) as Array<[Stage4EnrichmentLabel, Stage4EnrichmentLabelSpec]>
)
  .filter(([, spec]) => spec.status === 'active')
  .map(([label]) => label);
