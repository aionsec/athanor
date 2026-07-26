import type {
  CandidateAttributionConfidence,
  CandidateType,
} from '../../schema/candidates.js';

export const ATTRIBUTION_ELIGIBLE_CANDIDATE_TYPES = [
  'beacon',
  'data_transfer',
  'tls_anomaly',
] as const satisfies readonly CandidateType[];

export type AttributionEligibleCandidateType = (typeof ATTRIBUTION_ELIGIBLE_CANDIDATE_TYPES)[number];

export const ATTRIBUTION_CONFIDENCE_VALUES = [
  'full',
  'partial_time_skew',
  'partial_multi_process',
  'inferred',
  'unavailable',
] as const satisfies readonly CandidateAttributionConfidence[];

export const DEFAULT_ATTRIBUTION_TIME_SKEW_MS = 2000;
