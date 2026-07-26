import type { CandidateType } from '../../schema/candidates.js';
import {
  STAGE4_APPLICABILITY_BY_CANDIDATE,
  type Stage4EnrichmentLabel,
} from '../spec/enrichment-spec.js';

export type EnrichmentLabel = Stage4EnrichmentLabel;

const EMPTY_LABELS: ReadonlySet<EnrichmentLabel> = new Set();

const APPLICABILITY_BY_CANDIDATE = new Map<string, ReadonlySet<EnrichmentLabel>>(
  Object.entries(STAGE4_APPLICABILITY_BY_CANDIDATE).map(([candidateType, labels]) => [
    candidateType,
    new Set(labels),
  ]),
);

export function applicableLabelsForCandidateType(candidateType: CandidateType | string): ReadonlySet<EnrichmentLabel> {
  return APPLICABILITY_BY_CANDIDATE.get(candidateType) ?? EMPTY_LABELS;
}

export function isLabelApplicable(
  candidateType: CandidateType | string,
  label: EnrichmentLabel,
): boolean {
  return applicableLabelsForCandidateType(candidateType).has(label);
}
