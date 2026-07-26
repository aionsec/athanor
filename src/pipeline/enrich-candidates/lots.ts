import type { CandidateEnrichment } from '../../schema/candidates.js';

export function stampLots(
  enrichment: CandidateEnrichment,
  domains: string[],
  lotsDomains: Set<string>,
): void {
  if (domains.length === 0) {
    enrichment.lots_match = false;
    return;
  }

  enrichment.lots_match = domains.some((domain) => lotsDomains.has(domain.toLowerCase()));
}
