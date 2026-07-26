import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function eventHasBusinessHours(event: PostEnrichmentEvent): event is PostEnrichmentEvent & { enrichment: { business_hours: boolean } } {
  return typeof event.enrichment.business_hours === 'boolean';
}

export function stampBusinessHoursProportion(
  enrichment: CandidateEnrichment,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
): void {
  const withFlags = candidateEvents.filter(eventHasBusinessHours);
  if (withFlags.length === 0) return;

  const inHours = withFlags.filter((event) => event.enrichment.business_hours).length;
  enrichment.business_hours_proportion = inHours / withFlags.length;
}
