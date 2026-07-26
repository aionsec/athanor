import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function stampMissingSni(
  enrichment: CandidateEnrichment,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
): void {
  const sslEvents = candidateEvents.filter((event) => event.source === 'zeek' && event.event_type === 'ssl');
  if (sslEvents.length === 0) return;

  enrichment.missing_sni = sslEvents.some((event) => normalizeString((event as { server_name?: unknown }).server_name) === null);
}
