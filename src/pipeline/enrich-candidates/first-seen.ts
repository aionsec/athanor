import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function parseTimestamp(value: unknown): number | null {
  if (typeof value !== 'string' || value.trim().length === 0) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function stampFirstSeen(
  enrichment: CandidateEnrichment,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
): void {
  let firstSeenMs: number | null = null;

  for (const event of candidateEvents) {
    const ts = parseTimestamp(event.timestamp);
    if (ts === null) continue;
    if (firstSeenMs === null || ts < firstSeenMs) {
      firstSeenMs = ts;
    }
  }

  if (firstSeenMs === null) return;
  enrichment.first_seen = new Date(firstSeenMs).toISOString();
}
