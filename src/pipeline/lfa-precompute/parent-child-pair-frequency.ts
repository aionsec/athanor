import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import {
  extractParentChildPairEntity,
  type ParentChildPairEntitySource,
} from '../util/extract-parent-child-pair-entity.js';
import { normalizeString } from '../util/normalize-string.js';

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

export function computeParentChildPairFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byPair = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    if (!host) continue;

    const entity = extractParentChildPairEntity(event as ParentChildPairEntitySource);
    if (!entity) continue;

    if (!byPair.has(entity)) byPair.set(entity, new Set());
    byPair.get(entity)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [entity, hosts] of byPair.entries()) {
    output.set(entity, hosts.size);
  }
  return output;
}
