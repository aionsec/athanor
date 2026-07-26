import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import {
  extractScriptBlockEntity,
  type ScriptBlockEntitySource,
} from '../util/extract-script-block-entity.js';
import { normalizeString } from '../util/normalize-string.js';

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

export function computeScriptBlockHashFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byScriptBlock = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    if (!host) continue;

    const record = event as ScriptBlockEntitySource;
    const entity = extractScriptBlockEntity(record);
    if (!entity) continue;

    if (!byScriptBlock.has(entity)) byScriptBlock.set(entity, new Set());
    byScriptBlock.get(entity)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [entity, hosts] of byScriptBlock.entries()) {
    output.set(entity, hosts.size);
  }
  return output;
}
