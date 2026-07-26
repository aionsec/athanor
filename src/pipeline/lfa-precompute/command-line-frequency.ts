import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import { commandLineEntity } from '../util/normalize-command-line.js';
import { normalizeString } from '../util/normalize-string.js';

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function entityFromEvent(event: PostEnrichmentEvent): string | null {
  const record = event as {
    process_name?: unknown;
    source_image?: unknown;
    image?: unknown;
    command_line?: unknown;
  };

  return commandLineEntity(
    record.process_name ?? record.source_image ?? record.image,
    record.command_line,
  );
}

export function computeCommandLineFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byCommandLine = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const entity = entityFromEvent(event);
    if (!host || !entity) continue;

    if (!byCommandLine.has(entity)) byCommandLine.set(entity, new Set());
    byCommandLine.get(entity)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [entity, hosts] of byCommandLine.entries()) {
    output.set(entity, hosts.size);
  }
  return output;
}
