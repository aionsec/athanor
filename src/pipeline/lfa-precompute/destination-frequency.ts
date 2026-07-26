import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function destinationIp(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { dest_ip?: unknown }).dest_ip);
}

export function computeDestinationFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byDestination = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const destination = destinationIp(event);
    if (!host || !destination) continue;

    if (!byDestination.has(destination)) byDestination.set(destination, new Set());
    byDestination.get(destination)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [destination, hosts] of byDestination.entries()) {
    output.set(destination, hosts.size);
  }
  return output;
}
