import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function ja3Hash(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { ja3_hash?: unknown }).ja3_hash);
}

export function computeJa3Frequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byJa3 = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const ja3 = ja3Hash(event);
    if (!host || !ja3) continue;

    if (!byJa3.has(ja3)) byJa3.set(ja3, new Set());
    byJa3.get(ja3)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [ja3, hosts] of byJa3.entries()) {
    output.set(ja3, hosts.size);
  }
  return output;
}
