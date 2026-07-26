import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function domainValue(event: PostEnrichmentEvent): string | null {
  const record = event as {
    query?: unknown;
    server_name?: unknown;
    http_host?: unknown;
    host?: unknown;
  };

  return normalizeString(record.query)
    ?? normalizeString(record.server_name)
    ?? normalizeString(record.http_host)
    ?? (typeof record.http_host === 'string' ? null : normalizeString(record.host));
}

export function computeDomainFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byDomain = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const domain = domainValue(event);
    if (!host || !domain) continue;

    if (!byDomain.has(domain)) byDomain.set(domain, new Set());
    byDomain.get(domain)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [domain, hosts] of byDomain.entries()) {
    output.set(domain, hosts.size);
  }
  return output;
}
