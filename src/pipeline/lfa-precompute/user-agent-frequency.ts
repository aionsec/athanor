import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function userAgent(event: PostEnrichmentEvent): string | null {
  const record = event as { http_user_agent?: unknown; user_agent?: unknown };
  return normalizeString(record.http_user_agent) ?? normalizeString(record.user_agent);
}

export function computeUserAgentFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byUserAgent = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const ua = userAgent(event);
    if (!host || !ua) continue;

    if (!byUserAgent.has(ua)) byUserAgent.set(ua, new Set());
    byUserAgent.get(ua)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [ua, hosts] of byUserAgent.entries()) {
    output.set(ua, hosts.size);
  }
  return output;
}
