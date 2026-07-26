import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { ThreatIntelFeed } from './threat-intel-loader.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

export interface ThreatIntelContext {
  domains: string[];
  hashes: string[];
  events: ReadonlyArray<PostEnrichmentEvent>;
}

function normalizeLower(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function isThreatIntelMatch(
  candidate: Record<string, unknown>,
  feed: ThreatIntelFeed,
  context: ThreatIntelContext,
): boolean {
  const destinationIp = normalizeString(candidate.dest_ip);
  if (destinationIp && feed.ips.has(destinationIp)) return true;
  if (!destinationIp) {
    for (const event of context.events) {
      const eventDestIp = normalizeString((event as { dest_ip?: unknown }).dest_ip);
      if (eventDestIp && feed.ips.has(eventDestIp)) return true;
    }
  }

  const candidateDomains = [
    normalizeLower(candidate.base_domain),
    normalizeLower(candidate.domain),
  ].filter((value): value is string => Boolean(value));

  for (const domain of candidateDomains) {
    if (feed.domains.has(domain)) return true;
  }

  for (const domain of context.domains) {
    if (feed.domains.has(domain.toLowerCase())) return true;
  }

  const candidateHashes = [
    normalizeLower(candidate.sha256),
    normalizeLower(candidate.sha1),
    normalizeLower(candidate.md5),
  ].filter((value): value is string => Boolean(value));

  for (const hash of candidateHashes) {
    if (feed.hashes.has(hash)) return true;
  }

  for (const hash of context.hashes) {
    if (feed.hashes.has(hash.toLowerCase())) return true;
  }

  return false;
}

export function stampThreatIntel(
  enrichment: CandidateEnrichment,
  candidate: Record<string, unknown>,
  feed: ThreatIntelFeed,
  context: ThreatIntelContext,
): void {
  enrichment.threat_intel_match = isThreatIntelMatch(candidate, feed, context);
}
