import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import {
  normalizeString,
  normalizeSha256,
  sha256FromHashObject,
  sha256FromHashString,
} from '../util/normalize-hash.js';

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function sha256Value(event: PostEnrichmentEvent): string | null {
  const record = event as {
    sha256?: unknown;
    hashes?: unknown;
  };

  return normalizeSha256(record.sha256)
    ?? sha256FromHashObject(record.hashes)
    ?? sha256FromHashString(record.hashes);
}

export function computeHashFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byHash = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const sha256 = sha256Value(event);
    if (!host || !sha256) continue;

    if (!byHash.has(sha256)) byHash.set(sha256, new Set());
    byHash.get(sha256)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [sha256, hosts] of byHash.entries()) {
    output.set(sha256, hosts.size);
  }
  return output;
}
