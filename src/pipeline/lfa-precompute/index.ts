import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import { createEmptyLfaTables } from '../types/lfa-tables.js';
import type { LfaTables } from '../types/lfa-tables.js';
import { computeDestinationFrequency } from './destination-frequency.js';
import { computeCommandLineFrequency } from './command-line-frequency.js';
import { computeHashFrequency } from './hash-frequency.js';
import { computeDomainFrequency } from './domain-frequency.js';
import { computeUserAgentFrequency } from './user-agent-frequency.js';
import { computeJa3Frequency } from './ja3-frequency.js';
import { computeScriptBlockHashFrequency } from './script-block-hash-frequency.js';
import { computeProcessFrequency } from './process-frequency.js';
import { computeParentChildPairFrequency } from './parent-child-pair-frequency.js';

export { frequencyStats, prevalence, rarity, rarityScore } from '../types/lfa-tables.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function hasValidTimestamp(value: unknown): boolean {
  if (typeof value !== 'string' || value.trim().length === 0) return false;
  return Number.isFinite(Date.parse(value));
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function validForLfa(event: unknown): event is PostEnrichmentEvent {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  const record = event as { timestamp?: unknown };
  return hasValidTimestamp(record.timestamp);
}

export function precomputeLfa(events: ReadonlyArray<PostEnrichmentEvent>): LfaTables {
  const usableEvents = events.filter(validForLfa);
  const hosts = new Set<string>();

  for (const event of usableEvents) {
    const host = sourceHost(event);
    if (host) hosts.add(host);
  }

  const tables = createEmptyLfaTables(hosts.size);
  tables.destination = computeDestinationFrequency(usableEvents);
  tables.process = computeProcessFrequency(usableEvents);
  tables.commandLine = computeCommandLineFrequency(usableEvents);
  tables.hash = computeHashFrequency(usableEvents);
  tables.parentChildPair = computeParentChildPairFrequency(usableEvents);
  tables.scriptBlockHash = computeScriptBlockHashFrequency(usableEvents);
  tables.domain = computeDomainFrequency(usableEvents);
  tables.userAgent = computeUserAgentFrequency(usableEvents);
  tables.ja3 = computeJa3Frequency(usableEvents);
  return tables;
}
