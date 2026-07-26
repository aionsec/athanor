import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';
import { normalizeProcessName } from '../util/normalize-process.js';

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sourceHost(event: PostEnrichmentEvent): string | null {
  return normalizeString((event as { host?: unknown }).host) ?? normalizeString((event as { src_ip?: unknown }).src_ip);
}

function processName(event: PostEnrichmentEvent): string | null {
  const record = event as {
    process_name?: unknown;
    source_image?: unknown;
    image?: unknown;
    creator_image?: unknown;
  };

  return normalizeProcessName(record.process_name)
    ?? normalizeProcessName(record.source_image)
    ?? normalizeProcessName(record.image)
    ?? normalizeProcessName(record.creator_image);
}

export function computeProcessFrequency(events: ReadonlyArray<PostEnrichmentEvent>): Map<string, number> {
  const byProcess = new Map<string, Set<string>>();

  for (const event of events) {
    const host = sourceHost(event);
    const process = processName(event);
    if (!host || !process) continue;

    if (!byProcess.has(process)) byProcess.set(process, new Set());
    byProcess.get(process)!.add(host);
  }

  const output = new Map<string, number>();
  for (const [process, hosts] of byProcess.entries()) {
    output.set(process, hosts.size);
  }
  return output;
}
