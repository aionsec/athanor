import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { dataPath } from '../../lib/paths.js';

// Threat-intel indicators, from two sources: the bundled
// `data/threat-intel/minimal.json` table, and a `feed.json` sitting beside a dataset.
//
// The bundled table is a PLACEHOLDER holding a handful of documentation addresses. On
// real telemetry `threat_intel_match` reports nothing until it is replaced — see the
// README's boundaries section.
//
// `IntelMatchFeedEntry` is the alternative feed shape: a flat list of
// `{normalized_value, match_type}` entries, which is what indicator exports commonly
// look like.
export interface IntelMatchFeedEntry {
  normalized_value: string;
  match_type: string;
}

const DEFAULT_FEED_PATH = dataPath('threat-intel', 'minimal.json');

export interface ThreatIntelFeed {
  ips: Set<string>;
  domains: Set<string>;
  hashes: Set<string>;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeLower(value: unknown): string | null {
  const base = normalizeString(value);
  return base ? base.toLowerCase() : null;
}

function normalizeDomainFromUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.trim().toLowerCase();
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}

function toStringSet(
  value: unknown,
  normalize: (entry: unknown) => string | null,
): Set<string> {
  if (!Array.isArray(value)) return new Set();

  const out = new Set<string>();
  for (const entry of value) {
    const normalized = normalize(entry);
    if (normalized) out.add(normalized);
  }
  return out;
}

export function emptyThreatIntelFeed(): ThreatIntelFeed {
  return {
    ips: new Set<string>(),
    domains: new Set<string>(),
    hashes: new Set<string>(),
  };
}

export function loadThreatIntelFeed(path = DEFAULT_FEED_PATH): ThreatIntelFeed {
  if (!existsSync(path)) return emptyThreatIntelFeed();

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return emptyThreatIntelFeed();

  const record = raw as Record<string, unknown>;
  return {
    ips: toStringSet(record.ips, normalizeString),
    domains: toStringSet(record.domains, normalizeLower),
    hashes: toStringSet(record.hashes, normalizeLower),
  };
}

export function deriveThreatIntelFeedFromIntelMatchEntries(
  entries: ReadonlyArray<IntelMatchFeedEntry>,
): ThreatIntelFeed {
  const ips = new Set<string>();
  const domains = new Set<string>();
  const hashes = new Set<string>();

  for (const entry of entries) {
    const normalizedValue = normalizeString(entry.normalized_value);
    if (!normalizedValue) continue;

    if (entry.match_type === 'ioc_ip') {
      ips.add(normalizedValue);
      continue;
    }

    if (entry.match_type === 'ioc_domain') {
      domains.add(normalizedValue.toLowerCase());
      continue;
    }

    if (entry.match_type === 'ioc_hash') {
      hashes.add(normalizedValue.toLowerCase());
      continue;
    }

    if (entry.match_type === 'ioc_url') {
      const domain = normalizeDomainFromUrl(normalizedValue);
      if (domain) domains.add(domain);
    }
  }

  return { ips, domains, hashes };
}

function readIntelMatchFeedEntries(path: string): IntelMatchFeedEntry[] {
  const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
  const entries = Array.isArray(raw)
    ? raw
    : (raw && typeof raw === 'object' && Array.isArray((raw as { feeds?: unknown }).feeds)
      ? (raw as { feeds: unknown[] }).feeds
      : []);

  return entries.filter((entry): entry is IntelMatchFeedEntry => (
    !!entry
    && typeof entry === 'object'
    && typeof (entry as IntelMatchFeedEntry).normalized_value === 'string'
    && typeof (entry as IntelMatchFeedEntry).match_type === 'string'
  ));
}

export function loadThreatIntelFeedForDataset(datasetPath: string): ThreatIntelFeed {
  const variantDir = dirname(datasetPath);
  const variantFeedPath = join(variantDir, 'feed.json');

  if (!existsSync(variantFeedPath)) {
    return loadThreatIntelFeed();
  }

  return deriveThreatIntelFeedFromIntelMatchEntries(readIntelMatchFeedEntries(variantFeedPath));
}
