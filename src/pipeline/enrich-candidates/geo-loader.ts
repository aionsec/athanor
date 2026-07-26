import { existsSync, readFileSync } from 'node:fs';
import { dataPath } from '../../lib/paths.js';

const DEFAULT_DB_PATH = dataPath('geoip', 'minimal.json');

export interface GeoRecord {
  country: string;
  asn: string;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function loadGeoDatabase(path = DEFAULT_DB_PATH): Map<string, GeoRecord> {
  if (!existsSync(path)) return new Map();

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return new Map();

  const out = new Map<string, GeoRecord>();
  for (const [ip, payload] of Object.entries(raw)) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;
    const rec = payload as Record<string, unknown>;
    const country = normalizeString(rec.country);
    const asn = normalizeString(rec.asn);
    if (!country || !asn) continue;
    out.set(ip, { country, asn });
  }

  return out;
}
