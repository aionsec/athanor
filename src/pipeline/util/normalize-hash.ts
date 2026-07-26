import { normalizeString } from './normalize-string.js';

export { normalizeString } from './normalize-string.js';

function normalizeLower(value: unknown): string | null {
  const base = normalizeString(value);
  return base ? base.toLowerCase() : null;
}

export function normalizeSha256(value: unknown): string | null {
  const base = normalizeLower(value);
  if (!base) return null;
  return /^[a-f0-9]{64}$/.test(base) ? base : null;
}

export function normalizeHashKey(value: string): string {
  return value.trim().toLowerCase().replace(/[-_]/g, '');
}

export function sha256FromHashObject(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;

  const entries = Object.entries(value as Record<string, unknown>);
  for (const [key, raw] of entries) {
    if (normalizeHashKey(key) !== 'sha256') continue;
    const parsed = normalizeSha256(raw);
    if (parsed) return parsed;
  }

  return null;
}

export function sha256FromHashString(value: unknown): string | null {
  if (typeof value !== 'string') return null;

  const segments = value.split(',');
  for (const segment of segments) {
    const entry = segment.trim();
    if (!entry) continue;

    const separator = entry.includes('=') ? '=' : (entry.includes(':') ? ':' : null);
    if (!separator) continue;

    const [rawKey, ...rawValueParts] = entry.split(separator);
    if (normalizeHashKey(rawKey) !== 'sha256') continue;

    const rawValue = rawValueParts.join(separator);
    const parsed = normalizeSha256(rawValue);
    if (parsed) return parsed;
  }

  return null;
}
