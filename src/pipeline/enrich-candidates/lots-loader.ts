import { existsSync, readFileSync } from 'node:fs';
import { dataPath } from '../../lib/paths.js';

const DEFAULT_LOTS_PATH = dataPath('lots', 'minimal.json');

function normalizeDomain(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

export function loadLotsDomains(path = DEFAULT_LOTS_PATH): Set<string> {
  if (!existsSync(path)) return new Set();

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown;
  if (!Array.isArray(raw)) return new Set();

  const out = new Set<string>();
  for (const item of raw) {
    const domain = normalizeDomain(item);
    if (domain) out.add(domain);
  }

  return out;
}
