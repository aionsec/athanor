import { normalizeString } from './normalize-string.js';

export function normalizeProcessName(value: unknown): string | null {
  const raw = normalizeString(value);
  if (!raw) return null;

  const normalizedPath = raw.replace(/\//g, '\\');
  const parts = normalizedPath.split('\\').filter(Boolean);
  const basename = parts.length > 0 ? parts[parts.length - 1] : normalizedPath;
  const lowered = basename.trim().toLowerCase();
  return lowered.length > 0 ? lowered : null;
}
