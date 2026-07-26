import { createHash } from 'node:crypto';
import { canonicalJsonWithRounding } from './canonical-json.js';

function normalizeForDeterministicIdentity(value: unknown): unknown {
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) {
    const normalizedItems = value.map((item) => normalizeForDeterministicIdentity(item));
    return normalizedItems.sort((left, right) => {
      const leftSerialized = canonicalJsonWithRounding(left);
      const rightSerialized = canonicalJsonWithRounding(right);
      return leftSerialized.localeCompare(rightSerialized);
    });
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};

    for (const key of Object.keys(record).sort((left, right) => left.localeCompare(right))) {
      const normalized = normalizeForDeterministicIdentity(record[key]);
      if (normalized !== undefined) {
        out[key] = normalized;
      }
    }

    return out;
  }

  return value;
}

export function canonicalJsonForDeterministicIdentity(value: unknown): string {
  return canonicalJsonWithRounding(normalizeForDeterministicIdentity(value));
}

export function sha256HexForDeterministicIdentity(value: unknown): string {
  return createHash('sha256')
    .update(canonicalJsonForDeterministicIdentity(value), 'utf8')
    .digest('hex');
}
