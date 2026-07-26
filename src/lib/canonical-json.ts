const ROUNDING_DECIMALS = 6;
const ROUNDING_FACTOR = 10 ** ROUNDING_DECIMALS;

function roundNumber(value: number): number {
  if (!Number.isFinite(value)) return value;
  return Math.round(value * ROUNDING_FACTOR) / ROUNDING_FACTOR;
}

function normalize(value: unknown, roundNumbers: boolean): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'number') {
    return roundNumbers ? roundNumber(value) : value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalize(item, roundNumbers));
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const keys = Object.keys(record).sort((left, right) => left.localeCompare(right));

    for (const key of keys) {
      const normalized = normalize(record[key], roundNumbers);
      if (normalized !== undefined) {
        out[key] = normalized;
      }
    }

    return out;
  }

  return value;
}

/** Stable key ordering without numeric rounding, for lossless canonical records. */
export function canonicalJson(value: unknown): string {
  const normalized = normalize(value, false);
  return `${JSON.stringify(normalized, null, 2)}\n`;
}

export function canonicalJsonWithRounding(value: unknown): string {
  const normalized = normalize(value, true);
  return `${JSON.stringify(normalized, null, 2)}\n`;
}

export const CANONICAL_JSON_ROUNDING_DECIMALS = ROUNDING_DECIMALS;
