import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonWithRounding } from '../../../src/lib/canonical-json.js';

describe('canonicalJsonWithRounding', () => {
  it('sorts object keys recursively', () => {
    const input = {
      z: 1,
      a: {
        y: 2,
        b: 3,
      },
      m: [{ d: 4, c: 5 }],
    };

    const out = canonicalJsonWithRounding(input);
    const parsed = JSON.parse(out) as Record<string, unknown>;

    assert.deepEqual(Object.keys(parsed), ['a', 'm', 'z']);
    assert.deepEqual(Object.keys(parsed.a as Record<string, unknown>), ['b', 'y']);
    assert.deepEqual(Object.keys((parsed.m as Array<Record<string, unknown>>)[0]!), ['c', 'd']);
  });

  it('rounds numbers to 6 decimal places recursively', () => {
    const input = {
      score: 0.123456789,
      nested: {
        value: 10.00000049,
      },
      arr: [1.23456789, { x: 2.99999994 }],
    };

    const parsed = JSON.parse(canonicalJsonWithRounding(input)) as {
      score: number;
      nested: { value: number };
      arr: Array<number | { x: number }>;
    };

    assert.equal(parsed.score, 0.123457);
    assert.equal(parsed.nested.value, 10);
    assert.equal(parsed.arr[0], 1.234568);
    assert.deepEqual(parsed.arr[1], { x: 3 });
  });

  it('serializes with trailing newline and 2-space indentation', () => {
    const out = canonicalJsonWithRounding({ b: 1, a: 2 });
    assert.equal(out.endsWith('\n'), true);
    assert.match(out, /\n  "a": 2,\n  "b": 1\n}\n$/);
  });

  it('is idempotent', () => {
    const input = {
      d: 0.11111119,
      c: [{ z: 5, a: 1.99999991 }],
      b: null,
      a: undefined,
    };

    const first = canonicalJsonWithRounding(input);
    const second = canonicalJsonWithRounding(JSON.parse(first));
    assert.equal(first, second);
  });

  it('preserves NaN and Infinity as JSON null via stringify behavior', () => {
    const out = canonicalJsonWithRounding({ a: Number.NaN, b: Number.POSITIVE_INFINITY, c: Number.NEGATIVE_INFINITY });
    assert.deepEqual(JSON.parse(out), { a: null, b: null, c: null });
  });
});
