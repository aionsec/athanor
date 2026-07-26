import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, canonicalJsonWithRounding } from '../../src/lib/canonical-json.js';

describe('canonicalJsonWithRounding', () => {
  it('sorts object keys recursively', () => {
    const input = {
      z: 1,
      a: {
        c: 3,
        b: 2,
      },
    };

    const output = canonicalJsonWithRounding(input);
    assert.match(output, /"a": \{\n\s+"b": 2,\n\s+"c": 3\n\s+\},\n\s+"z": 1/);
  });

  it('rounds numbers to 6 decimal places recursively', () => {
    const input = {
      score: 0.123456789,
      nested: [0.3333333333],
    };

    const output = canonicalJsonWithRounding(input);
    assert.match(output, /"score": 0.123457/);
    assert.match(output, /"nested": \[\n\s+0.333333\n\s+\]/);
  });

  it('serializes with trailing newline and LF-only output', () => {
    const output = canonicalJsonWithRounding({ a: 1 });
    assert.equal(output.endsWith('\n'), true);
    assert.equal(output.includes('\r\n'), false);
  });
});

describe('canonicalJson', () => {
  it('sorts object keys without rounding numeric values', () => {
    const value = {
      z: 0.123456789,
      nested: { b: 2, a: 1 },
      a: 'first',
    };

    const output = canonicalJson(value);
    assert.equal(
      output,
      '{\n  "a": "first",\n  "nested": {\n    "a": 1,\n    "b": 2\n  },\n  "z": 0.123456789\n}\n',
    );
    assert.deepEqual(JSON.parse(output), value);
  });
});
