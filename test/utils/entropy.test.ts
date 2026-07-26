import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy } from '../../src/utils/entropy.js';

describe('domain utils: shannonEntropy', () => {
  it('returns 0 for empty/repeated strings', () => {
    assert.equal(shannonEntropy(''), 0);
    assert.equal(shannonEntropy('aaaaaa'), 0);
  });

  it('is higher for diverse symbols than repeated symbols', () => {
    const low = shannonEntropy('aaaaaaaaaaaaaaaa');
    const high = shannonEntropy('abcd1234wxyz5678');
    assert.ok(high > low);
    assert.ok(high > 2.5);
  });
});
