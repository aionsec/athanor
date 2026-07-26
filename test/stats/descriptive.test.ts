import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mean, median, stddev, mad, madRatio, madConsistency, cvConsistency } from '../../src/stats/descriptive.js';

describe('Descriptive statistics', () => {
  it('mean of empty array is 0', () => {
    assert.equal(mean([]), 0);
  });

  it('mean computes correctly', () => {
    assert.equal(mean([1, 2, 3, 4, 5]), 3);
  });

  it('median of odd-length array', () => {
    assert.equal(median([3, 1, 2]), 2);
  });

  it('median of even-length array', () => {
    assert.equal(median([1, 2, 3, 4]), 2.5);
  });

  it('stddev of constant values is 0', () => {
    assert.equal(stddev([5, 5, 5, 5]), 0);
  });

  it('mad of constant values is 0', () => {
    assert.equal(mad([5, 5, 5, 5]), 0);
  });

  it('mad is robust to outliers', () => {
    // 99 values of 60, 1 outlier of 1000 — MAD should still be ~0
    const values = Array(99).fill(60);
    values.push(1000);
    assert.ok(mad(values) < 1, `MAD ${mad(values)} should be near 0 with one outlier`);
  });

  it('madRatio of uniform values is 0', () => {
    assert.equal(madRatio([100, 100, 100]), 0);
  });

  it('madConsistency of uniform values is 1', () => {
    assert.equal(madConsistency([100, 100, 100]), 1);
  });

  it('cvConsistency of uniform values is 1', () => {
    assert.equal(cvConsistency([100, 100, 100]), 1);
  });

  it('MAD is more robust than CV to outliers', () => {
    const values = Array(99).fill(60);
    values.push(1000);
    const madC = madConsistency(values);
    const cvC = cvConsistency(values);
    assert.ok(madC > cvC, `MAD consistency ${madC} should be higher than CV consistency ${cvC} with outlier`);
  });
});
