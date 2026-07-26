import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isWithinBusinessHours, loadBusinessHoursConfig } from '../../../src/enrich-events/index.js';

describe('business-hours', () => {
  it('classifies weekday in-window timestamp as business hours', () => {
    const config = loadBusinessHoursConfig();
    const inWindow = '2026-04-13T13:30:00.000Z'; // Monday
    assert.equal(isWithinBusinessHours(inWindow, config), true);
  });

  it('classifies weekend timestamp as outside business hours', () => {
    const config = loadBusinessHoursConfig();
    const weekend = '2026-04-12T13:30:00.000Z'; // Sunday
    assert.equal(isWithinBusinessHours(weekend, config), false);
  });

  it('classifies out-of-window weekday timestamp as outside business hours', () => {
    const config = loadBusinessHoursConfig();
    const beforeHours = '2026-04-13T07:59:00.000Z'; // Monday
    const afterHours = '2026-04-13T18:01:00.000Z';

    assert.equal(isWithinBusinessHours(beforeHours, config), false);
    assert.equal(isWithinBusinessHours(afterHours, config), false);
  });
});
