import { readFileSync } from 'node:fs';
import { dataPath } from '../lib/paths.js';

export interface BusinessHoursConfig {
  timezone: 'UTC';
  workdays: number[];
  startHour: number;
  endHour: number;
}

const DEFAULT_CONFIG_PATH = dataPath('business-hours', 'config.yaml');

function parseWorkdays(value: string): number[] {
  const trimmed = value.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (trimmed.length === 0) return [1, 2, 3, 4, 5];
  const parsed = trimmed
    .split(',')
    .map((entry) => Number(entry.trim()))
    .filter((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 6);

  return parsed.length > 0 ? parsed : [1, 2, 3, 4, 5];
}

export function loadBusinessHoursConfig(path = DEFAULT_CONFIG_PATH): BusinessHoursConfig {
  const text = readFileSync(path, 'utf-8');
  const lines = text.split(/\r?\n/);

  let timezone: 'UTC' = 'UTC';
  let workdays = [1, 2, 3, 4, 5];
  let startHour = 9;
  let endHour = 17;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;

    const timezoneMatch = line.match(/^timezone:\s*(.+)$/i);
    if (timezoneMatch) {
      const value = timezoneMatch[1].trim().toUpperCase();
      timezone = value === 'UTC' ? 'UTC' : 'UTC';
      continue;
    }

    const workdaysMatch = line.match(/^workdays:\s*(.+)$/i);
    if (workdaysMatch) {
      workdays = parseWorkdays(workdaysMatch[1]);
      continue;
    }

    const startMatch = line.match(/^start_hour:\s*(\d+)$/i);
    if (startMatch) {
      startHour = Math.max(0, Math.min(23, Number(startMatch[1])));
      continue;
    }

    const endMatch = line.match(/^end_hour:\s*(\d+)$/i);
    if (endMatch) {
      endHour = Math.max(0, Math.min(24, Number(endMatch[1])));
      continue;
    }
  }

  if (endHour <= startHour) {
    endHour = startHour + 1;
  }

  return {
    timezone,
    workdays,
    startHour,
    endHour,
  };
}
