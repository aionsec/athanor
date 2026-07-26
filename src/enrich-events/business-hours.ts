import { loadBusinessHoursConfig, type BusinessHoursConfig } from './business-hours-loader.js';

export { loadBusinessHoursConfig } from './business-hours-loader.js';
export type { BusinessHoursConfig } from './business-hours-loader.js';

export function isWithinBusinessHours(timestampIso: string, config: BusinessHoursConfig): boolean {
  const ms = Date.parse(timestampIso);
  if (!Number.isFinite(ms)) return false;

  const date = new Date(ms);
  const day = date.getUTCDay();
  const hour = date.getUTCHours();

  if (!config.workdays.includes(day)) return false;
  return hour >= config.startHour && hour < config.endHour;
}

export function resolveBusinessHours(timestampIso: string, config = loadBusinessHoursConfig()): boolean {
  return isWithinBusinessHours(timestampIso, config);
}
