import { normalizeProcessName } from './normalize-process.js';
import { normalizeString } from './normalize-string.js';

export function normalizeCommandLine(value: unknown): string | null {
  const raw = normalizeString(value);
  if (!raw) return null;

  const normalized = raw.replace(/\s+/g, ' ').trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

export function commandLineEntity(processName: unknown, commandLine: unknown): string | null {
  const normalizedProcess = normalizeProcessName(processName);
  const normalizedCommandLine = normalizeCommandLine(commandLine);
  if (!normalizedProcess || !normalizedCommandLine) return null;

  return `${normalizedProcess}\x1f${normalizedCommandLine}`;
}
