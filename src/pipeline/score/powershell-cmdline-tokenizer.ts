export interface TokenizedPowerShellCommandLine {
  raw_tokens: string[];
  canonical_flags: string[];
  parameter_values: Map<string, string[]>;
}

interface PowerShellParameterDefinition {
  canonical: string;
  key: string;
  takes_value: boolean;
}

const UNICODE_DASH_CHARS = '\u2013\u2014\u2015';
const PARAM_PREFIX_RE = new RegExp(`^[-/${UNICODE_DASH_CHARS}]`);
const PARAM_STRIP_RE = new RegExp(`^[-/${UNICODE_DASH_CHARS}]+`);

const PARAMETER_DEFINITIONS: PowerShellParameterDefinition[] = [
  { canonical: 'NoProfile', key: 'noprofile', takes_value: false },
  { canonical: 'WindowStyle', key: 'windowstyle', takes_value: true },
  { canonical: 'NonInteractive', key: 'noninteractive', takes_value: false },
  { canonical: 'ExecutionPolicy', key: 'executionpolicy', takes_value: true },
  { canonical: 'EncodedCommand', key: 'encodedcommand', takes_value: true },
  { canonical: 'STA', key: 'sta', takes_value: false },
  { canonical: 'Version', key: 'version', takes_value: true },
  { canonical: 'Command', key: 'command', takes_value: true },
  { canonical: 'NoExit', key: 'noexit', takes_value: false },
];

const PARAMETER_ALIAS: Record<string, string> = {
  nop: 'NoProfile',
  noni: 'NonInteractive',
  w: 'WindowStyle',
  ep: 'ExecutionPolicy',
  enc: 'EncodedCommand',
  e: 'EncodedCommand',
  v: 'Version',
};

function normalizeTokenDashPrefix(token: string): string {
  if (token.length === 0) return token;
  return token.replace(PARAM_STRIP_RE, '-');
}

function isParameterToken(token: string): boolean {
  return PARAM_PREFIX_RE.test(token);
}

function resolveCanonicalParameter(rawName: string): PowerShellParameterDefinition | null {
  const normalized = rawName.trim().toLowerCase();
  if (normalized.length === 0) return null;

  const aliasHit = PARAMETER_ALIAS[normalized];
  if (aliasHit) {
    return PARAMETER_DEFINITIONS.find((def) => def.canonical === aliasHit) ?? null;
  }

  const matches = PARAMETER_DEFINITIONS.filter((def) => def.key.startsWith(normalized));
  if (matches.length !== 1) return null;
  return matches[0];
}

function normalizeParameterValue(value: string): string {
  return value.trim().toLowerCase();
}

function pushUnique(list: string[], value: string): void {
  if (!list.includes(value)) list.push(value);
}

function addParameterValue(map: Map<string, string[]>, key: string, value: string): void {
  const values = map.get(key) ?? [];
  values.push(value);
  map.set(key, values);
}

export function splitPowerShellCommandLine(commandLine: string): string[] {
  const out: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (let i = 0; i < commandLine.length; i += 1) {
    const ch = commandLine[i];

    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }

    if (inDouble && ch === '`') {
      escaped = true;
      continue;
    }

    if (!inDouble && ch === '\'') {
      inSingle = !inSingle;
      continue;
    }

    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }

    if (!inSingle && !inDouble && /\s/.test(ch)) {
      if (current.length > 0) {
        out.push(current);
        current = '';
      }
      continue;
    }

    current += ch;
  }

  if (current.length > 0) out.push(current);
  return out;
}

export function tokenizePowerShellCommandLine(commandLine: string): TokenizedPowerShellCommandLine {
  const rawTokens = splitPowerShellCommandLine(commandLine ?? '');
  const canonicalFlags: string[] = [];
  const parameterValues = new Map<string, string[]>();

  for (let i = 0; i < rawTokens.length; i += 1) {
    const rawToken = rawTokens[i];
    if (!isParameterToken(rawToken)) continue;

    const normalizedPrefix = normalizeTokenDashPrefix(rawToken);
    const stripped = normalizedPrefix.replace(/^-+/, '');
    if (stripped.length === 0) continue;

    let name = stripped;
    let inlineValue: string | null = null;
    const colonIdx = stripped.indexOf(':');
    const equalsIdx = stripped.indexOf('=');
    const splitIdx = [colonIdx, equalsIdx]
      .filter((idx) => idx > 0)
      .sort((left, right) => left - right)[0] ?? -1;
    if (splitIdx > 0) {
      name = stripped.slice(0, splitIdx);
      inlineValue = stripped.slice(splitIdx + 1);
    }

    const resolved = resolveCanonicalParameter(name);
    if (!resolved) continue;

    let value: string | null = inlineValue;
    if (resolved.takes_value && !value) {
      const nextToken = rawTokens[i + 1];
      if (nextToken && !isParameterToken(nextToken)) {
        value = nextToken;
        i += 1;
      }
    }

    if (value !== null) {
      addParameterValue(parameterValues, resolved.canonical, value);
    }

    if (resolved.canonical === 'WindowStyle' && value) {
      pushUnique(canonicalFlags, `WindowStyle:${normalizeParameterValue(value)}`);
      continue;
    }

    if (resolved.canonical === 'ExecutionPolicy' && value) {
      pushUnique(canonicalFlags, `ExecutionPolicy:${normalizeParameterValue(value)}`);
      continue;
    }

    if (resolved.canonical === 'Version' && value) {
      pushUnique(canonicalFlags, `Version:${normalizeParameterValue(value)}`);
      continue;
    }

    pushUnique(canonicalFlags, resolved.canonical);
  }

  return {
    raw_tokens: rawTokens,
    canonical_flags: canonicalFlags,
    parameter_values: parameterValues,
  };
}

export function hasCanonicalFlag(tokens: TokenizedPowerShellCommandLine, canonical: string): boolean {
  return tokens.canonical_flags.includes(canonical);
}

export function getParameterValues(tokens: TokenizedPowerShellCommandLine, canonical: string): string[] {
  return [...(tokens.parameter_values.get(canonical) ?? [])];
}

