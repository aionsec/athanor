import { existsSync, readFileSync } from 'node:fs';

export type UnusualParentChildTier = 'critical' | 'high' | 'medium' | 'low' | 'unknown' | 'benign';

export type UnusualParentCategory =
  | 'office'
  | 'browser'
  | 'ai_coding_assistant'
  | 'email_client'
  | 'pdf_reader'
  | 'script_host'
  | 'lolbin'
  | 'web_server'
  | 'service_host'
  | 'unknown'
  | 'whitelisted';

export type UnusualChildCategory =
  | 'powershell'
  | 'cmd'
  | 'wscript_cscript'
  | 'mshta'
  | 'rundll32_regsvr32'
  | 'certutil_bitsadmin'
  | 'msi_installer'
  | 'build_tool'
  | 'other_lolbin'
  | 'unknown';

export interface ParentTaxonomyEntry {
  parent_category: UnusualParentCategory;
  parent_basename: string;
  child_basenames: ReadonlySet<string>;
  tier: Exclude<UnusualParentChildTier, 'unknown' | 'benign'>;
  score: number;
}

export interface WhitelistRule {
  id: string;
  parent_path_regex: RegExp;
  parent_basename: string;
  rationale: string;
  parent_command_line_regex: RegExp | null;
}

export interface SuspiciousChildPathRule {
  path_regex: RegExp;
  tier: ParentTaxonomyEntry['tier'];
  score: number;
}

const TAXONOMY_TIERS = new Set<ParentTaxonomyEntry['tier']>([
  'critical',
  'high',
  'medium',
  'low',
]);

const PARENT_CATEGORIES = new Set<Exclude<UnusualParentCategory, 'unknown' | 'whitelisted'>>([
  'office',
  'browser',
  'ai_coding_assistant',
  'email_client',
  'pdf_reader',
  'script_host',
  'lolbin',
  'web_server',
  'service_host',
]);

const CHILD_CATEGORY_BY_BASENAME = new Map<string, UnusualChildCategory>([
  ['powershell.exe', 'powershell'],
  ['pwsh.exe', 'powershell'],
  ['cmd.exe', 'cmd'],
  ['wscript.exe', 'wscript_cscript'],
  ['cscript.exe', 'wscript_cscript'],
  ['mshta.exe', 'mshta'],
  ['rundll32.exe', 'rundll32_regsvr32'],
  ['regsvr32.exe', 'rundll32_regsvr32'],
  ['certutil.exe', 'certutil_bitsadmin'],
  ['bitsadmin.exe', 'certutil_bitsadmin'],
  ['msiexec.exe', 'msi_installer'],
  ['installutil.exe', 'msi_installer'],
  ['msbuild.exe', 'build_tool'],
  ['regasm.exe', 'other_lolbin'],
  ['regsvcs.exe', 'other_lolbin'],
  ['forfiles.exe', 'other_lolbin'],
  ['cmstp.exe', 'other_lolbin'],
  ['msdt.exe', 'other_lolbin'],
  ['verclsid.exe', 'other_lolbin'],
  ['odbcconf.exe', 'other_lolbin'],
  ['hh.exe', 'other_lolbin'],
  ['ieexec.exe', 'other_lolbin'],
  ['scrcons.exe', 'other_lolbin'],
  ['scriptrunner.exe', 'other_lolbin'],
  ['pcalua.exe', 'other_lolbin'],
  ['infdefaultinstall.exe', 'other_lolbin'],
]);

export const DEFAULT_UNUSUAL_PARENT_CHILD_SUSPICIOUS_CHILDREN = new Set<string>(
  [...CHILD_CATEGORY_BY_BASENAME.keys()],
);

function parseCsvLines(raw: string): string[] {
  const lines: string[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    lines.push(trimmed);
  }
  return lines;
}

function toLower(value: string | null | undefined): string {
  return (value ?? '').trim().toLowerCase();
}

function normalizePath(value: string | null | undefined): string {
  return (value ?? '').trim().replace(/\//g, '\\');
}

export function normalizeBasename(value: string | null | undefined): string {
  const normalized = normalizePath(value);
  if (normalized.length === 0) return '';

  const pieces = normalized.split('\\').filter((part) => part.length > 0);
  const basename = pieces.length > 0 ? pieces[pieces.length - 1] : normalized;
  return basename.trim().toLowerCase();
}

function canonicalParentCategory(raw: string): UnusualParentCategory {
  const normalized = toLower(raw);
  if (normalized.startsWith('service_host')) return 'service_host';
  if (PARENT_CATEGORIES.has(normalized as Exclude<UnusualParentCategory, 'unknown' | 'whitelisted'>)) {
    return normalized as Exclude<UnusualParentCategory, 'unknown' | 'whitelisted'>;
  }
  return 'unknown';
}

export function classifyChildCategory(childBasename: string): UnusualChildCategory {
  return CHILD_CATEGORY_BY_BASENAME.get(toLower(childBasename)) ?? 'unknown';
}

function ensureAnchoredRegex(regex: string, label: string): void {
  const trimmed = regex.trim();
  if (!trimmed.startsWith('^') || !trimmed.endsWith('$')) {
    throw new Error(`Unanchored ${label} regex (must be ^...$): ${regex}`);
  }
}

function parseWhitelistColumns(line: string): {
  id: string;
  parentPathRegex: string;
  parentBasename: string;
  parentCommandLineRegex: string;
  rationale: string;
} | null {
  const parts = line.split(',').map((part) => part.trim());
  if (parts.length < 4) return null;
  if (toLower(parts[0]) === 'id') return null;

  if (parts.length === 4) {
    return {
      id: parts[0],
      parentPathRegex: parts[1],
      parentBasename: parts[2],
      parentCommandLineRegex: '',
      rationale: parts[3],
    };
  }

  return {
    id: parts[0],
    parentPathRegex: parts[1],
    parentBasename: parts[2],
    parentCommandLineRegex: parts[3],
    rationale: parts.slice(4).join(',').trim(),
  };
}

export function loadUnusualParentChildTaxonomyFile(path: string): Map<string, ParentTaxonomyEntry[]> {
  if (!existsSync(path)) return new Map<string, ParentTaxonomyEntry[]>();

  const raw = readFileSync(path, 'utf-8');
  const out = new Map<string, ParentTaxonomyEntry[]>();

  for (const line of parseCsvLines(raw)) {
    const parts = line.split(',').map((part) => part.trim());
    if (parts.length < 5) continue;
    if (toLower(parts[0]) === 'parent_category') continue;

    const parentBasename = normalizeBasename(parts[1]);
    if (parentBasename.length === 0) continue;

    const childBasenames = new Set(
      parts[2]
        .split('|')
        .map((part) => normalizeBasename(part))
        .filter((part) => part.length > 0),
    );
    if (childBasenames.size === 0) continue;

    const tierRaw = toLower(parts[3]);
    if (!TAXONOMY_TIERS.has(tierRaw as ParentTaxonomyEntry['tier'])) continue;

    const score = Number.parseFloat(parts[4]);
    if (!Number.isFinite(score)) continue;

    const entry: ParentTaxonomyEntry = {
      parent_category: canonicalParentCategory(parts[0]),
      parent_basename: parentBasename,
      child_basenames: childBasenames,
      tier: tierRaw as ParentTaxonomyEntry['tier'],
      score: Math.max(0, Math.min(1, score)),
    };

    const bucket = out.get(parentBasename) ?? [];
    bucket.push(entry);
    out.set(parentBasename, bucket);
  }

  return out;
}

export function loadUnusualParentChildWhitelistFile(path: string): WhitelistRule[] {
  if (!existsSync(path)) return [];

  const raw = readFileSync(path, 'utf-8');
  const out: WhitelistRule[] = [];

  for (const line of parseCsvLines(raw)) {
    const columns = parseWhitelistColumns(line);
    if (!columns) continue;

    const id = columns.id.trim();
    const parentPathRegex = columns.parentPathRegex.trim();
    const parentBasename = normalizeBasename(columns.parentBasename);
    const rationale = columns.rationale.trim();
    const parentCommandLineRegexRaw = columns.parentCommandLineRegex.trim();

    if (id.length === 0 || parentPathRegex.length === 0 || parentBasename.length === 0) continue;
    ensureAnchoredRegex(parentPathRegex, 'whitelist');

    let parentPathPattern: RegExp;
    try {
      parentPathPattern = new RegExp(parentPathRegex, 'i');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid parent_path_regex for whitelist row ${id}: ${message}`);
    }

    let parentCommandLinePattern: RegExp | null = null;
    if (parentCommandLineRegexRaw.length > 0) {
      try {
        parentCommandLinePattern = new RegExp(parentCommandLineRegexRaw, 'i');
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Invalid parent_command_line_regex for whitelist row ${id}: ${message}`);
      }
    }

    out.push({
      id,
      parent_path_regex: parentPathPattern,
      parent_basename: parentBasename,
      rationale,
      parent_command_line_regex: parentCommandLinePattern,
    });
  }

  return out;
}

export function loadSuspiciousChildPathRules(filePath: string): SuspiciousChildPathRule[] {
  if (!existsSync(filePath)) return [];

  const raw = readFileSync(filePath, 'utf-8');
  const out: SuspiciousChildPathRule[] = [];

  for (const line of parseCsvLines(raw)) {
    const parts = line.split(',').map((part) => part.trim());
    if (parts.length < 3) continue;
    if (toLower(parts[0]) === 'path_regex') continue;

    const pathRegexRaw = parts[0];
    if (pathRegexRaw.length === 0) continue;
    ensureAnchoredRegex(pathRegexRaw, 'suspicious-child path');

    let pathPattern: RegExp;
    try {
      pathPattern = new RegExp(pathRegexRaw, 'i');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid path_regex for suspicious-child path rule "${pathRegexRaw}": ${message}`);
    }

    const tierRaw = toLower(parts[1]);
    if (!TAXONOMY_TIERS.has(tierRaw as ParentTaxonomyEntry['tier'])) continue;

    const score = Number.parseFloat(parts[2]);
    if (!Number.isFinite(score)) continue;

    out.push({
      path_regex: pathPattern,
      tier: tierRaw as ParentTaxonomyEntry['tier'],
      score: Math.max(0, Math.min(1, score)),
    });
  }

  return out;
}

export function matchSuspiciousChildPath(
  processPath: string | undefined,
  rules: readonly SuspiciousChildPathRule[],
): SuspiciousChildPathRule | null {
  if (!processPath) return null;

  const normalized = normalizePath(processPath);
  if (normalized.length === 0) return null;

  for (const rule of rules) {
    if (rule.path_regex.test(normalized)) return rule;
  }

  return null;
}

export function lookupParentChildTier(
  taxonomy: Map<string, ParentTaxonomyEntry[]>,
  parentBasename: string,
  childBasename: string,
): ParentTaxonomyEntry | null {
  const entries = taxonomy.get(toLower(parentBasename));
  if (!entries || entries.length === 0) return null;

  const child = toLower(childBasename);
  for (const entry of entries) {
    if (entry.child_basenames.has(child)) return entry;
  }

  return null;
}

export function matchesWhitelistRule(
  rule: WhitelistRule,
  parentProcessPath: string,
  parentProcessName: string,
  parentCommandLine: string | null,
): boolean {
  const normalizedParentPath = normalizePath(parentProcessPath);
  if (!rule.parent_path_regex.test(normalizedParentPath)) return false;

  const observedParentBasename = normalizeBasename(parentProcessName || parentProcessPath);
  if (observedParentBasename !== rule.parent_basename) return false;

  if (!rule.parent_command_line_regex) return true;
  if (!parentCommandLine) return false;

  return rule.parent_command_line_regex.test(parentCommandLine);
}
