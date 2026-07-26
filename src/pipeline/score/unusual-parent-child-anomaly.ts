/**
 * Unusual parent-child scoring — stage 3 for the `unusual_parent_child_anomaly` type.
 *
 * Windows has a normal shape. `services.exe` starts services. `explorer.exe` starts the
 * things a person double-clicks. `winword.exe` starts nothing. Most of what an intruder
 * does on an endpoint shows up first as a violation of that shape — a document handler
 * spawning a shell, a service host spawning a browser — and this scorer is the check for
 * it.
 *
 * Entity: ONE process-create event. Unlike the network scorers, which aggregate many
 * records into one entity, each EID 1 event is its own candidate. The pair is what is
 * being judged, and it is fully present in a single record.
 *
 * The judgment is a TABLE LOOKUP, not a computation. `data/unusual-parent-child-anomaly/
 * parent-taxonomy.csv` lists, per parent, the child executables that are SUSPICIOUS under
 * it, with a tier and a score for the pair — `winword.exe → powershell.exe` is `critical`
 * at 0.95. A tier table can be read, argued with and amended by someone who knows an
 * estate, which arithmetic over process names could not be.
 *
 * Three refinements sit on top of the lookup:
 *
 *   - CHILD CATEGORY   the child is classified (shell, script host, LOLBin, and so on),
 *                      so `winword.exe → cmd.exe` and `winword.exe → notepad.exe` are not
 *                      the same finding.
 *   - SUSPICIOUS PATH  `suspicious-child-paths.csv` makes a child eligible on its PATH
 *                      when its basename is unknown — anything run from a temp, cache or
 *                      download directory. The sample dataset's implant runs from an npm
 *                      cache folder under a name no table has ever seen.
 *   - WHITELIST        `whitelist.csv` suppresses by parent: `explorer.exe` is how a
 *                      person starts things, and management agents legitimately spawn
 *                      whatever they were told to install.
 *
 * The composite is the tier score, clamped to [0, 1]. There is no weighted sum here
 * because there is nothing to weigh: one pair, one verdict.
 *
 * Loading is PERMISSIVE-OPTIONAL: a missing taxonomy file yields an empty table and a
 * scorer that finds nothing, rather than a crash. The `permissive` flag is what makes a
 * partially-configured estate usable — see `loadUnusualParentChildAnomalyConfig`.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { dataPath } from '../../lib/paths.js';
import { round } from '../../stats/descriptive.js';
import type { UnusualParentChildAnomalyCandidate } from '../../schema/candidates.js';
import type { ProcessCreateEvent } from '../../schema/events.js';
import { assignDeterministicCandidateIds } from './candidate-id.js';
import {
  classifyChildCategory,
  DEFAULT_UNUSUAL_PARENT_CHILD_SUSPICIOUS_CHILDREN,
  loadSuspiciousChildPathRules,
  loadUnusualParentChildTaxonomyFile,
  loadUnusualParentChildWhitelistFile,
  lookupParentChildTier,
  matchesWhitelistRule,
  matchSuspiciousChildPath,
  normalizeBasename,
  type ParentTaxonomyEntry,
  type SuspiciousChildPathRule,
  type UnusualParentCategory,
  type UnusualParentChildTier,
  type WhitelistRule,
} from './unusual-parent-child-anomaly-taxonomy.js';
import {
  getParameterValues,
  hasCanonicalFlag,
  tokenizePowerShellCommandLine,
} from './powershell-cmdline-tokenizer.js';

export interface UnusualParentChildAnomalyConfig {
  min_emit_score: number;
  taxonomy: Map<string, ParentTaxonomyEntry[]>;
  whitelist: WhitelistRule[];
  suspicious_children: ReadonlySet<string>;
  suspicious_child_path_rules: readonly SuspiciousChildPathRule[];
}

export interface LoadUnusualParentChildAnomalyConfigOptions {
  dataDirPath?: string;
  taxonomyPath?: string;
  whitelistPath?: string;
  permissive?: boolean;
}

const DEFAULT_DATA_DIR = dataPath('unusual-parent-child-anomaly');
const TAXONOMY_PATH = join(DEFAULT_DATA_DIR, 'parent-taxonomy.csv');
const WHITELIST_PATH = join(DEFAULT_DATA_DIR, 'whitelist.csv');
const SUSPICIOUS_CHILD_PATHS_PATH = join(DEFAULT_DATA_DIR, 'suspicious-child-paths.csv');

function buildBaseConfig(): UnusualParentChildAnomalyConfig {
  return {
    min_emit_score: 0.30,
    taxonomy: new Map<string, ParentTaxonomyEntry[]>(),
    whitelist: [],
    suspicious_children: new Set(DEFAULT_UNUSUAL_PARENT_CHILD_SUSPICIOUS_CHILDREN),
    suspicious_child_path_rules: loadSuspiciousChildPathRules(SUSPICIOUS_CHILD_PATHS_PATH),
  };
}

function asNonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizePath(value: string | null | undefined): string {
  return (value ?? '').trim().replace(/\//g, '\\');
}

function parentLookupKey(host: string | null, processGuid: string | null): string {
  return `${host ?? ''}\x1f${processGuid ?? ''}`;
}

function hasHiddenWindow(windowStyleValues: string[]): boolean {
  return windowStyleValues.some((value) => {
    const normalized = value.trim().toLowerCase();
    return normalized === 'hidden' || normalized === '1';
  });
}

function hasExecutionPolicyBypass(values: string[]): boolean {
  return values.some((value) => value.trim().toLowerCase() === 'bypass');
}

function hasVersion2(values: string[]): boolean {
  return values.some((value) => value.trim().toLowerCase().startsWith('2'));
}

function hasSuspiciousCommandlineFlag(commandLine: string): boolean {
  const tokenized = tokenizePowerShellCommandLine(commandLine);
  const windowStyleValues = getParameterValues(tokenized, 'WindowStyle');
  const executionPolicyValues = getParameterValues(tokenized, 'ExecutionPolicy');
  const versionValues = getParameterValues(tokenized, 'Version');

  return hasCanonicalFlag(tokenized, 'EncodedCommand')
    || hasCanonicalFlag(tokenized, 'NoProfile')
    || hasCanonicalFlag(tokenized, 'NonInteractive')
    || hasCanonicalFlag(tokenized, 'STA')
    || hasHiddenWindow(windowStyleValues)
    || hasExecutionPolicyBypass(executionPolicyValues)
    || hasVersion2(versionValues);
}

function uniqueFlags(
  values: Array<'whitelist_matched' | 'parent_guid_missing'>,
): Array<'whitelist_matched' | 'parent_guid_missing'> {
  const out: Array<'whitelist_matched' | 'parent_guid_missing'> = [];
  for (const value of values) {
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

function canonicalParentCategory(raw: ParentTaxonomyEntry['parent_category']): UnusualParentCategory {
  if (raw === 'service_host') return 'service_host';
  return raw;
}

function buildParentLookup(events: ProcessCreateEvent[]): Map<string, ProcessCreateEvent> {
  const out = new Map<string, ProcessCreateEvent>();

  for (const event of events) {
    const guid = asNonEmptyString(event.process_guid);
    if (!guid) continue;

    const host = asNonEmptyString(event.host);
    out.set(parentLookupKey(host, guid), event);
    out.set(guid, event);
  }

  return out;
}

function lookupParentEvent(
  lookup: ReadonlyMap<string, ProcessCreateEvent>,
  host: string | null,
  parentGuid: string | null,
): ProcessCreateEvent | null {
  if (!parentGuid) return null;

  const byHostKey = lookup.get(parentLookupKey(host, parentGuid));
  if (byHostKey) return byHostKey;

  return lookup.get(parentGuid) ?? null;
}

interface TierResult {
  tier: UnusualParentChildTier;
  score: number;
  parent_category: UnusualParentCategory;
  whitelistMatched: boolean;
}

function resolveTierResult(
  event: ProcessCreateEvent,
  parentBasename: string,
  childBasename: string,
  parentEvent: ProcessCreateEvent | null,
  config: UnusualParentChildAnomalyConfig,
  pathRule: SuspiciousChildPathRule | null,
): TierResult {
  // Whitelist precedence (ruling 2026-07-20): events admitted via a suspicious-child
  // PATH RULE bypass the parent whitelist. The whitelist trusts a parent's ordinary
  // spawning behavior; suspicious child provenance (an executable run from the npm
  // package-manager cache) is exactly the signal that overrides that trust.
  // Basename-gated events keep today's whitelist-first behavior unchanged.
  if (!pathRule) {
    for (const rule of config.whitelist) {
      if (
        !matchesWhitelistRule(
          rule,
          event.parent_process_path,
          event.parent_process_name,
          parentEvent?.command_line ?? null,
        )
      ) {
        continue;
      }

      return {
        tier: 'benign',
        score: 0,
        parent_category: 'whitelisted',
        whitelistMatched: true,
      };
    }
  }

  const taxonomyEntry = lookupParentChildTier(config.taxonomy, parentBasename, childBasename);
  if (taxonomyEntry) {
    return {
      tier: taxonomyEntry.tier,
      score: taxonomyEntry.score,
      parent_category: canonicalParentCategory(taxonomyEntry.parent_category),
      whitelistMatched: false,
    };
  }

  if (pathRule) {
    return {
      tier: pathRule.tier,
      score: pathRule.score,
      parent_category: 'unknown',
      whitelistMatched: false,
    };
  }

  return {
    tier: 'unknown',
    score: 0.30,
    parent_category: 'unknown',
    whitelistMatched: false,
  };
}

// Spawn-signature aggregation (detection-engineering dedup, Sigma-correlation /
// EDR-alert style): duplicate observations of one logical spawn — e.g. generator
// eid1s differing only in host-string (IP vs hostname), guid, pid, and timestamp —
// collapse into a single candidate. The signature deliberately EXCLUDES host so a
// hostname-observed and a src-IP-observed record of the same spawn unify.
function spawnSignatureKey(candidate: UnusualParentChildAnomalyCandidate): string {
  return [
    normalizeBasename(candidate.parent_image || candidate.parent_process_name),
    normalizeBasename(candidate.process_name),
    normalizePath(candidate.image),
    candidate.user,
  ].join('\x1f');
}

function comparePrimaryPreference(
  left: UnusualParentChildAnomalyCandidate,
  right: UnusualParentChildAnomalyCandidate,
): number {
  if (left.time_window_start !== right.time_window_start) {
    return left.time_window_start.localeCompare(right.time_window_start);
  }
  if ((left.host ?? '') !== (right.host ?? '')) {
    return (left.host ?? '').localeCompare(right.host ?? '');
  }
  return left.process_guid.localeCompare(right.process_guid);
}

function aggregateSpawnSignatures(
  candidates: UnusualParentChildAnomalyCandidate[],
): UnusualParentChildAnomalyCandidate[] {
  const groups = new Map<string, UnusualParentChildAnomalyCandidate[]>();
  for (const candidate of candidates) {
    const key = spawnSignatureKey(candidate);
    const group = groups.get(key);
    if (group) group.push(candidate);
    else groups.set(key, [candidate]);
  }

  const out: UnusualParentChildAnomalyCandidate[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      out.push(group[0]);
      continue;
    }

    // Primary = earliest observation; the detection fires at first occurrence, so
    // every field (window end included) stays the primary's verbatim — later
    // identical observations are corroboration, not a wider incident window.
    let primary = group[0];
    for (const member of group) {
      if (comparePrimaryPreference(member, primary) < 0) primary = member;
    }

    const chronological = [...group].sort((left, right) =>
      left.time_window_start.localeCompare(right.time_window_start));

    out.push({
      ...primary,
      evidence: {
        ...primary.evidence,
        constituent_event_ids: chronological.flatMap(
          (member) => member.evidence.constituent_event_ids,
        ),
      },
    });
  }

  return out;
}

export function scoreUnusualParentChildAnomalyCandidates(
  events: ProcessCreateEvent[],
  config: UnusualParentChildAnomalyConfig = DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG,
  context: { parentLookup?: Map<string, ProcessCreateEvent> } = {},
): UnusualParentChildAnomalyCandidate[] {
  const suspiciousChildren = new Set(
    [...config.suspicious_children]
      .map((entry) => normalizeBasename(entry))
      .filter((entry) => entry.length > 0),
  );

  const parentLookup = context.parentLookup ?? buildParentLookup(events);
  const candidates: UnusualParentChildAnomalyCandidate[] = [];

  for (const event of events) {
    const childPathOrName = event.process_path || event.process_name;
    const childBasename = normalizeBasename(childPathOrName);
    const pathRule = matchSuspiciousChildPath(childPathOrName, config.suspicious_child_path_rules);
    if (!suspiciousChildren.has(childBasename) && !pathRule) continue;

    const parentBasename = normalizeBasename(event.parent_process_path || event.parent_process_name);
    const parentGuid = asNonEmptyString(event.parent_process_guid);
    const host = asNonEmptyString(event.host);
    const parentEvent = lookupParentEvent(parentLookup, host, parentGuid);

    const tierResult = resolveTierResult(event, parentBasename, childBasename, parentEvent, config, pathRule);
    const composite = Math.max(0, Math.min(1, tierResult.score));
    if (composite < config.min_emit_score) continue;

    const dataQualityFlags = uniqueFlags([
      ...(tierResult.whitelistMatched ? ['whitelist_matched' as const] : []),
      ...(!parentEvent ? ['parent_guid_missing' as const] : []),
    ]);

    candidates.push({
      candidate_id: '',
      type: 'unusual_parent_child_anomaly',
      time_window_start: event.timestamp,
      time_window_end: event.timestamp,
      host: event.host,

      process_guid: event.process_guid,
      parent_process_guid: parentGuid,
      image: normalizePath(event.process_path),
      process_name: event.process_name,
      parent_image: normalizePath(event.parent_process_path),
      parent_process_name: event.parent_process_name,
      command_line: event.command_line,
      user: event.user,

      parent_child_tradecraft_tier: round(composite, 4),
      unusual_parent_child_anomaly_score: round(composite, 4),
      tier: tierResult.tier,
      parent_category: tierResult.parent_category,
      child_category: classifyChildCategory(childBasename),

      grandparent_image: parentEvent ? normalizePath(parentEvent.parent_process_path) : null,
      grandparent_process_guid: parentEvent ? asNonEmptyString(parentEvent.parent_process_guid) : null,
      has_suspicious_commandline_flag: hasSuspiciousCommandlineFlag(event.command_line ?? ''),

      data_quality_flags: dataQualityFlags,

      process_id: event.process_id,
      enrichment: {},
      evidence: {
        constituent_event_ids: [event.id],
      },
    });
  }

  return assignDeterministicCandidateIds('UPC', aggregateSpawnSignatures(candidates).sort((left, right) => {
    if (right.unusual_parent_child_anomaly_score !== left.unusual_parent_child_anomaly_score) {
      return right.unusual_parent_child_anomaly_score - left.unusual_parent_child_anomaly_score;
    }
    if ((left.host ?? '') !== (right.host ?? '')) {
      return (left.host ?? '').localeCompare(right.host ?? '');
    }
    if (left.time_window_start !== right.time_window_start) {
      return left.time_window_start.localeCompare(right.time_window_start);
    }
    return left.process_guid.localeCompare(right.process_guid);
  }));
}

export function loadUnusualParentChildAnomalyConfig(
  options: LoadUnusualParentChildAnomalyConfigOptions = {},
): UnusualParentChildAnomalyConfig {
  const dataDirPath = options.dataDirPath ?? DEFAULT_DATA_DIR;
  const taxonomyPath = options.taxonomyPath ?? join(dataDirPath, 'parent-taxonomy.csv');
  const whitelistPath = options.whitelistPath ?? join(dataDirPath, 'whitelist.csv');
  const suspiciousChildPathsPath = join(dataDirPath, 'suspicious-child-paths.csv');
  const permissive = options.permissive === true;

  const missing: string[] = [];
  if (!existsSync(taxonomyPath)) missing.push(`taxonomy: ${taxonomyPath}`);
  if (!existsSync(whitelistPath)) missing.push(`whitelist: ${whitelistPath}`);
  if (missing.length > 0 && !permissive) {
    throw new Error(`Missing Unusual Parent-Child config file(s): ${missing.join(', ')}`);
  }

  const config = buildBaseConfig();
  config.taxonomy = loadUnusualParentChildTaxonomyFile(taxonomyPath);
  config.whitelist = loadUnusualParentChildWhitelistFile(whitelistPath);
  config.suspicious_child_path_rules = loadSuspiciousChildPathRules(suspiciousChildPathsPath);
  return config;
}

export const DEFAULT_UNUSUAL_PARENT_CHILD_ANOMALY_CONFIG: UnusualParentChildAnomalyConfig = (() => {
  try {
    return loadUnusualParentChildAnomalyConfig({ permissive: true });
  } catch {
    return buildBaseConfig();
  }
})();

export function resetCandidateCounter(): void {}

export const DEFAULT_UNUSUAL_PARENT_CHILD_DATA_PATHS = {
  taxonomy_path: TAXONOMY_PATH,
  whitelist_path: WHITELIST_PATH,
} as const;
