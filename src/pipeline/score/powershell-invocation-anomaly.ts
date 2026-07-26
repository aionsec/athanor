/**
 * PowerShell invocation scoring — stage 3 for the `powershell_invocation_anomaly` type.
 *
 * PowerShell is an administration tool, an installer runtime and an intrusion toolkit,
 * and the same binary does all three. Nothing about the presence of `powershell.exe` on a
 * host says anything. What says something is HOW it was invoked — and that question has
 * four independent answers, which is why this scorer has four dimensions.
 *
 * Entity: ONE process-create event. Optionally correlated with an EID 7 image-load event
 * on the same `(host, process_guid)` within a time window.
 *
 * FOUR DIMENSIONS, COMBINED WITH max():
 *
 *   1. RENAME       a binary whose `OriginalFileName` is `powershell.exe` while its
 *                   image is called something else. PE metadata survives a copy; the
 *                   file name does not. This is the cheapest evasion there is and the
 *                   cheapest to catch — a clean rename scores 1.0.
 *   2. CUSTOM HOST  a process loading `System.Management.Automation.dll` without being a
 *                   recognized PowerShell host. Running the engine in-process skips
 *                   `powershell.exe` entirely, so every name-based check misses it.
 *                   REQUIRES EID 7 events; without them the dimension records
 *                   `custom_host_uncheckable` and scores 0.
 *   3. PARENT       the spawning process, against a taxonomy — an Office application, a
 *                   browser or a web server starting PowerShell is a different event
 *                   from a management agent doing it.
 *   4. COMMAND LINE the invocation itself, graded in five tiers rather than counted.
 *                   `-EncodedCommand` + `-NoProfile` + `-STA` + hidden window together is
 *                   tier 1 (1.0) — that exact combination is a tool fingerprint, not four
 *                   independent choices. So is `-Version 2`, which downgrades to a
 *                   PowerShell with no script-block logging. Three suspicious flags in any
 *                   arrangement is tier 2 (0.90); encoding plus one other is tier 3
 *                   (0.75); a hidden window plus one other is tier 4 (0.60); encoding
 *                   alone is tier 5 (0.40); anything else is benign (0.0). The Shannon
 *                   entropy of an encoded payload is recorded either way.
 *                   The command line is TOKENIZED, not substring-matched — PowerShell
 *                   accepts abbreviated parameters, and `-enc` as a substring finds
 *                   things that are not `-EncodedCommand`.
 *
 * max() rather than a weighted sum, for the same reason the TLS scorer uses it: these are
 * four ALTERNATIVE ways to reach the same conclusion, not four parts of one. A renamed
 * binary is damning whatever its command line looks like. `dominant_dimension` records
 * which one won, so a reader knows what they are looking at without re-deriving it.
 *
 * Two suppression paths, applied BEFORE any dimension runs, because this scorer fires on
 * a very common binary: `hard_parent_exclusions` (regex over the parent path) and
 * `vendor_pairs` (parent path plus command-line pattern) each skip the event entirely.
 * Legitimate software produces alarming-looking invocations on every host, every day.
 *
 * Config loading is PERMISSIVE-OPTIONAL: a missing data file yields an empty table and a
 * scorer that finds less, rather than a crash.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { dataPath } from '../../lib/paths.js';
import { round } from '../../stats/descriptive.js';
import type { PowerShellInvocationAnomalyCandidate } from '../../schema/candidates.js';
import type { ImageLoadEvent, ProcessCreateEvent, TelemetryEvent } from '../../schema/events.js';
import { isImageLoadEventType, isProcessCreateEventType } from '../../schema/events.js';
import { assignDeterministicCandidateIds } from './candidate-id.js';
import {
  basenameFromPath,
  classifyCommandLine,
  classifyCustomHost,
  classifyParent,
  classifyRename,
  dominantDimension,
  normalizePath,
  type HostAllowlistEntry,
  type ParentTaxonomyEntry,
} from './powershell-invocation-anomaly-classifiers.js';

export interface ParentHardExclusionRule {
  source: string;
  regex: string;
}

export interface VendorPairWhitelistEntry {
  parent_process_path_pattern: string;
  command_line_pattern: string;
}

export interface PowerShellInvocationConfig {
  min_dimension_score: number;
  custom_host_correlation_window_ms: number;
  hard_parent_exclusions: ParentHardExclusionRule[];
  host_allowlist: Map<string, HostAllowlistEntry[]>;
  parent_taxonomy: Map<string, ParentTaxonomyEntry>;
  vendor_pairs: VendorPairWhitelistEntry[];
}

export interface LoadPowerShellInvocationConfigOptions {
  dataDirPath?: string;
  whitelistDir?: string;
  permissive?: boolean;
}

const DEFAULT_DATA_DIR = dataPath('powershell-invocation');
const DEFAULT_WHITELIST_DIR = dataPath('whitelists');

const HARD_EXCLUSIONS_PATH = join(DEFAULT_DATA_DIR, 'parent-hard-exclusions.json');
const HOST_ALLOWLIST_PATH = join(DEFAULT_DATA_DIR, 'host-allowlist.json');
const PARENT_TAXONOMY_PATH = join(DEFAULT_DATA_DIR, 'parent-taxonomy.csv');
const VENDOR_PAIRS_PATH = join(DEFAULT_WHITELIST_DIR, 'powershell-invocation-vendor-pairs.csv');

const SMA_DLL_NAMES = [
  'system.management.automation.dll',
  'system.management.automation.ni.dll',
];

function parseCsvLines(raw: string): string[] {
  const lines: string[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    const inlineCommentIdx = trimmed.indexOf('#');
    const withoutComment = inlineCommentIdx === -1
      ? trimmed
      : trimmed.slice(0, inlineCommentIdx).trim();
    if (withoutComment.length > 0) lines.push(withoutComment);
  }
  return lines;
}

function buildBaseConfig(): PowerShellInvocationConfig {
  return {
    min_dimension_score: 0.30,
    custom_host_correlation_window_ms: 30_000,
    hard_parent_exclusions: [],
    host_allowlist: new Map<string, HostAllowlistEntry[]>(),
    parent_taxonomy: new Map<string, ParentTaxonomyEntry>(),
    vendor_pairs: [],
  };
}

function toLower(value: string | null | undefined): string {
  return (value ?? '').trim().toLowerCase();
}

function ensureAnchoredRegex(regex: string): void {
  const trimmed = regex.trim();
  if (!trimmed.startsWith('^') || !trimmed.endsWith('$')) {
    throw new Error(`Unanchored hard-exclusion regex (must be ^...$): ${regex}`);
  }
}

export function loadPowerShellParentHardExclusionsFile(path: string): ParentHardExclusionRule[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, 'utf-8');
  const parsed = JSON.parse(raw) as Array<{ source?: string; regex?: string }>;
  const out: ParentHardExclusionRule[] = [];

  for (const item of parsed) {
    const source = (item.source ?? '').trim();
    const regex = (item.regex ?? '').trim();
    if (source.length === 0 || regex.length === 0) continue;
    ensureAnchoredRegex(regex);
    out.push({ source, regex });
  }

  return out;
}

export function loadPowerShellHostAllowlistFile(path: string): Map<string, HostAllowlistEntry[]> {
  if (!existsSync(path)) return new Map<string, HostAllowlistEntry[]>();
  const raw = readFileSync(path, 'utf-8');
  const parsed = JSON.parse(raw) as HostAllowlistEntry[];
  const out = new Map<string, HostAllowlistEntry[]>();

  for (const entry of parsed) {
    const normalizedName = basenameFromPath(entry.process_name);
    if (normalizedName.length === 0) continue;
    const normalizedEntry: HostAllowlistEntry = {
      ...entry,
      process_name: normalizedName,
      path_prefix: entry.path_prefix ? normalizePath(entry.path_prefix) : undefined,
    };
    const bucket = out.get(normalizedName) ?? [];
    bucket.push(normalizedEntry);
    out.set(normalizedName, bucket);
  }

  return out;
}

export function loadPowerShellParentTaxonomyFile(path: string): Map<string, ParentTaxonomyEntry> {
  if (!existsSync(path)) return new Map<string, ParentTaxonomyEntry>();
  const raw = readFileSync(path, 'utf-8');
  const out = new Map<string, ParentTaxonomyEntry>();

  for (const line of parseCsvLines(raw)) {
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const parentBasename = basenameFromPath(parts[0]);
    const category = parts[1].trim() as ParentTaxonomyEntry['category'];
    const score = Number.parseFloat(parts[2].trim());
    if (parentBasename.length === 0 || !Number.isFinite(score)) continue;
    out.set(parentBasename, {
      parent_basename: parentBasename,
      category,
      score: Math.max(0, Math.min(1, score)),
    });
  }

  return out;
}

function normalizePattern(value: string): string {
  return value.trim().replace(/\//g, '\\').toLowerCase();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function loadPowerShellVendorPairWhitelistFile(path: string): VendorPairWhitelistEntry[] {
  if (!existsSync(path)) return [];
  const raw = readFileSync(path, 'utf-8');
  const out: VendorPairWhitelistEntry[] = [];

  for (const line of parseCsvLines(raw)) {
    const parts = line.split(',');
    if (parts.length < 2) continue;
    const parentPattern = normalizePattern(parts[0]);
    const cmdPattern = normalizePattern(parts.slice(1).join(','));
    if (parentPattern.length === 0 || cmdPattern.length === 0) continue;
    out.push({
      parent_process_path_pattern: parentPattern,
      command_line_pattern: cmdPattern,
    });
  }

  return out;
}

export function loadPowerShellInvocationConfig(
  options: LoadPowerShellInvocationConfigOptions = {},
): PowerShellInvocationConfig {
  const dataDirPath = options.dataDirPath ?? DEFAULT_DATA_DIR;
  const whitelistDir = options.whitelistDir ?? DEFAULT_WHITELIST_DIR;
  const permissive = options.permissive === true;

  const hardExclusionsPath = join(dataDirPath, 'parent-hard-exclusions.json');
  const hostAllowlistPath = join(dataDirPath, 'host-allowlist.json');
  const parentTaxonomyPath = join(dataDirPath, 'parent-taxonomy.csv');
  const vendorPairsPath = join(whitelistDir, 'powershell-invocation-vendor-pairs.csv');

  const missing: string[] = [];
  if (!existsSync(hardExclusionsPath)) missing.push(`hard exclusions: ${hardExclusionsPath}`);
  if (!existsSync(hostAllowlistPath)) missing.push(`host allowlist: ${hostAllowlistPath}`);
  if (!existsSync(parentTaxonomyPath)) missing.push(`parent taxonomy: ${parentTaxonomyPath}`);
  if (!existsSync(vendorPairsPath)) missing.push(`vendor pairs: ${vendorPairsPath}`);
  if (missing.length > 0 && !permissive) {
    throw new Error(`Missing PowerShell Invocation config file(s): ${missing.join(', ')}`);
  }

  const config = buildBaseConfig();
  config.hard_parent_exclusions = loadPowerShellParentHardExclusionsFile(hardExclusionsPath);
  config.host_allowlist = loadPowerShellHostAllowlistFile(hostAllowlistPath);
  config.parent_taxonomy = loadPowerShellParentTaxonomyFile(parentTaxonomyPath);
  config.vendor_pairs = loadPowerShellVendorPairWhitelistFile(vendorPairsPath);
  return config;
}

export const DEFAULT_POWERSHELL_INVOCATION_CONFIG: PowerShellInvocationConfig = (() => {
  try {
    return loadPowerShellInvocationConfig({ permissive: true });
  } catch {
    return buildBaseConfig();
  }
})();

function wildcardContainsMatch(value: string, pattern: string): boolean {
  const normalizedValue = normalizePattern(value);
  const normalizedPattern = normalizePattern(pattern);
  if (normalizedPattern.includes('*')) {
    const regexSource = escapeRegExp(normalizedPattern).replace(/\\\*/g, '.*');
    if (regexSource.length === 0) return false;
    return new RegExp(regexSource, 'i').test(normalizedValue);
  }
  if (normalizedPattern.includes('\\')) return normalizedValue.includes(normalizedPattern);
  return basenameFromPath(normalizedValue) === basenameFromPath(normalizedPattern);
}

function matchesVendorWhitelist(
  parentProcessPath: string,
  commandLine: string,
  vendorPairs: VendorPairWhitelistEntry[],
): boolean {
  return vendorPairs.some((entry) =>
    wildcardContainsMatch(parentProcessPath, entry.parent_process_path_pattern)
    && wildcardContainsMatch(commandLine, entry.command_line_pattern));
}

function matchesHardExclusion(parentProcessPath: string, rules: ParentHardExclusionRule[]): boolean {
  if (parentProcessPath.length === 0) return false;
  return rules.some((rule) => {
    const regex = new RegExp(rule.regex, 'i');
    return regex.test(parentProcessPath);
  });
}

function isSmaDllImageLoad(imageLoaded: string): boolean {
  const normalized = normalizePath(imageLoaded);
  return SMA_DLL_NAMES.some((name) => normalized.endsWith(`\\${name}`) || normalized.endsWith(name));
}

function asString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value;
}

interface ParsedProcessCreate {
  id: string;
  timestamp: string;
  host: string;
  process_guid: string;
  process_name: string | null;
  process_path: string;
  process_id: number | null;
  parent_process_name: string | null;
  parent_process_path: string;
  parent_process_guid: string | null;
  user: string;
  original_file_name: string | null;
  description: string | null;
  product: string | null;
  company: string | null;
  command_line: string;
}

function parseProcessCreate(event: ProcessCreateEvent): ParsedProcessCreate | null {
  const host = asString(event.host);
  const processGuid = asString(event.process_guid);
  const timestamp = asString(event.timestamp);
  if (!host || !processGuid || !timestamp) return null;

  return {
    id: event.id,
    timestamp,
    host,
    process_guid: processGuid,
    process_name: asString(event.process_name),
    process_path: asString(event.process_path) ?? '',
    process_id: asNumber(event.process_id),
    parent_process_name: asString(event.parent_process_name),
    parent_process_path: asString(event.parent_process_path) ?? '',
    parent_process_guid: asString(event.parent_process_guid),
    user: asString(event.user) ?? '',
    original_file_name: event.original_file_name ?? null,
    description: event.description ?? null,
    product: event.product ?? null,
    company: event.company ?? null,
    command_line: asString(event.command_line) ?? '',
  };
}

interface ParsedImageLoad {
  id: string;
  timestamp: string;
  host: string;
  process_guid: string;
  image: string;
  image_loaded: string;
}

function parseImageLoad(event: ImageLoadEvent): ParsedImageLoad | null {
  const host = asString(event.host);
  const processGuid = asString(event.process_guid);
  const timestamp = asString(event.timestamp);
  if (!host || !processGuid || !timestamp) return null;

  return {
    id: event.id,
    timestamp,
    host,
    process_guid: processGuid,
    image: asString(event.image) ?? '',
    image_loaded: asString(event.image_loaded) ?? '',
  };
}

function buildImageLoadIndex(imageLoads: ParsedImageLoad[]): Map<string, ParsedImageLoad[]> {
  const out = new Map<string, ParsedImageLoad[]>();
  for (const imageLoad of imageLoads) {
    const key = `${imageLoad.host}\x1f${imageLoad.process_guid}`;
    const bucket = out.get(key) ?? [];
    bucket.push(imageLoad);
    out.set(key, bucket);
  }
  for (const [key, bucket] of out) {
    bucket.sort((left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime());
    out.set(key, bucket);
  }
  return out;
}

function findCorrelatedSmaLoad(
  processEvent: ParsedProcessCreate,
  imageLoadIndex: Map<string, ParsedImageLoad[]>,
  windowMs: number,
): ParsedImageLoad | null {
  const key = `${processEvent.host}\x1f${processEvent.process_guid}`;
  const entries = imageLoadIndex.get(key) ?? [];
  if (entries.length === 0) return null;

  const processTs = new Date(processEvent.timestamp).getTime();
  let bestMatch: ParsedImageLoad | null = null;
  let bestDelta = Number.POSITIVE_INFINITY;

  for (const entry of entries) {
    if (!isSmaDllImageLoad(entry.image_loaded)) continue;
    const delta = Math.abs(new Date(entry.timestamp).getTime() - processTs);
    if (delta > windowMs) continue;
    if (delta < bestDelta) {
      bestMatch = entry;
      bestDelta = delta;
    }
  }

  return bestMatch;
}

function uniqueFlags<T extends string>(values: Array<T | null>): T[] {
  const out: T[] = [];
  for (const value of values) {
    if (!value) continue;
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

function parseTimestampMs(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function computeEvidenceWindow(
  anchorTimestamp: string,
  evidenceIds: ReadonlyArray<string>,
  timestampByEventId: ReadonlyMap<string, string>,
): { start: string; end: string } {
  const anchorMs = parseTimestampMs(anchorTimestamp);
  if (anchorMs === null) {
    return {
      start: anchorTimestamp,
      end: anchorTimestamp,
    };
  }

  let minTs = anchorMs;
  let maxTs = anchorMs;

  for (const evidenceId of evidenceIds) {
    const evidenceTimestamp = timestampByEventId.get(evidenceId);
    if (!evidenceTimestamp) continue;

    const evidenceMs = parseTimestampMs(evidenceTimestamp);
    if (evidenceMs === null) continue;

    if (evidenceMs < minTs) minTs = evidenceMs;
    if (evidenceMs > maxTs) maxTs = evidenceMs;
  }

  return {
    start: new Date(minTs).toISOString(),
    end: new Date(maxTs).toISOString(),
  };
}

export function scorePowerShellInvocationAnomalyCandidates(
  events: TelemetryEvent[],
  config: PowerShellInvocationConfig = DEFAULT_POWERSHELL_INVOCATION_CONFIG,
): PowerShellInvocationAnomalyCandidate[] {
  const processCreates: ParsedProcessCreate[] = [];
  const imageLoads: ParsedImageLoad[] = [];
  const timestampByEventId = new Map<string, string>();

  for (const event of events) {
    if (event.source !== 'sysmon') continue;

    if (isProcessCreateEventType(event.event_type)) {
      const parsed = parseProcessCreate(event as ProcessCreateEvent);
      if (parsed) {
        processCreates.push(parsed);
        timestampByEventId.set(parsed.id, parsed.timestamp);
      }
      continue;
    }

    if (isImageLoadEventType(event.event_type)) {
      const parsed = parseImageLoad(event as ImageLoadEvent);
      if (parsed) {
        imageLoads.push(parsed);
        timestampByEventId.set(parsed.id, parsed.timestamp);
      }
    }
  }

  const imageLoadIndex = buildImageLoadIndex(imageLoads);
  const hasImageLoadTelemetry = imageLoads.length > 0;
  const candidates: PowerShellInvocationAnomalyCandidate[] = [];

  for (const event of processCreates) {
    if (matchesHardExclusion(event.parent_process_path, config.hard_parent_exclusions)) continue;
    if (matchesVendorWhitelist(event.parent_process_path, event.command_line, config.vendor_pairs)) continue;

    const rename = classifyRename(
      event.process_name,
      event.original_file_name,
      event.description,
      event.company,
    );

    const correlatedSmaLoad = findCorrelatedSmaLoad(
      event,
      imageLoadIndex,
      config.custom_host_correlation_window_ms,
    );
    const customHost = classifyCustomHost(
      event.process_name,
      event.process_path,
      config.host_allowlist,
      correlatedSmaLoad !== null,
      rename.force_host_category,
    );

    const parent = classifyParent(
      event.parent_process_name,
      event.parent_process_path,
      event.command_line,
      config.parent_taxonomy,
    );

    const cmdline = classifyCommandLine(event.command_line);
    const dataQualityFlags = uniqueFlags([
      rename.data_quality_flag,
      parent.data_quality_flag,
      !hasImageLoadTelemetry ? 'custom_host_uncheckable' : null,
    ]);

    const composite = Math.max(rename.score, customHost.score, parent.score, cmdline.score);
    if (composite < config.min_dimension_score) continue;

    const dominant = dominantDimension(rename.score, customHost.score, parent.score, cmdline.score);
    const evidenceIds = [event.id];
    if (correlatedSmaLoad && !evidenceIds.includes(correlatedSmaLoad.id)) evidenceIds.push(correlatedSmaLoad.id);
    const window = computeEvidenceWindow(event.timestamp, evidenceIds, timestampByEventId);

    candidates.push({
      candidate_id: '',
      type: 'powershell_invocation_anomaly',
      time_window_start: window.start,
      time_window_end: window.end,
      host: event.host,

      process_guid: event.process_guid,
      rename_suspicion: round(rename.score, 4),
      custom_host_suspicion: round(customHost.score, 4),
      parent_suspicion: round(parent.score, 4),
      commandline_suspicion: round(cmdline.score, 4),
      powershell_invocation_anomaly_score: round(composite, 4),

      dominant_dimension: dominant,
      host_category: customHost.host_category,
      parent_category: parent.parent_category,
      cmdline_classification: cmdline.cmdline_classification,
      cmdline_flags_detected: cmdline.cmdline_flags_detected,
      encoded_command_entropy:
        cmdline.encoded_command_entropy === null ? null : round(cmdline.encoded_command_entropy, 4),
      cmdline_length: event.command_line.length,

      process_name: event.process_name,
      process_path: event.process_path,
      original_file_name: event.original_file_name,
      description: event.description,
      product: event.product,
      company: event.company,
      command_line: event.command_line,
      user: event.user,
      process_id: event.process_id,
      parent_process_name: event.parent_process_name ?? '',
      parent_process_path: event.parent_process_path,
      parent_process_guid: event.parent_process_guid,
      sma_dll_loaded: correlatedSmaLoad !== null,
      sma_dll_load_image: correlatedSmaLoad?.image ?? null,
      data_quality_flags: dataQualityFlags,

      enrichment: {},
      evidence: {
        constituent_event_ids: evidenceIds,
      },
    });
  }

  return assignDeterministicCandidateIds('PSI', candidates.sort((left, right) => {
    if (right.powershell_invocation_anomaly_score !== left.powershell_invocation_anomaly_score) {
      return right.powershell_invocation_anomaly_score - left.powershell_invocation_anomaly_score;
    }
    if ((left.host ?? '') !== (right.host ?? '')) return (left.host ?? '').localeCompare(right.host ?? '');
    if (left.time_window_start !== right.time_window_start) return left.time_window_start.localeCompare(right.time_window_start);
    return left.process_guid.localeCompare(right.process_guid);
  }));
}

export function resetCandidateCounter(): void {}

// Exposed for tests and contract checks.
export const DEFAULT_POWERSHELL_INVOCATION_DATA_PATHS = {
  hard_exclusions_path: HARD_EXCLUSIONS_PATH,
  host_allowlist_path: HOST_ALLOWLIST_PATH,
  parent_taxonomy_path: PARENT_TAXONOMY_PATH,
  vendor_pairs_path: VENDOR_PAIRS_PATH,
} as const;
