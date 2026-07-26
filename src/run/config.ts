// Athanor's config surface.
//
// The defaults below are the configuration that produced the committed goldens in
// `fixtures/`. They are baked in rather than read from a file, so athanor distills the
// same way out of the box as it does under test.
//
// An optional `athanor.yaml` overrides them. A file is only read when `--config` NAMES
// one: athanor never picks up a stray `athanor.yaml` from the working directory, because
// a config that is found rather than named changes scores without anyone asking.
//
// The override is a PER-KEY DEEP MERGE, and the three rules are the whole of it:
//
//   1. a key the config names takes the config's value;
//   2. a key the config does NOT name keeps its canon default;
//   3. a key the config sets to `null` is REMOVED — the "clear this floor" path.
//
// So `emit_floors: {beacon: 0.2}` lowers the beacon floor and leaves the other
// three standing, and `emit_floors: {tls_anomaly: null}` deletes the TLS floor and
// leaves the rest. A config is read as what it says, not as what it forgot to say.
// The surface is deliberately small: candidate types, emit floors, presentation ids.
// Scorer weights and thresholds are NOT reachable from here — see `docs/design.md`.
import { existsSync, readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { assertEmitFloorsMapping, parseEmitFloorValue } from './floors.js';

export interface PresentationIdConfig {
  enabled: boolean;
  prefixes: Record<string, string>;
}

export interface AthanorConfig {
  /** Candidate types to distill, in emit order. */
  candidateTypes: string[];
  /** Per-type minimum score; candidates below it become caput mortuum. */
  emitFloors: Record<string, number>;
  /** Score-ranked human-facing ids (BCN-001…); null disables the rename. */
  presentationIds: PresentationIdConfig | null;
}

/**
 * The shipped defaults. `data_transfer` deliberately has NO floor — four floors, five
 * candidate types — so every data-transfer candidate that clears the scorer's own 1 MB
 * minimum is emitted.
 */
export const DEFAULT_ATHANOR_CONFIG: AthanorConfig = {
  candidateTypes: [
    'beacon',
    'data_transfer',
    'tls_anomaly',
    'unusual_parent_child_anomaly',
    'powershell_invocation_anomaly',
  ],
  emitFloors: {
    beacon: 0.40,
    powershell_invocation_anomaly: 0.60,
    unusual_parent_child_anomaly: 0.60,
    tls_anomaly: 0.40,
  },
  presentationIds: {
    enabled: true,
    prefixes: {
      data_transfer: 'DT',
      unusual_parent_child_anomaly: 'UPCA',
    },
  },
};

export const DEFAULT_ATHANOR_CONFIG_FILENAME = 'athanor.yaml';

export function defaultAthanorConfig(): AthanorConfig {
  return {
    candidateTypes: [...DEFAULT_ATHANOR_CONFIG.candidateTypes],
    emitFloors: { ...DEFAULT_ATHANOR_CONFIG.emitFloors },
    presentationIds: DEFAULT_ATHANOR_CONFIG.presentationIds
      ? {
        enabled: DEFAULT_ATHANOR_CONFIG.presentationIds.enabled,
        prefixes: { ...DEFAULT_ATHANOR_CONFIG.presentationIds.prefixes },
      }
      : null,
  };
}

// ─── config parsers ───

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function dedupeOrdered(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const deduped: string[] = [];

  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    deduped.push(value);
  }

  return deduped;
}

function parseDistillCandidates(value: unknown, configPath: string): string[] {
  if (value === undefined) return [];
  // A LIST is not a mapping: there are no per-key names to merge, and its order is
  // the emit order — so a declared list replaces the default list whole. What the
  // merge rules do buy it is that "declared empty" can no longer be read as
  // "declared nothing": both of the shapes that would silently distill NOTHING are
  // refused here instead of quietly falling back to the canon five.
  if (value === null) {
    throw new Error(
      `Invalid scenario distillation config at ${configPath}: `
      + 'distill_candidates is null, which would distill nothing — remove the key to keep '
      + 'the default list, or name the candidate types you want',
    );
  }
  if (!Array.isArray(value)) {
    throw new Error(
      `Invalid scenario distillation config at ${configPath}: `
      + 'distill_candidates must be an array of non-empty strings when provided',
    );
  }
  if (value.length === 0) {
    throw new Error(
      `Invalid scenario distillation config at ${configPath}: `
      + 'distill_candidates is empty, which would distill nothing — remove the key to keep '
      + 'the default list, or name the candidate types you want',
    );
  }

  const parsed = value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      throw new Error(
        `Invalid scenario distillation config at ${configPath}: `
        + `distill_candidates[${index}] must be a non-empty string`,
      );
    }
    return entry.trim();
  });

  return dedupeOrdered(parsed);
}

// ─── athanor config resolution ───

/**
 * What a config file changed, in dotted key names (`emit_floors.beacon`). Exists so
 * the CLI can report the effective config in one line: a merge that is invisible is
 * a merge nobody can debug.
 */
export interface ConfigMergeSummary {
  /** Keys the config gave a value — an override of a default, or an addition. */
  overridden: string[];
  /** Keys the config removed by setting them to `null`. */
  removed: string[];
}

export interface ResolvedAthanorConfig {
  config: AthanorConfig;
  summary: ConfigMergeSummary;
}

/** `emit_floors`, merged per key over the canon floors. */
function mergeEmitFloors(
  raw: unknown,
  base: Record<string, number>,
  configPath: string,
  summary: ConfigMergeSummary,
): Record<string, number> {
  if (raw === undefined) return base;
  // `emit_floors: null` (or a bare `emit_floors:`) removes the block: no floors at
  // all, every candidate emitted however low it scores.
  if (raw === null) {
    summary.removed.push('emit_floors');
    return {};
  }
  assertEmitFloorsMapping(raw, configPath);

  const merged = { ...base };
  for (const [type, value] of Object.entries(raw as Record<string, unknown>)) {
    if (value === null) {
      delete merged[type];
      summary.removed.push(`emit_floors.${type}`);
      continue;
    }
    merged[type] = parseEmitFloorValue(type, value, configPath);
    summary.overridden.push(`emit_floors.${type}`);
  }
  return merged;
}

/** `presentation_ids`, merged per key (and `prefixes` per candidate type). */
function mergePresentationIds(
  raw: unknown,
  base: PresentationIdConfig | null,
  configPath: string,
  summary: ConfigMergeSummary,
): PresentationIdConfig | null {
  if (raw === undefined) return base;
  // `presentation_ids: null` removes the block: candidates keep their deterministic
  // ids and no `pipeline_candidate_id` is assigned.
  if (raw === null) {
    summary.removed.push('presentation_ids');
    return null;
  }
  const block = asObject(raw);
  if (!block) {
    throw new Error(
      `Invalid scenario config at ${configPath}: `
      + 'presentation_ids must be a mapping with an enabled flag',
    );
  }

  const baseBlock = base ?? { enabled: true, prefixes: {} };

  let enabled = baseBlock.enabled;
  if (block['enabled'] !== undefined) {
    if (typeof block['enabled'] !== 'boolean') {
      throw new Error(
        `Invalid scenario config at ${configPath}: presentation_ids.enabled must be a boolean`,
      );
    }
    enabled = block['enabled'];
    summary.overridden.push('presentation_ids.enabled');
  }

  const prefixes: Record<string, string> = { ...baseBlock.prefixes };
  const rawPrefixes = block['prefixes'];
  if (rawPrefixes === null) {
    for (const type of Object.keys(prefixes)) delete prefixes[type];
    summary.removed.push('presentation_ids.prefixes');
  } else if (rawPrefixes !== undefined) {
    const prefixMap = asObject(rawPrefixes);
    if (!prefixMap) {
      throw new Error(
        `Invalid scenario config at ${configPath}: `
        + 'presentation_ids.prefixes must be a mapping of candidate type to prefix string',
      );
    }
    for (const [type, value] of Object.entries(prefixMap)) {
      if (value === null) {
        delete prefixes[type];
        summary.removed.push(`presentation_ids.prefixes.${type}`);
        continue;
      }
      if (typeof value !== 'string' || value.trim().length === 0) {
        throw new Error(
          `Invalid scenario config at ${configPath}: `
          + `presentation_ids.prefixes.${type} must be a non-empty string`,
        );
      }
      prefixes[type] = value.trim();
      summary.overridden.push(`presentation_ids.prefixes.${type}`);
    }
  }

  return { enabled, prefixes };
}

/**
 * Parse an already-loaded YAML/JSON config object over the course-canon defaults,
 * reporting what it changed.
 *
 * Per-key deep merge (the three rules at the top of this file): a named key wins, an
 * unnamed key keeps its default, an explicit `null` removes. `distill_candidates` is
 * the one exception, and only because it is a list rather than a mapping — see
 * `parseDistillCandidates`.
 */
export function parseAthanorConfigWithSummary(
  loaded: unknown,
  configPath: string,
): ResolvedAthanorConfig {
  const config = asObject(loaded);
  if (!config) {
    throw new Error(`Invalid athanor config at ${configPath}: top-level YAML must be an object`);
  }

  const resolved = defaultAthanorConfig();
  const summary: ConfigMergeSummary = { overridden: [], removed: [] };

  if (config['distill_candidates'] !== undefined) {
    resolved.candidateTypes = parseDistillCandidates(config['distill_candidates'], configPath);
    summary.overridden.push('distill_candidates');
  }

  resolved.emitFloors = mergeEmitFloors(
    config['emit_floors'],
    resolved.emitFloors,
    configPath,
    summary,
  );
  resolved.presentationIds = mergePresentationIds(
    config['presentation_ids'],
    resolved.presentationIds,
    configPath,
    summary,
  );

  return { config: resolved, summary };
}

/** `parseAthanorConfigWithSummary` without the merge report. */
export function parseAthanorConfig(loaded: unknown, configPath: string): AthanorConfig {
  return parseAthanorConfigWithSummary(loaded, configPath).config;
}

/** Read an `athanor.yaml` (or any scenario YAML) from disk over the canon defaults. */
export function loadAthanorConfigWithSummary(configPath: string): ResolvedAthanorConfig {
  if (!existsSync(configPath)) {
    throw new Error(`athanor config not found: ${configPath}`);
  }
  return parseAthanorConfigWithSummary(parseYaml(readFileSync(configPath, 'utf-8')), configPath);
}

/** `loadAthanorConfigWithSummary` without the merge report. */
export function loadAthanorConfig(configPath: string): AthanorConfig {
  return loadAthanorConfigWithSummary(configPath).config;
}

/**
 * Overlay a partial in-memory config on the canon defaults.
 *
 * This is the PROGRAMMATIC seam, and its semantics are per-FIELD replacement, not the
 * YAML file's per-key merge: a caller passing `emitFloors` is handing over the whole
 * map it wants, and a typed object has no way to say "remove this one key" that a
 * plain omission does not already say better. Merge the map yourself
 * (`{...defaultAthanorConfig().emitFloors, beacon: 0.2}`) when that is what you mean.
 */
export function resolveAthanorConfig(overrides?: Partial<AthanorConfig>): AthanorConfig {
  const resolved = defaultAthanorConfig();
  if (!overrides) return resolved;

  if (overrides.candidateTypes !== undefined) {
    resolved.candidateTypes = [...overrides.candidateTypes];
  }
  if (overrides.emitFloors !== undefined) {
    resolved.emitFloors = { ...overrides.emitFloors };
  }
  if (overrides.presentationIds !== undefined) {
    resolved.presentationIds = overrides.presentationIds
      ? {
        enabled: overrides.presentationIds.enabled,
        prefixes: { ...overrides.presentationIds.prefixes },
      }
      : null;
  }

  return resolved;
}
