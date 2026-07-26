// Emit floors: the per-candidate-type minimum score a candidate must reach to be emitted.
//
// A distillation with no floor is not a distillation — every entity that clears a
// scorer's minimum evidence threshold produces a candidate, and most of them score low
// for the good reason that they are ordinary. Emitting all of them hands the volume
// problem back to whoever reads the output.
//
// But a threshold that DELETES evidence without saying so is the thing this tool argues
// against. So `applyEmitFloor` does not filter — it PARTITIONS, and returns both halves.
// What falls below the floor becomes the caput mortuum, which the run counts in its
// summary and `--discards` writes to disk, each record stamped with the `emit_floor`
// that cut it. A floor set too high is invisible from the output side; reading what it
// dropped is the only way to audit one.
//
// The two parsers are split — block-shape check, then per-value parse — because a config
// file is merged key by key, so each declared floor is validated on its own.
import type { PostEnrichmentCandidate } from '../pipeline/types/post-enrichment-candidate.js';

/** Refuses an `emit_floors` that is not a mapping of candidate type to score. */
export function assertEmitFloorsMapping(raw: unknown, configPath: string): void {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(
      `Invalid scenario config at ${configPath}: `
      + 'emit_floors must be a mapping of candidate type to minimum score',
    );
  }
}

/**
 * One floor value, validated and coerced. Must be a number in [0, 1]; a numeric string
 * is coerced, because YAML makes `0.4` and `"0.4"` easy to confuse and refusing the
 * second helps nobody.
 */
export function parseEmitFloorValue(type: string, value: unknown, configPath: string): number {
  const num = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(num) || num < 0 || num > 1) {
    throw new Error(
      `Invalid scenario config at ${configPath}: emit_floors.${type} must be a number in [0, 1]`,
    );
  }
  return num;
}

/**
 * A discarded candidate, stamped with the floor that discarded it.
 *
 * The stamp is on the DISCARD only, never on an emitted candidate: `emit_floor` is a
 * fact about the decision, not about the entity, and an emitted candidate's floor is
 * the one it cleared rather than the one it met. `--discards` output is also the
 * artifact a student opens on its own hours later, with no CLI summary on screen next
 * to it — a discard pile that cannot say what cut it is asking to be taken on trust.
 */
export type DiscardedCandidate<T> = T & { emit_floor: number };

export interface EmitFloorResult<T> {
  /** Candidates at or above the floor — what gets emitted. */
  kept: T[];
  /**
   * The discard pile: candidates the floor dropped. Alchemically, the caput mortuum —
   * the worthless residue left in the athanor after distillation. Returned rather
   * than discarded so a student can see exactly what the floor cost them.
   */
  caputMortuum: DiscardedCandidate<T>[];
}

/**
 * Apply `emitFloors[candidateType]` to one type's scored, enriched candidates.
 * The score field is `<candidate_type>_score` by convention, and a candidate whose score
 * field is absent or non-numeric is KEPT: a floor only ever drops candidates it can
 * measure. A type with no floor configured keeps everything.
 */
export function applyEmitFloor<T extends PostEnrichmentCandidate>(
  candidateType: string,
  candidates: readonly T[],
  emitFloors: Record<string, number>,
): EmitFloorResult<T> {
  const floor = emitFloors[candidateType];
  if (floor === undefined) {
    return { kept: [...candidates], caputMortuum: [] };
  }

  const scoreField = `${candidateType}_score`;
  const kept: T[] = [];
  const caputMortuum: DiscardedCandidate<T>[] = [];
  for (const candidate of candidates) {
    const score = (candidate as unknown as Record<string, unknown>)[scoreField];
    if (typeof score !== 'number' || score >= floor) {
      kept.push(candidate);
    } else {
      caputMortuum.push({ ...candidate, emit_floor: floor });
    }
  }

  return { kept, caputMortuum };
}
