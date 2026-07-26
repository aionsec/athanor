// The spine: the whole distillation pipe, end to end.
//
// Normalized events in, scored and enriched candidates out. Everything in `src/pipeline/`
// is a stage; this file is the order they run in and the accounting between them.
//
//   stage 2 enrich → [ per candidate type: select → score → attribute → LFA →
//                      stage 4 enrich → emit floor ] → presentation ids
//
// TWO PROPERTIES OF THAT ORDER ARE LOAD-BEARING.
//
// 1. Stage 2 runs ONCE, hoisted out of the per-type loop. `enrichEvents` is pure, so
//    enriching once and handing the result to five runners is identical to enriching
//    inside each of them — and it is what makes `runBackHalf`'s "these events are
//    already stage-2 output, do NOT re-enrich them" contract expressible at all.
//
// 2. Everything from `select` onward runs once PER CANDIDATE TYPE, and each per-type
//    runner is handed the FULL stage-2 event set. ONLY THE SCORER SEES A SUBSET.
//    Attribution needs the Sysmon events a network scorer never looked at; the frequency
//    tables need every host on the estate, or "rare" answers a narrower question than it
//    appears to. Narrowing here would be a silent correctness bug, not an optimization.
//
// The floors partition rather than delete: what falls below a type's floor goes into the
// caput mortuum, which is returned alongside the candidates. See `floors.ts` for why.
//
// Presentation ids come last, after the floors, because they are assigned by RANK — and
// ranking a list that still contains everything the floor was going to drop would
// number them differently.
import type { EnrichmentLabel } from '../pipeline/enrich-candidates/applicability.js';
import type { ThreatIntelFeed } from '../pipeline/enrich-candidates/threat-intel-loader.js';
import type { LfaTables } from '../pipeline/types/lfa-tables.js';
import type { PostEnrichmentCandidate } from '../pipeline/types/post-enrichment-candidate.js';
import type { PostEnrichmentEvent } from '../pipeline/types/post-enrichment-event.js';
import type { CandidateType } from '../schema/candidates.js';
import { type AthanorConfig, resolveAthanorConfig } from './config.js';
import { applyEmitFloor, type DiscardedCandidate } from './floors.js';
import { assignPresentationIds } from './presentation.js';
import {
  enrichEventsForRun,
  toPostEnrichmentEvents,
  type DistillationRunner,
} from './runner-factory.js';
import type { DistillationEnrichedEvent, DistillationStage1Events } from './select.js';
import { runBeaconDistillation } from './runners/beacon-distillation.js';
import { runDataTransferDistillation } from './runners/data-transfer-distillation.js';
import { runPowerShellInvocationAnomalyDistillation } from './runners/powershell-invocation-anomaly-distillation.js';
import { runTlsAnomalyDistillation } from './runners/tls-anomaly-distillation.js';
import { runUnusualParentChildAnomalyDistillation } from './runners/unusual-parent-child-anomaly-distillation.js';

/**
 * Keyed by `CandidateType` rather than by `string`: a type added to the union without
 * a runner then fails to compile instead of failing at the dispatch below. The other
 * direction — `CANDIDATE_TYPES` (the value list `config.ts` validates against) naming
 * a type this map does not — is pinned in `test/run/runner.test.ts`.
 */
const RUNNER_BY_CANDIDATE: Record<CandidateType, DistillationRunner> = {
  beacon: runBeaconDistillation,
  data_transfer: runDataTransferDistillation,
  powershell_invocation_anomaly: runPowerShellInvocationAnomalyDistillation,
  unusual_parent_child_anomaly: runUnusualParentChildAnomalyDistillation,
  tls_anomaly: runTlsAnomalyDistillation,
};

/** Every candidate type a runner is registered for. The config layer's valid set. */
export const REGISTERED_CANDIDATE_TYPES: readonly string[] = Object.keys(RUNNER_BY_CANDIDATE);

/** A candidate that survived its emit floor and carries a presentation id. */
export type EmittedCandidate = PostEnrichmentCandidate & { pipeline_candidate_id?: string };

export interface PipelineRunResult {
  /** Emitted candidates, grouped by candidate type in `config.candidateTypes` order. */
  candidates: EmittedCandidate[];
  /**
   * The emit-floor discard pile — candidates that were scored, attributed and
   * stage-4 enriched, then dropped for scoring below their type's floor. They keep
   * their deterministic `candidate_id`: presentation ids are only assigned to what
   * is emitted. Each carries the `emit_floor` that cut it, so the pile is legible
   * without the run summary beside it.
   */
  caputMortuum: DiscardedCandidate<PostEnrichmentCandidate>[];
  events: PostEnrichmentEvent[];
  lfaTables: LfaTables;
  applicableLabels: ReadonlySet<EnrichmentLabel>;
}

export interface RunPipelineOptions extends Partial<AthanorConfig> {
  /** Overrides the default `data/threat-intel/minimal.json` table. */
  threatIntelFeed?: ThreatIntelFeed;
}

function resolveRunner(candidateType: string): DistillationRunner {
  const runner = RUNNER_BY_CANDIDATE[candidateType as CandidateType];
  // Unreachable from a config file — `parseDistillCandidates` refuses an unknown type
  // with a CliError first. Reaching it means a PROGRAMMATIC caller passed a bad type,
  // which is a defect, and the stack is what a defect should leave.
  if (!runner) {
    throw new Error(`No per-candidate distillation runner registered for candidate type: ${candidateType}`);
  }
  return runner;
}

/**
 * Stages 3 and 4 for every configured candidate type, then the floors and the
 * presentation ids. The events are already stage-2 output and are NOT re-enriched.
 */
function distill(
  enrichedEvents: ReadonlyArray<PostEnrichmentEvent>,
  config: AthanorConfig,
  threatIntelFeed?: ThreatIntelFeed,
): PipelineRunResult {
  if (config.candidateTypes.length === 0) {
    throw new Error('athanor config resolved zero candidate types for distillation');
  }

  const allCandidates: PostEnrichmentCandidate[] = [];
  const caputMortuum: DiscardedCandidate<PostEnrichmentCandidate>[] = [];
  const allApplicableLabels = new Set<EnrichmentLabel>();
  let sharedContext: Pick<PipelineRunResult, 'events' | 'lfaTables'> | null = null;

  for (const candidateType of config.candidateTypes) {
    const runner = resolveRunner(candidateType);
    const result = runner.withEnrichedEvents(enrichedEvents, { threatIntelFeed });

    if (!sharedContext) {
      sharedContext = {
        events: result.events,
        lfaTables: result.lfaTables,
      };
    }

    const floored = applyEmitFloor(candidateType, result.candidates, config.emitFloors);
    allCandidates.push(...floored.kept);
    caputMortuum.push(...floored.caputMortuum);
    for (const label of result.applicableLabels) {
      allApplicableLabels.add(label);
    }
  }

  if (!sharedContext) {
    throw new Error('athanor distillation had no runner context');
  }

  const candidates: EmittedCandidate[] = config.presentationIds?.enabled
    ? assignPresentationIds(allCandidates, config.presentationIds.prefixes)
    : allCandidates;

  return {
    candidates,
    caputMortuum,
    events: sharedContext.events,
    lfaTables: sharedContext.lfaTables,
    applicableLabels: allApplicableLabels,
  };
}

/**
 * The full pipe: normalized events in, scored + enriched + floored + presentation-id'd
 * candidates out (plus the caput mortuum the floors discarded).
 */
export function runPipeline(
  events: DistillationStage1Events,
  config?: RunPipelineOptions,
): PipelineRunResult {
  const resolved = resolveAthanorConfig(config);
  return distill(enrichEventsForRun(events), resolved, config?.threatIntelFeed);
}

/**
 * Stages 3–4 only, for callers that already hold stage-2 output. The events are
 * validated against the PostEnrichmentEvent contract but are NOT re-enriched.
 */
export function runBackHalf(
  enrichedEvents: ReadonlyArray<PostEnrichmentEvent>,
  config?: RunPipelineOptions,
): PipelineRunResult {
  const resolved = resolveAthanorConfig(config);
  const validated = toPostEnrichmentEvents([...enrichedEvents] as DistillationEnrichedEvent[]);
  return distill(validated, resolved, config?.threatIntelFeed);
}
