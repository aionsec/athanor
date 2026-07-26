// The per-candidate-type runner: one factory, five instances.
//
// Every candidate type runs the same sequence — select the events its scorer reads, score
// them, attribute, build the frequency tables, enrich — and differs only in the four
// functions it hands this factory. That is what keeps "add a candidate type" from meaning
// "reimplement the back half".
//
// The factory does NO file IO and is synchronous. Events arrive as an in-memory array;
// `src/ingest/` owns everything to do with folders and files.
//
// WHICH ARRAY EACH STAGE RECEIVES is the part to read carefully — see the comment inside
// `withEnrichedEvents`. Getting it wrong produces no error, just quietly different
// numbers.
import { enrichEvents } from '../enrich-events/index.js';
import type { CandidateType } from '../schema/candidates.js';
import { attributeCandidates } from '../pipeline/attribute/index.js';
import {
  applicableLabelsForCandidateType,
  type EnrichmentLabel,
} from '../pipeline/enrich-candidates/applicability.js';
import { enrichCandidates } from '../pipeline/enrich-candidates/index.js';
import {
  loadThreatIntelFeed,
  type ThreatIntelFeed,
} from '../pipeline/enrich-candidates/threat-intel-loader.js';
import { precomputeLfa } from '../pipeline/lfa-precompute/index.js';
import type { LfaTables } from '../pipeline/types/lfa-tables.js';
import type { PostEnrichmentCandidate } from '../pipeline/types/post-enrichment-candidate.js';
import { isPostEnrichmentEvent, type PostEnrichmentEvent } from '../pipeline/types/post-enrichment-event.js';
import type { PreEnrichmentCandidate } from '../pipeline/types/pre-enrichment-candidate.js';
import type { DistillationEnrichedEvent, DistillationStage1Events } from './select.js';

export interface DistillationRunResult {
  candidates: PostEnrichmentCandidate[];
  events: PostEnrichmentEvent[];
  lfaTables: LfaTables;
  applicableLabels: ReadonlySet<EnrichmentLabel>;
}

export interface DistillationRunnerContextOptions {
  threatIntelFeed?: ThreatIntelFeed;
}

export type DistillationRunnerWithContext = (
  events: DistillationStage1Events,
  options?: DistillationRunnerContextOptions,
) => DistillationRunResult;

export type DistillationRunnerWithEnrichedEvents = (
  enrichedEvents: ReadonlyArray<PostEnrichmentEvent>,
  options?: DistillationRunnerContextOptions,
) => DistillationRunResult;

export interface DistillationRunner {
  (events: DistillationStage1Events): PostEnrichmentCandidate[];
  /** Stage 2 → 4 for this candidate type. Enriches the events it is handed. */
  withContext: DistillationRunnerWithContext;
  /** Stages 3 → 4 only: the events are already stage-2 output and are NOT re-enriched. */
  withEnrichedEvents: DistillationRunnerWithEnrichedEvents;
}

export interface DistillationRunnerConfig<
  TScorerInput,
  TScoredCandidate extends PreEnrichmentCandidate | PostEnrichmentCandidate =
    | PreEnrichmentCandidate
    | PostEnrichmentCandidate,
> {
  candidateType: CandidateType;
  selectScorerInput: (events: DistillationEnrichedEvent[]) => TScorerInput;
  scoreCandidates: (input: TScorerInput) => ReadonlyArray<TScoredCandidate>;
  postScore?: (
    candidates: ReadonlyArray<TScoredCandidate>,
    events: DistillationEnrichedEvent[],
  ) => ReadonlyArray<TScoredCandidate>;
  resetCandidateCounter?: () => void;
}

export function toPostEnrichmentEvents(events: DistillationEnrichedEvent[]): PostEnrichmentEvent[] {
  return events.map((event, index) => {
    if (!isPostEnrichmentEvent(event)) {
      const eventId = typeof (event as { id?: unknown }).id === 'string'
        ? (event as { id: string }).id
        : `index:${index}`;
      throw new Error(`Stage 2 event failed PostEnrichmentEvent contract validation (${eventId})`);
    }
    return event;
  });
}

/**
 * Stage 2 for the whole run: enrich every event once, then validate it against the
 * PostEnrichmentEvent contract. `enrichEvents` is pure, so running it once for the whole
 * run rather than once per candidate type is a common-subexpression elimination and not
 * a behavior change — and it is what makes `runBackHalf`'s "already enriched, do not
 * re-enrich" contract expressible at all.
 */
export function enrichEventsForRun(events: DistillationStage1Events): PostEnrichmentEvent[] {
  return toPostEnrichmentEvents(enrichEvents(events));
}

export function createDistillationRunner<
  TScorerInput,
  TScoredCandidate extends PreEnrichmentCandidate | PostEnrichmentCandidate =
    | PreEnrichmentCandidate
    | PostEnrichmentCandidate,
>(
  config: DistillationRunnerConfig<TScorerInput, TScoredCandidate>,
): DistillationRunner {
  const withEnrichedEvents: DistillationRunnerWithEnrichedEvents = (
    enrichedEvents,
    options,
  ): DistillationRunResult => {
    // The FULL stage-2 event set. ONLY THE SCORER SEES A PER-TYPE SUBSET; attribution,
    // the frequency tables and stage-4 enrichment all see everything.
    //
    // `state2` is deliberately a SEPARATE array from `postEnrichmentEvents`, and the copy
    // is not defensive paranoia. `selectTelemetryEvents` returns its argument by cast, so
    // without the copy the two process scorers would be handed the very array that
    // `attributeCandidates` and `precomputeLfa` consume immediately afterwards. A scorer
    // that sorted or spliced its input would then silently reorder the evidence and
    // corrupt the rarity tables — no error, different numbers. One copy makes the
    // isolation a property of the code instead of a rule contributors have to know.
    const postEnrichmentEvents = [...enrichedEvents];
    const state2 = [...postEnrichmentEvents] as DistillationEnrichedEvent[];
    const scorerInput = config.selectScorerInput(state2);
    const threatIntelFeed = options?.threatIntelFeed ?? loadThreatIntelFeed();

    config.resetCandidateCounter?.();
    const scoredCandidates = config.scoreCandidates(scorerInput);
    const state3 = config.postScore
      ? config.postScore(scoredCandidates, state2)
      : scoredCandidates;
    const state3b = attributeCandidates(state3, postEnrichmentEvents);

    const lfaTables = precomputeLfa(postEnrichmentEvents);
    const state4 = enrichCandidates(state3b, lfaTables, {
      candidateType: config.candidateType,
      events: postEnrichmentEvents,
      threatIntelFeed,
    });

    return {
      candidates: state4,
      events: postEnrichmentEvents,
      lfaTables,
      applicableLabels: applicableLabelsForCandidateType(config.candidateType),
    };
  };

  const withContext: DistillationRunnerWithContext = (
    events,
    options,
  ): DistillationRunResult => withEnrichedEvents(enrichEventsForRun(events), options);

  const runner = ((events: DistillationStage1Events): PostEnrichmentCandidate[] => {
    return withContext(events).candidates;
  }) as DistillationRunner;

  runner.withContext = withContext;
  runner.withEnrichedEvents = withEnrichedEvents;
  return runner;
}
