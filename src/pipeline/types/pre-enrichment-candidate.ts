import { z } from 'zod';
import type { PostEnrichmentCandidate } from './post-enrichment-candidate.js';

export type EmptyEnrichment = Record<string, never>;

type ToPreEnrichment<T> = T extends { enrichment: unknown }
  ? Omit<T, 'enrichment'> & { enrichment: EmptyEnrichment }
  : never;

export type PreEnrichmentCandidate = ToPreEnrichment<PostEnrichmentCandidate>;

export const emptyEnrichmentSchema = z.record(z.never());

export const preEnrichmentCandidateSchema = z.object({
  candidate_id: z.string().min(1),
  type: z.string().min(1),
  time_window_start: z.string().min(1),
  time_window_end: z.string().min(1),
  enrichment: emptyEnrichmentSchema,
}).passthrough();

export function isPreEnrichmentCandidate(value: unknown): value is PreEnrichmentCandidate {
  return preEnrichmentCandidateSchema.safeParse(value).success;
}
