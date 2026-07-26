import { z } from 'zod';
import type {
  BeaconCandidate,
  DataTransferCandidate,
  PowerShellInvocationAnomalyCandidate,
  UnusualParentChildAnomalyCandidate,
  TlsAnomalyCandidate,
} from '../../schema/candidates.js';

export type PostEnrichmentCandidate =
  | BeaconCandidate
  | DataTransferCandidate
  | PowerShellInvocationAnomalyCandidate
  | UnusualParentChildAnomalyCandidate
  | TlsAnomalyCandidate;

export const postEnrichmentCandidateSchema = z.object({
  candidate_id: z.string().min(1),
  type: z.string().min(1),
  time_window_start: z.string().min(1),
  time_window_end: z.string().min(1),
  enrichment: z.record(z.unknown()),
}).passthrough();

export function isPostEnrichmentCandidate(value: unknown): value is PostEnrichmentCandidate {
  return postEnrichmentCandidateSchema.safeParse(value).success;
}
