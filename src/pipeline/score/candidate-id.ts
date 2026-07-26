import { sha256HexForDeterministicIdentity } from '../../lib/deterministic-identity.js';

type CandidateRecord = Record<string, unknown>;

export function generateDeterministicCandidateId(prefix: string, payload: CandidateRecord): string {
  return `${prefix}-${sha256HexForDeterministicIdentity(payload).slice(0, 16)}`;
}

export function withDeterministicCandidateId<T extends { candidate_id: string }>(
  prefix: string,
  candidate: T,
): T {
  const { candidate_id: _ignored, ...payload } = candidate as T & CandidateRecord;
  return {
    ...payload,
    candidate_id: generateDeterministicCandidateId(prefix, payload),
  } as T;
}

export function assignDeterministicCandidateIds<T extends { candidate_id: string }>(
  prefix: string,
  candidates: readonly T[],
): T[] {
  return candidates.map((candidate) => withDeterministicCandidateId(prefix, candidate));
}
