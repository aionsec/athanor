// Presentation ids: the human-facing layer over the content-derived candidate ids.
//
// A content id (`BCN-3f8a1c2e9d4b7a60`) is stable and unreadable. A presentation id
// (`BCN-001`) is readable and NOT stable — it is assigned by RANK within a type, so the
// candidate that is BCN-002 today is BCN-003 tomorrow if a stronger beacon appears.
// Across runs, compare on `pipeline_candidate_id`; presentation ids are for reading one
// report.
//
// It RENAMES: the deterministic scorer id moves to `pipeline_candidate_id` and
// `candidate_id` becomes the human-facing, score-ranked presentation id
// (BCN-001, DT-001, TLS-001, UPCA-001…). The prefix comes from `prefixOverrides`
// when the type has one, otherwise from the deterministic id's own prefix — which
// is why `data_transfer` (deterministic prefix DTR) and
// `unusual_parent_child_anomaly` (deterministic prefix UPC) need overrides and
// beacon / tls_anomaly / powershell_invocation_anomaly do not.

export function assignPresentationIds<T extends { candidate_id: string; type: string }>(
  candidates: readonly T[],
  prefixOverrides: Record<string, string>,
): Array<T & { pipeline_candidate_id: string }> {
  // Candidates carry their discriminator in `type` (e.g. 'beacon'), NOT `candidate_type`.
  const byType = new Map<string, T[]>();
  for (const c of candidates) {
    const group = byType.get(c.type) ?? [];
    group.push(c);
    byType.set(c.type, group);
  }
  const newIds = new Map<string, string>();
  for (const [type, group] of byType) {
    const scoreField = `${type}_score`;
    const ranked = [...group].sort((a, b) => {
      const sa = (a as Record<string, unknown>)[scoreField];
      const sb = (b as Record<string, unknown>)[scoreField];
      const na = typeof sa === 'number' ? sa : -Infinity;
      const nb = typeof sb === 'number' ? sb : -Infinity;
      if (na !== nb) return nb - na;
      return a.candidate_id < b.candidate_id ? -1 : 1;
    });
    const prefix = prefixOverrides[type] ?? ranked[0].candidate_id.split('-')[0];
    ranked.forEach((c, i) => newIds.set(c.candidate_id, `${prefix}-${String(i + 1).padStart(3, '0')}`));
  }
  return candidates.map((c) => ({
    ...c,
    pipeline_candidate_id: c.candidate_id,
    candidate_id: newIds.get(c.candidate_id) ?? c.candidate_id,
  }));
}
