import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { GeoRecord } from './geo-loader.js';

function destinationIp(candidate: Record<string, unknown>): string | null {
  const value = candidate.dest_ip;
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function stampGeo(
  enrichment: CandidateEnrichment,
  candidate: Record<string, unknown>,
  geoDb: Map<string, GeoRecord>,
): void {
  const destIp = destinationIp(candidate);
  if (!destIp) return;
  const lookup = geoDb.get(destIp);
  if (!lookup) return;

  enrichment.geo_country = lookup.country;
  enrichment.geo_asn = lookup.asn;
}
