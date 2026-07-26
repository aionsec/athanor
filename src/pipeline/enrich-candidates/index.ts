import type { CandidateEnrichment, CandidateType } from '../../schema/candidates.js';
import { loadGeoDatabase, type GeoRecord } from './geo-loader.js';
import { loadLotsDomains } from './lots-loader.js';
import { loadThreatIntelFeed, type ThreatIntelFeed } from './threat-intel-loader.js';
import { applicableLabelsForCandidateType } from './applicability.js';
import type { EnrichmentLabel } from './applicability.js';
import { stampThreatIntel } from './threat-intel.js';
import { stampGeo } from './geo.js';
import { stampRarity } from './rarity-stamper.js';
import { stampBusinessHoursProportion } from './business-hours-aggregator.js';
import { stampFirstSeen } from './first-seen.js';
import { stampMissingSni } from './missing-sni.js';
import { stampLots } from './lots.js';
import { stampProtocolMismatch } from './protocol-mismatch.js';
import {
  assertActiveStage4StamperCoverage,
  STAGE4_STAMPER_BINDINGS,
  type Stage4StamperBinding,
} from './stamper-bindings.js';
import { extractScriptBlockEntity } from '../util/extract-script-block-entity.js';
import {
  extractParentChildPairEntity,
  type ParentChildPairEntitySource,
} from '../util/extract-parent-child-pair-entity.js';
import { normalizeProcessName } from '../util/normalize-process.js';
import { commandLineEntity } from '../util/normalize-command-line.js';
import {
  normalizeSha256,
  sha256FromHashObject,
  sha256FromHashString,
} from '../util/normalize-hash.js';
import { normalizeString } from '../util/normalize-string.js';
import type { LfaTables } from '../types/lfa-tables.js';
import type { PreEnrichmentCandidate } from '../types/pre-enrichment-candidate.js';
import type { PostEnrichmentCandidate } from '../types/post-enrichment-candidate.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

assertActiveStage4StamperCoverage();

export interface EnrichCandidatesOptions {
  candidateType?: CandidateType;
  events?: ReadonlyArray<PostEnrichmentEvent>;
  threatIntelFeed?: ThreatIntelFeed;
  geoDb?: Map<string, GeoRecord>;
  lotsSet?: Set<string>;
}

function normalizeLower(value: unknown): string | null {
  const base = normalizeString(value);
  return base ? base.toLowerCase() : null;
}

function getCandidateType(candidate: Record<string, unknown>): CandidateType | null {
  const type = normalizeString(candidate.type);
  return type ? (type as CandidateType) : null;
}

function getEvidenceIds(candidate: Record<string, unknown>): Set<string> {
  const evidence = candidate.evidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return new Set();

  const ids = (evidence as { constituent_event_ids?: unknown }).constituent_event_ids;
  if (!Array.isArray(ids)) return new Set();

  const out = new Set<string>();
  for (const id of ids) {
    const normalized = normalizeString(id);
    if (normalized) out.add(normalized);
  }
  return out;
}

function matchesBeaconEndpoint(candidate: Record<string, unknown>, event: PostEnrichmentEvent): boolean {
  const srcIp = normalizeString(candidate.src_ip);
  const destIp = normalizeString(candidate.dest_ip);
  if (!srcIp || !destIp) return false;

  const eventSrcIp = normalizeString((event as { src_ip?: unknown }).src_ip);
  const eventDestIp = normalizeString((event as { dest_ip?: unknown }).dest_ip);
  if (!eventSrcIp || !eventDestIp) return false;

  return srcIp === eventSrcIp && destIp === eventDestIp;
}

function eventsForCandidate(
  candidate: Record<string, unknown>,
  allEvents: ReadonlyArray<PostEnrichmentEvent>,
): PostEnrichmentEvent[] {
  if (allEvents.length === 0) return [];

  const ids = getEvidenceIds(candidate);
  if (ids.size > 0) {
    const matchesById = allEvents.filter((event) => ids.has(event.id));
    if (matchesById.length > 0) return matchesById;
  }

  const candidateType = getCandidateType(candidate);
  if (candidateType === 'beacon') {
    return allEvents.filter((event) => matchesBeaconEndpoint(candidate, event));
  }

  return [];
}

function collectDomains(candidate: Record<string, unknown>, events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();

  const candidateDomain = normalizeLower(candidate.base_domain) ?? normalizeLower(candidate.domain);
  if (candidateDomain) values.add(candidateDomain);

  for (const event of events) {
    const record = event as {
      query?: unknown;
      server_name?: unknown;
      http_host?: unknown;
      host?: unknown;
    };

    const domain = normalizeLower(record.query)
      ?? normalizeLower(record.server_name)
      ?? normalizeLower(record.http_host)
      ?? (typeof record.http_host === 'string' ? null : normalizeLower(record.host));
    if (domain) values.add(domain);
  }

  return [...values];
}

function collectUserAgents(events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();
  for (const event of events) {
    const ua = normalizeString((event as { http_user_agent?: unknown; user_agent?: unknown }).http_user_agent)
      ?? normalizeString((event as { user_agent?: unknown }).user_agent);
    if (ua) values.add(ua);
  }
  return [...values];
}

function collectJa3Hashes(events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();
  for (const event of events) {
    const ja3 = normalizeString((event as { ja3_hash?: unknown }).ja3_hash);
    if (ja3) values.add(ja3);
  }
  return [...values];
}

function collectHashes(candidate: Record<string, unknown>): string[] {
  return [
    normalizeLower(candidate.sha256),
    normalizeLower(candidate.sha1),
    normalizeLower(candidate.md5),
  ].filter((value): value is string => Boolean(value));
}

function collectProcessNames(candidate: Record<string, unknown>, events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();

  const candidateProcess = normalizeProcessName(candidate.process_name);
  if (candidateProcess) values.add(candidateProcess);

  for (const event of events) {
    const record = event as {
      process_name?: unknown;
      source_image?: unknown;
      image?: unknown;
      creator_image?: unknown;
    };
    const process = normalizeProcessName(record.process_name)
      ?? normalizeProcessName(record.source_image)
      ?? normalizeProcessName(record.image)
      ?? normalizeProcessName(record.creator_image);
    if (process) values.add(process);
  }

  return [...values];
}

function collectCommandLineValues(candidate: Record<string, unknown>, events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();

  const candidateEntity = commandLineEntity(candidate.process_name, candidate.command_line);
  if (candidateEntity) values.add(candidateEntity);

  for (const event of events) {
    const record = event as {
      process_name?: unknown;
      source_image?: unknown;
      image?: unknown;
      command_line?: unknown;
    };

    const entity = commandLineEntity(
      record.process_name ?? record.source_image ?? record.image,
      record.command_line,
    );
    if (entity) values.add(entity);
  }

  return [...values];
}

function collectHashValues(candidate: Record<string, unknown>, events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();

  const candidateSha256 = normalizeSha256(candidate.sha256);
  if (candidateSha256) values.add(candidateSha256);

  for (const event of events) {
    const record = event as {
      sha256?: unknown;
      hashes?: unknown;
    };
    const sha256 = normalizeSha256(record.sha256)
      ?? sha256FromHashObject(record.hashes)
      ?? sha256FromHashString(record.hashes);
    if (sha256) values.add(sha256);
  }

  return [...values];
}

function collectScriptBlockValues(candidate: Record<string, unknown>, events: ReadonlyArray<PostEnrichmentEvent>): string[] {
  const values = new Set<string>();

  const candidateEntity = extractScriptBlockEntity(candidate);
  if (candidateEntity) values.add(candidateEntity);

  for (const event of events) {
    const entity = extractScriptBlockEntity(event as {
      script_block_hash?: unknown;
      script_block_id?: unknown;
      script_block_text?: unknown;
    });
    if (entity) values.add(entity);
  }

  return [...values];
}

function collectParentChildPairValues(
  candidate: Record<string, unknown>,
  events: ReadonlyArray<PostEnrichmentEvent>,
): string[] {
  const values = new Set<string>();

  const candidateEntity = extractParentChildPairEntity(candidate as ParentChildPairEntitySource);
  if (candidateEntity) values.add(candidateEntity);

  for (const event of events) {
    const entity = extractParentChildPairEntity(event as ParentChildPairEntitySource);
    if (entity) values.add(entity);
  }

  return [...values];
}

function cloneEnrichment(candidate: Record<string, unknown>): CandidateEnrichment {
  const existing = candidate.enrichment;
  if (!existing || typeof existing !== 'object' || Array.isArray(existing)) {
    return {};
  }
  return { ...(existing as CandidateEnrichment) };
}

export function enrichCandidates(
  candidates: ReadonlyArray<PreEnrichmentCandidate | PostEnrichmentCandidate>,
  lfaTables: LfaTables,
  options: EnrichCandidatesOptions = {},
): PostEnrichmentCandidate[] {
  const allEvents = options.events ?? [];
  const threatIntelFeed = options.threatIntelFeed ?? loadThreatIntelFeed();
  const geoDb = options.geoDb ?? loadGeoDatabase();
  const lotsSet = options.lotsSet ?? loadLotsDomains();

  return candidates.map((candidate) => {
    const asRecord = candidate as unknown as Record<string, unknown>;
    const candidateType = getCandidateType(asRecord);
    const applicable: ReadonlySet<EnrichmentLabel> = candidateType
      ? applicableLabelsForCandidateType(candidateType)
      : new Set<EnrichmentLabel>();
    const applicableBindings = new Set<Stage4StamperBinding>(
      [...applicable].map((label) => STAGE4_STAMPER_BINDINGS[label]),
    );

    // If caller is constraining this invocation to a specific type and this candidate
    // is not that type, keep it as pass-through.
    if (options.candidateType && candidateType !== options.candidateType) {
      return {
        ...candidate,
        enrichment: cloneEnrichment(asRecord),
      } as PostEnrichmentCandidate;
    }

    if (applicable.size === 0) {
      return {
        ...candidate,
        enrichment: cloneEnrichment(asRecord),
      } as PostEnrichmentCandidate;
    }

    const candidateEvents = eventsForCandidate(asRecord, allEvents);
    const domains = collectDomains(asRecord, candidateEvents);
    const userAgents = collectUserAgents(candidateEvents);
    const ja3Hashes = collectJa3Hashes(candidateEvents);
    const hashes = collectHashes(asRecord);
    const processNames = collectProcessNames(asRecord, candidateEvents);
    const hashValues = collectHashValues(asRecord, candidateEvents);
    const commandLineValues = collectCommandLineValues(asRecord, candidateEvents);
    const parentChildPairValues = collectParentChildPairValues(asRecord, candidateEvents);
    const scriptBlockValues = collectScriptBlockValues(asRecord, candidateEvents);

    const enrichment = cloneEnrichment(asRecord);

    if (applicableBindings.has('threat_intel')) {
      stampThreatIntel(enrichment, asRecord, threatIntelFeed, {
        domains,
        hashes,
        events: candidateEvents,
      });
    }
    if (applicableBindings.has('geo')) {
      stampGeo(enrichment, asRecord, geoDb);
    }
    if (applicableBindings.has('rarity')) {
      stampRarity(enrichment, asRecord, lfaTables, {
        processNames,
        hashValues,
        commandLineValues,
        parentChildPairValues,
        scriptBlockValues,
        domains,
        userAgents,
        ja3Hashes,
      }, applicable);
    }
    if (applicableBindings.has('first_seen')) {
      stampFirstSeen(enrichment, candidateEvents);
    }
    if (applicableBindings.has('business_hours')) {
      stampBusinessHoursProportion(enrichment, candidateEvents);
    }
    if (applicableBindings.has('lots')) {
      stampLots(enrichment, domains, lotsSet);
    }
    if (applicableBindings.has('missing_sni')) {
      stampMissingSni(enrichment, candidateEvents);
    }
    if (applicableBindings.has('protocol_mismatch')) {
      stampProtocolMismatch(enrichment, asRecord, candidateEvents);
    }

    return {
      ...candidate,
      enrichment,
    } as PostEnrichmentCandidate;
  });
}
