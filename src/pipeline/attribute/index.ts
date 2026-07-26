import type {
  CandidateAttributionBlock,
  CandidateAttributionConfidence,
  CandidateAttributionDataQualityFlag,
} from '../../schema/candidates.js';
import type { PostEnrichmentCandidate } from '../types/post-enrichment-candidate.js';
import type { PreEnrichmentCandidate } from '../types/pre-enrichment-candidate.js';
import {
  ATTRIBUTION_ELIGIBLE_CANDIDATE_TYPES,
  DEFAULT_ATTRIBUTION_TIME_SKEW_MS,
} from './spec.js';

type CandidateRecord = (PreEnrichmentCandidate | PostEnrichmentCandidate) & Record<string, unknown>;
type EventRecord = Record<string, unknown>;

interface ConnEventRecord extends EventRecord {
  id: string;
  source: 'zeek';
  event_type: 'conn';
  timestamp: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  zeek_uid?: string;
}

interface SslEventRecord extends EventRecord {
  id: string;
  source: 'zeek';
  event_type: 'ssl';
  timestamp: string;
  zeek_uid?: string;
}

interface NetworkConnectRecord extends EventRecord {
  id: string;
  source: 'sysmon';
  event_type: 'network_connect';
  timestamp: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  host?: string;
  process_guid: string;
  process_name: string;
  process_id: number;
  user: string;
}

interface ProcessCreateRecord extends EventRecord {
  id: string;
  source: 'sysmon';
  event_type: 'process_create';
  timestamp: string;
  host?: string;
  process_guid: string;
  process_name: string;
  process_path?: string;
  process_id: number;
  user: string;
  parent_process_guid?: string;
  parent_process_name?: string;
  parent_process_path?: string;
}

interface AttributionMatch {
  networkConnect: NetworkConnectRecord;
  deltaMs: number;
}

interface GuidStats {
  processGuid: string;
  count: number;
  maxDeltaMs: number;
  sample: NetworkConnectRecord;
}

export interface AttributeCandidatesOptions {
  timeSkewMs?: number;
}

const ATTRIBUTION_ELIGIBLE_SET = new Set<string>(ATTRIBUTION_ELIGIBLE_CANDIDATE_TYPES);

function asString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function parseTimestampMs(value: unknown): number | null {
  const text = asString(value);
  if (!text) return null;
  const ms = Date.parse(text);
  return Number.isFinite(ms) ? ms : null;
}

function isConnEventRecord(event: EventRecord): event is ConnEventRecord {
  // NOTE: src_port is intentionally NOT required. Zeek's normalized conn record
  // does not carry the ephemeral source port, and the conn↔network_connect join
  // keys on the stable 3-tuple (src host, dest, dest port) — see tupleKey().
  return event.source === 'zeek'
    && event.event_type === 'conn'
    && asString(event.id) !== null
    && asString(event.timestamp) !== null
    && asString(event.src_ip) !== null
    && asString(event.dest_ip) !== null
    && asNumber(event.dest_port) !== null;
}

function isSslEventRecord(event: EventRecord): event is SslEventRecord {
  return event.source === 'zeek'
    && event.event_type === 'ssl'
    && asString(event.id) !== null
    && asString(event.timestamp) !== null;
}

function isNetworkConnectRecord(event: EventRecord): event is NetworkConnectRecord {
  return event.source === 'sysmon'
    && event.event_type === 'network_connect'
    && asString(event.id) !== null
    && asString(event.timestamp) !== null
    && asString(event.src_ip) !== null
    && asNumber(event.src_port) !== null
    && asString(event.dest_ip) !== null
    && asNumber(event.dest_port) !== null
    && asString(event.process_guid) !== null
    && asString(event.process_name) !== null
    && asNumber(event.process_id) !== null
    && asString(event.user) !== null;
}

function isProcessCreateRecord(event: EventRecord): event is ProcessCreateRecord {
  return event.source === 'sysmon'
    && event.event_type === 'process_create'
    && asString(event.id) !== null
    && asString(event.timestamp) !== null
    && asString(event.process_guid) !== null
    && asString(event.process_name) !== null
    && asNumber(event.process_id) !== null
    && asString(event.user) !== null;
}

// Join Zeek `conn` and Sysmon `network_connect` (EID3) on the stable 3-tuple
// (source host, destination, destination port). The ephemeral SOURCE PORT is
// deliberately excluded: Zeek's normalized conn record does not carry it, and
// the two sensors observe independent ephemeral ports for the same logical
// connection, so including it would never match. Disambiguation across multiple
// candidate bridge events is done by nearest-timestamp.
function tupleKey(srcIp: string, destIp: string, destPort: number): string {
  return `${srcIp}|${destIp}|${destPort}`;
}

function nearestByTimestamp<T extends EventRecord>(
  events: readonly T[],
  targetMs: number,
): { event: T; deltaMs: number } | null {
  if (events.length === 0) return null;

  let best: T | null = null;
  let bestDelta = Number.POSITIVE_INFINITY;

  for (const event of events) {
    const ms = parseTimestampMs(event.timestamp);
    if (ms === null) continue;
    const delta = Math.abs(ms - targetMs);
    if (delta < bestDelta) {
      best = event;
      bestDelta = delta;
      continue;
    }
    if (delta === bestDelta && best) {
      const currentId = asString(event.id) ?? '';
      const bestId = asString(best.id) ?? '';
      if (currentId.localeCompare(bestId) < 0) {
        best = event;
      }
    }
  }

  if (!best || !Number.isFinite(bestDelta)) return null;
  return { event: best, deltaMs: bestDelta };
}

function extractEvidenceIds(candidate: CandidateRecord): string[] {
  const evidence = candidate.evidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    return [];
  }

  const ids = (evidence as { constituent_event_ids?: unknown }).constituent_event_ids;
  if (!Array.isArray(ids)) return [];

  return ids
    .map((value) => asString(value))
    .filter((value): value is string => value !== null);
}

function buildAttributionBlock(input: {
  host: string | null;
  confidence: CandidateAttributionConfidence;
  flags: CandidateAttributionDataQualityFlag[];
  processGuid: string | null;
  processName: string | null;
  processPath: string | null;
  processId: number | null;
  user: string | null;
  parentProcessGuid: string | null;
  parentProcessName: string | null;
  parentProcessPath: string | null;
}): CandidateAttributionBlock {
  return {
    host: input.host,
    process_guid: input.processGuid,
    process_name: input.processName,
    process_path: input.processPath,
    process_id: input.processId,
    user: input.user,
    parent_process_guid: input.parentProcessGuid,
    parent_process_name: input.parentProcessName,
    parent_process_path: input.parentProcessPath,
    confidence: input.confidence,
    data_quality_flags: input.flags,
  };
}

export function hasNetworkConnectTelemetry(events: ReadonlyArray<EventRecord>): boolean {
  return events.some((event) => isNetworkConnectRecord(event));
}

export function attributeCandidates<T extends PreEnrichmentCandidate | PostEnrichmentCandidate>(
  candidates: readonly T[],
  events: ReadonlyArray<EventRecord>,
  options: AttributeCandidatesOptions = {},
): T[] {
  if (candidates.length === 0 || events.length === 0) {
    return [...candidates];
  }

  if (!hasNetworkConnectTelemetry(events)) {
    // Preserve legacy outputs for datasets without attribution bridge telemetry.
    return [...candidates];
  }

  const timeSkewMs = options.timeSkewMs ?? DEFAULT_ATTRIBUTION_TIME_SKEW_MS;

  const eventsById = new Map<string, EventRecord>();
  const connByUid = new Map<string, ConnEventRecord[]>();
  const eid3ByTuple = new Map<string, NetworkConnectRecord[]>();
  const processCreateByGuid = new Map<string, ProcessCreateRecord>();

  for (const event of events) {
    const id = asString(event.id);
    if (id) eventsById.set(id, event);

    if (isConnEventRecord(event)) {
      const uid = asString(event.zeek_uid);
      if (uid) {
        const bucket = connByUid.get(uid) ?? [];
        bucket.push(event);
        connByUid.set(uid, bucket);
      }
      continue;
    }

    if (isNetworkConnectRecord(event)) {
      const key = tupleKey(event.src_ip, event.dest_ip, event.dest_port);
      const bucket = eid3ByTuple.get(key) ?? [];
      bucket.push(event);
      eid3ByTuple.set(key, bucket);
      continue;
    }

    if (isProcessCreateRecord(event)) {
      processCreateByGuid.set(event.process_guid, event);
    }
  }

  const out: T[] = [];
  for (const candidate of candidates) {
    const record = candidate as CandidateRecord;
    const candidateType = asString(record.type);
    if (!candidateType || !ATTRIBUTION_ELIGIBLE_SET.has(candidateType)) {
      out.push(candidate);
      continue;
    }

    const evidenceIds = extractEvidenceIds(record);
    const matches: AttributionMatch[] = [];
    let relevantEvidenceCount = 0;
    let unresolvedRelevantEvidenceCount = 0;

    for (const evidenceId of evidenceIds) {
      const evidenceEvent = eventsById.get(evidenceId);
      if (!evidenceEvent) continue;

      if (isNetworkConnectRecord(evidenceEvent)) {
        relevantEvidenceCount += 1;
        matches.push({ networkConnect: evidenceEvent, deltaMs: 0 });
        continue;
      }

      if (isConnEventRecord(evidenceEvent)) {
        relevantEvidenceCount += 1;
        const connTs = parseTimestampMs(evidenceEvent.timestamp);
        if (connTs === null) {
          unresolvedRelevantEvidenceCount += 1;
          continue;
        }

        const key = tupleKey(
          evidenceEvent.src_ip,
          evidenceEvent.dest_ip,
          evidenceEvent.dest_port,
        );
        const candidateEid3Events = eid3ByTuple.get(key) ?? [];
        const nearest = nearestByTimestamp(candidateEid3Events, connTs);
        if (!nearest) {
          unresolvedRelevantEvidenceCount += 1;
          continue;
        }
        matches.push({ networkConnect: nearest.event, deltaMs: nearest.deltaMs });
        continue;
      }

      if (isSslEventRecord(evidenceEvent)) {
        relevantEvidenceCount += 1;
        const sslTs = parseTimestampMs(evidenceEvent.timestamp);
        const uid = asString(evidenceEvent.zeek_uid);
        if (sslTs === null || !uid) {
          unresolvedRelevantEvidenceCount += 1;
          continue;
        }

        const connCandidates = connByUid.get(uid) ?? [];
        const nearestConn = nearestByTimestamp(connCandidates, sslTs);
        if (!nearestConn) {
          unresolvedRelevantEvidenceCount += 1;
          continue;
        }

        const conn = nearestConn.event;
        const key = tupleKey(conn.src_ip, conn.dest_ip, conn.dest_port);
        const candidateEid3Events = eid3ByTuple.get(key) ?? [];
        const nearestEid3 = nearestByTimestamp(candidateEid3Events, sslTs);
        if (!nearestEid3) {
          unresolvedRelevantEvidenceCount += 1;
          continue;
        }

        matches.push({ networkConnect: nearestEid3.event, deltaMs: nearestEid3.deltaMs });
      }
    }

    if (matches.length === 0) {
      const flags: CandidateAttributionDataQualityFlag[] = ['no_eid3_match'];
      if (relevantEvidenceCount > 0) {
        flags.push('partial_evidence_unattributed');
      }

      out.push({
        ...(candidate as CandidateRecord),
        attribution: buildAttributionBlock({
          host: null,
          confidence: 'unavailable',
          flags,
          processGuid: null,
          processName: null,
          processPath: null,
          processId: null,
          user: null,
          parentProcessGuid: null,
          parentProcessName: null,
          parentProcessPath: null,
        }),
      } as T);
      continue;
    }

    const statsByGuid = new Map<string, GuidStats>();
    for (const match of matches) {
      const guid = match.networkConnect.process_guid;
      const existing = statsByGuid.get(guid);
      if (!existing) {
        statsByGuid.set(guid, {
          processGuid: guid,
          count: 1,
          maxDeltaMs: match.deltaMs,
          sample: match.networkConnect,
        });
        continue;
      }
      existing.count += 1;
      existing.maxDeltaMs = Math.max(existing.maxDeltaMs, match.deltaMs);
    }

    const stats = [...statsByGuid.values()]
      .sort((left, right) => {
        if (right.count !== left.count) return right.count - left.count;
        if (left.maxDeltaMs !== right.maxDeltaMs) return left.maxDeltaMs - right.maxDeltaMs;
        return left.processGuid.localeCompare(right.processGuid);
      });

    const dominant = stats[0];
    const processCreate = processCreateByGuid.get(dominant.processGuid);

    const flags: CandidateAttributionDataQualityFlag[] = [];
    if (unresolvedRelevantEvidenceCount > 0) {
      flags.push('partial_evidence_unattributed');
    }
    if (stats.length > 1) {
      flags.push('multi_process_match');
    }
    if (dominant.maxDeltaMs > timeSkewMs) {
      flags.push('time_skew_exceeded');
    }
    if (!processCreate) {
      flags.push('missing_process_create');
    }

    let confidence: CandidateAttributionConfidence;
    if (stats.length > 1) {
      confidence = 'partial_multi_process';
    } else if (dominant.maxDeltaMs > timeSkewMs) {
      confidence = 'partial_time_skew';
    } else if (unresolvedRelevantEvidenceCount > 0 || !processCreate) {
      confidence = 'inferred';
    } else {
      confidence = 'full';
    }

    const processName = processCreate ? asString(processCreate.process_name) : asString(dominant.sample.process_name);
    const processId = processCreate ? asNumber(processCreate.process_id) : asNumber(dominant.sample.process_id);

    const next = {
      ...(candidate as CandidateRecord),
      attribution: buildAttributionBlock({
        host: processCreate
          ? asString(processCreate.host)
          : asString(dominant.sample.host),
        confidence,
        flags,
        processGuid: dominant.processGuid,
        processName,
        processPath: processCreate ? asString(processCreate.process_path) : null,
        processId,
        user: processCreate ? asString(processCreate.user) : asString(dominant.sample.user),
        parentProcessGuid: processCreate ? asString(processCreate.parent_process_guid) : null,
        parentProcessName: processCreate ? asString(processCreate.parent_process_name) : null,
        parentProcessPath: processCreate ? asString(processCreate.parent_process_path) : null,
      }),
    } as CandidateRecord;

    if (processName !== null) {
      next.process_name = processName;
    }
    if (processId !== null) {
      next.process_id = processId;
    }

    out.push(next as T);
  }

  return out;
}
