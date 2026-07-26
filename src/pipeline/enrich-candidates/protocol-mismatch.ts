import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { PostEnrichmentEvent } from '../types/post-enrichment-event.js';

type CandidateRecord = Record<string, unknown>;

type CanonicalService =
  | 'http'
  | 'ssl'
  | 'dns'
  | 'ssh'
  | 'smb'
  | 'rdp'
  | 'ldap'
  | 'kerberos'
  | 'icmp';

const SERVICE_ALIASES: Readonly<Record<string, CanonicalService>> = {
  http: 'http',
  www: 'http',

  ssl: 'ssl',
  tls: 'ssl',
  https: 'ssl',
  'https-alt': 'ssl',

  dns: 'dns',
  domain: 'dns',

  ssh: 'ssh',

  smb: 'smb',
  cifs: 'smb',
  'microsoft-ds': 'smb',
  'netbios-ssn': 'smb',

  rdp: 'rdp',
  'ms-wbt-server': 'rdp',
  termservice: 'rdp',

  ldap: 'ldap',
  ldaps: 'ldap',

  kerberos: 'kerberos',
  krb5: 'kerberos',
  'kerberos-sec': 'kerberos',

  icmp: 'icmp',
} as const;

const EXPECTED_SERVICES_BY_PORT: Readonly<Record<number, readonly CanonicalService[]>> = {
  22: ['ssh'],
  53: ['dns'],
  80: ['http'],
  88: ['kerberos'],
  139: ['smb'],
  389: ['ldap'],
  443: ['ssl'],
  445: ['smb'],
  464: ['kerberos'],
  636: ['ldap'],
  3389: ['rdp'],
  8000: ['http'],
  8080: ['http'],
  8443: ['ssl'],
  8888: ['http'],
  9443: ['ssl'],
} as const;

const EVENT_TYPE_FALLBACK: Readonly<Record<string, CanonicalService>> = {
  ssl: 'ssl',
  dns: 'dns',
  http: 'http',
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeCanonicalService(value: unknown): CanonicalService | null {
  const normalized = normalizeString(value)?.toLowerCase();
  if (!normalized || normalized === '-' || normalized === 'unknown' || normalized === 'none' || normalized === 'null') {
    return null;
  }

  return SERVICE_ALIASES[normalized] ?? null;
}

function normalizePort(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65535) {
    return value;
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number.parseInt(value, 10);
    if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535) {
      return parsed;
    }
  }

  return null;
}

function pickMostFrequentService(counts: Map<CanonicalService, number>): CanonicalService | null {
  let selected: CanonicalService | null = null;
  let selectedCount = Number.NEGATIVE_INFINITY;

  for (const [service, count] of counts) {
    if (count > selectedCount) {
      selected = service;
      selectedCount = count;
      continue;
    }

    if (count === selectedCount && selected !== null && service < selected) {
      selected = service;
    }
  }

  return selected;
}

function collectExpectedServices(
  candidate: CandidateRecord,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
): Set<CanonicalService> {
  const ports = new Set<number>();

  const candidatePort = normalizePort(candidate.dest_port);
  if (candidatePort !== null) {
    ports.add(candidatePort);
  }

  for (const event of candidateEvents) {
    const eventPort = normalizePort((event as { dest_port?: unknown }).dest_port);
    if (eventPort !== null) {
      ports.add(eventPort);
    }
  }

  const expected = new Set<CanonicalService>();
  for (const port of ports) {
    const services = EXPECTED_SERVICES_BY_PORT[port];
    if (!services) continue;
    for (const service of services) {
      expected.add(service);
    }
  }

  return expected;
}

function observedFromProtocolDistribution(candidate: CandidateRecord): CanonicalService | null {
  if (!isPlainObject(candidate.protocol_distribution)) return null;

  const counts = new Map<CanonicalService, number>();

  for (const [rawService, rawWeight] of Object.entries(candidate.protocol_distribution)) {
    const service = normalizeCanonicalService(rawService);
    if (!service) continue;

    const weight = typeof rawWeight === 'number' && Number.isFinite(rawWeight)
      ? rawWeight
      : 0;
    counts.set(service, (counts.get(service) ?? 0) + weight);
  }

  return pickMostFrequentService(counts);
}

function observedFromConnServiceEvents(candidateEvents: ReadonlyArray<PostEnrichmentEvent>): CanonicalService | null {
  const counts = new Map<CanonicalService, number>();

  for (const event of candidateEvents) {
    if (event.source !== 'zeek' || event.event_type !== 'conn') continue;

    const service = normalizeCanonicalService((event as { service?: unknown }).service);
    if (!service) continue;

    counts.set(service, (counts.get(service) ?? 0) + 1);
  }

  return pickMostFrequentService(counts);
}

function observedFromEventTypeFallback(candidateEvents: ReadonlyArray<PostEnrichmentEvent>): CanonicalService | null {
  const counts = new Map<CanonicalService, number>();

  for (const event of candidateEvents) {
    const fallbackService = EVENT_TYPE_FALLBACK[event.event_type];
    if (!fallbackService) continue;

    counts.set(fallbackService, (counts.get(fallbackService) ?? 0) + 1);
  }

  return pickMostFrequentService(counts);
}

function observedFromProtoFallback(
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
  expectedServices: ReadonlySet<CanonicalService>,
): CanonicalService | null {
  const protoValues = new Set<string>();

  for (const event of candidateEvents) {
    if (event.source !== 'zeek' || event.event_type !== 'conn') continue;

    const proto = normalizeString((event as { proto?: unknown }).proto)?.toLowerCase();
    if (!proto) continue;
    protoValues.add(proto);
  }

  if (protoValues.size !== 1) return null;

  const [proto] = [...protoValues];

  if (proto === 'icmp') return 'icmp';
  if (proto === 'udp' && expectedServices.has('dns')) return 'dns';

  return null;
}

function resolveObservedService(
  candidate: CandidateRecord,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
  expectedServices: ReadonlySet<CanonicalService>,
): CanonicalService | null {
  const candidateObserved = normalizeCanonicalService(candidate.observed_service);
  if (candidateObserved) return candidateObserved;

  const candidateProtocolService = normalizeCanonicalService(candidate.protocol_service);
  if (candidateProtocolService) return candidateProtocolService;

  const candidateProtocolDistribution = observedFromProtocolDistribution(candidate);
  if (candidateProtocolDistribution) return candidateProtocolDistribution;

  const connServiceObserved = observedFromConnServiceEvents(candidateEvents);
  if (connServiceObserved) return connServiceObserved;

  const eventTypeFallback = observedFromEventTypeFallback(candidateEvents);
  if (eventTypeFallback) return eventTypeFallback;

  return observedFromProtoFallback(candidateEvents, expectedServices);
}

export function stampProtocolMismatch(
  enrichment: CandidateEnrichment,
  candidate: CandidateRecord,
  candidateEvents: ReadonlyArray<PostEnrichmentEvent>,
): void {
  const expectedServices = collectExpectedServices(candidate, candidateEvents);
  if (expectedServices.size === 0) {
    enrichment.protocol_mismatch = null;
    return;
  }

  const observedService = resolveObservedService(candidate, candidateEvents, expectedServices);
  if (!observedService) {
    enrichment.protocol_mismatch = null;
    return;
  }

  enrichment.protocol_mismatch = !expectedServices.has(observedService);
}
