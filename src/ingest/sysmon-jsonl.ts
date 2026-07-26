/**
 * Sysmon JSONL (native field names, one flat object per line) → normalized
 * `ProcessCreateEvent` (EID 1) and `NetworkConnectEvent` (EID 3).
 *
 * The exact inverse of the renderer that writes the sample dataset's Sysmon files.
 *
 * EID 1 — process create:
 *   UtcTime            → timestamp        (`YYYY-MM-DD HH:MM:SS.mmm`, UTC)
 *   Computer           → host
 *   host.ip            → src_ip           (ECS shipper metadata, NOT a Sysmon-native
 *                                          field: Sysmon has no host-IP column, and a
 *                                          `Computer` that is a NetBIOS name would make
 *                                          the normalized src_ip unrecoverable)
 *   ProcessGuid/ProcessId              → process_guid / process_id
 *   Image                              → process_path  +  process_name = basename(Image)
 *   ParentImage/ParentProcessGuid/Id   → parent_process_path + parent_process_name / …
 *   Description/Product/Company/OriginalFileName → description/product/company/
 *                                          original_file_name  ('-' → null)
 *   CommandLine/CurrentDirectory/User/IntegrityLevel → command_line/current_directory/
 *                                          user/integrity_level
 *   Hashes             → hashes           (Sysmon's comma-joined wire string, verbatim —
 *                                          re-splitting it would invent a shape; the
 *                                          unset token '-' decodes to absent, as it
 *                                          does for the PE metadata fields, so a real
 *                                          estate's hash-less record does not carry a
 *                                          literal "-" into the LFA hash table)
 *
 * EID 3 — network connect:
 *   UtcTime → timestamp · Computer → host · ProcessGuid/ProcessId/User → …
 *   Image → process_name = basename(Image), and NO process_path: the normalized EID 3
 *   contract has no such field, and adding one breaks the event round-trip.
 *   Protocol → protocol · SourceIp/SourcePort → src_ip/src_port ·
 *   DestinationIp/DestinationPort → dest_ip/dest_port
 *
 * Both stamp `source: 'sysmon'` and `domain: 'traditional'` from the dialect.
 */

import {
  compact,
  IngestError,
  isoFromMs,
  type RawRecord,
  RecordReader,
  SYSMON_UNSET,
  windowsBasename,
} from './codecs.js';
import type { ParsedEvent } from './merge.js';

export const SYSMON_PROCESS_CREATE_DIALECT = 'sysmon/process_create';
export const SYSMON_NETWORK_CONNECT_DIALECT = 'sysmon/network_connect';

/** Sysmon EIDs this ingest layer understands, and the dialect each maps to. */
export const SYSMON_DIALECT_BY_EVENT_ID = {
  1: SYSMON_PROCESS_CREATE_DIALECT,
  3: SYSMON_NETWORK_CONNECT_DIALECT,
} as const;

function requireEventId(reader: RecordReader, expected: 1 | 3): number {
  const eventId = reader.requiredNumber('EventID');
  if (eventId !== expected) {
    throw new IngestError(`${reader.label}: expected Sysmon EventID ${expected}, got ${eventId}`);
  }
  return eventId;
}

export function parseSysmonEid1Record(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const eventId = requireEventId(reader, 1);
  const timestampMs = reader.sysmonTimestampMs();

  const image = reader.requiredString('Image');
  const parentImage = reader.requiredString('ParentImage');

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'sysmon',
    event_type: 'process_create',
    event_id: eventId,
    host: reader.requiredString('Computer'),
    src_ip: reader.optionalString('host.ip'),

    process_guid: reader.requiredString('ProcessGuid'),
    process_id: reader.requiredNumber('ProcessId'),
    process_path: image,
    process_name: windowsBasename(image),

    description: reader.unsetAwareString('Description', SYSMON_UNSET) ?? null,
    product: reader.unsetAwareString('Product', SYSMON_UNSET) ?? null,
    company: reader.unsetAwareString('Company', SYSMON_UNSET) ?? null,
    original_file_name: reader.unsetAwareString('OriginalFileName', SYSMON_UNSET) ?? null,

    command_line: reader.requiredString('CommandLine'),
    current_directory: reader.optionalString('CurrentDirectory'),
    user: reader.requiredString('User'),
    integrity_level: reader.optionalString('IntegrityLevel'),
    hashes: reader.unsetAwareString('Hashes', SYSMON_UNSET),

    parent_process_guid: reader.requiredString('ParentProcessGuid'),
    parent_process_id: reader.requiredNumber('ParentProcessId'),
    parent_process_path: parentImage,
    parent_process_name: windowsBasename(parentImage),
    domain: 'traditional',
  });

  return { dialect: SYSMON_PROCESS_CREATE_DIALECT, timestampMs, event, origin: reader.label };
}

export function parseSysmonEid3Record(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const eventId = requireEventId(reader, 3);
  const timestampMs = reader.sysmonTimestampMs();

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'sysmon',
    event_type: 'network_connect',
    event_id: eventId,
    host: reader.requiredString('Computer'),
    process_guid: reader.requiredString('ProcessGuid'),
    process_id: reader.requiredNumber('ProcessId'),
    // No process_path for EID 3 — see the module comment.
    process_name: windowsBasename(reader.requiredString('Image')),
    user: reader.requiredString('User'),
    protocol: reader.requiredString('Protocol'),
    src_ip: reader.requiredString('SourceIp'),
    src_port: reader.requiredNumber('SourcePort'),
    dest_ip: reader.requiredString('DestinationIp'),
    dest_port: reader.requiredNumber('DestinationPort'),
    domain: 'traditional',
  });

  return { dialect: SYSMON_NETWORK_CONNECT_DIALECT, timestampMs, event, origin: reader.label };
}

export function parseSysmonEid1(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parseSysmonEid1Record);
}

export function parseSysmonEid3(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parseSysmonEid3Record);
}

/** Dispatches a mixed Sysmon file on each record's `EventID`. */
export function parseSysmonRecord(raw: RawRecord): ParsedEvent {
  const eventId = new RecordReader(raw).requiredNumber('EventID');
  if (eventId === 1) return parseSysmonEid1Record(raw);
  if (eventId === 3) return parseSysmonEid3Record(raw);
  throw new IngestError(
    `${raw.file}:${raw.line}: unsupported Sysmon EventID ${eventId} `
    + '(athanor ingests EID 1 process_create and EID 3 network_connect)',
  );
}

export function parseSysmon(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parseSysmonRecord);
}
