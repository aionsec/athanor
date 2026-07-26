/**
 * THE NORMALIZED EVENT SCHEMA — the contract everything downstream of ingest reads.
 *
 * Nothing past `src/ingest/` ever sees a log line. Scorers, attribution, the frequency
 * tables and both enrichment stages all read the interfaces in this file, which is what
 * makes "support a new log format" a question about one parser rather than about the
 * pipeline. A dialect parser's whole job is to produce one of these.
 *
 * Every event carries `id`, `timestamp` (ISO 8601, UTC, milliseconds), `source` and
 * `event_type`. `source` and `event_type` together pick the lane. Every interface also
 * permits unknown keys and they are carried through untouched, so a converter can attach
 * fields the pipeline does not read without breaking anything.
 *
 * TWO ADMISSION REGIMES, deliberately different:
 *
 *   - RAW INGEST: each parser enforces its own required fields and HARD-ERRORS on a
 *     record it cannot read, naming the file and line. A parser knows exactly what it
 *     needs and can point at the offending input.
 *   - THE `events.json` LANE: `loadEventsFromArray` below applies `hasRequiredFields` and
 *     DROPS what it cannot admit. This lane is handed an array by some other tool and can
 *     only account for what it discarded — which it does, by index, via the caller.
 *
 * Neither is allowed to be quiet. Silently losing a record is silently losing evidence.
 *
 * `docs/schema.md` is the prose version of this file, field by field, with which stage
 * reads what.
 */

/**
 * Normalized conn.log event — the input to network candidate scoring.
 */
export interface ConnLogEvent {
  id: string;
  timestamp: string;        // ISO 8601
  source: 'zeek';
  event_type: 'conn';
  src_ip: string;           // id.orig_h
  src_port?: number;        // id.orig_p
  dest_ip: string;          // id.resp_h
  dest_port: number;        // id.resp_p
  proto: string;            // proto (tcp, udp, icmp)
  service?: string;         // service
  conn_state?: string;      // conn_state
  duration?: number;        // duration (seconds)
  orig_bytes?: number;      // orig_bytes (payload bytes out)
  resp_bytes?: number;      // resp_bytes (payload bytes in)
  orig_pkts?: number;       // orig_pkts
  resp_pkts?: number;       // resp_pkts
  zeek_uid?: string;        // uid
  history?: string;         // history
  [key: string]: unknown;
}

// ─── PowerShell Invocation Anomaly Event Contracts ─────────

export const SYSMON_PROCESS_CREATE_EVENT_TYPE = 'process_create' as const;
export function isProcessCreateEventType(value: unknown): value is typeof SYSMON_PROCESS_CREATE_EVENT_TYPE {
  return value === SYSMON_PROCESS_CREATE_EVENT_TYPE;
}

export interface ProcessCreateEvent {
  id: string;
  timestamp: string;
  source: 'sysmon';
  event_type: typeof SYSMON_PROCESS_CREATE_EVENT_TYPE;
  domain?: 'traditional';
  event_id: 1;
  host: string;
  src_ip?: string;

  process_name: string;
  process_path: string;
  process_id: number;
  process_guid: string;

  parent_process_name: string;
  parent_process_path: string;
  parent_process_id: number;
  parent_process_guid: string;

  user: string;
  integrity_level: string;
  current_directory?: string;

  original_file_name: string | null;
  description: string | null;
  product: string | null;
  company: string | null;

  command_line: string;
  // Sysmon's comma-joined wire string, carried verbatim: `MD5=…,SHA256=…,IMPHASH=…`.
  hashes?: string;
  [key: string]: unknown;
}

export const SYSMON_NETWORK_CONNECT_EVENT_TYPE = 'network_connect' as const;
export function isNetworkConnectEventType(value: unknown): value is typeof SYSMON_NETWORK_CONNECT_EVENT_TYPE {
  return value === SYSMON_NETWORK_CONNECT_EVENT_TYPE;
}

export interface NetworkConnectEvent {
  id: string;
  timestamp: string;
  source: 'sysmon';
  event_type: typeof SYSMON_NETWORK_CONNECT_EVENT_TYPE;
  event_id: 3;
  host: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  protocol: string;
  process_name: string;
  process_id: number;
  process_guid: string;
  user: string;
  [key: string]: unknown;
}

export const SYSMON_IMAGE_LOAD_EVENT_TYPE = 'image_load' as const;
export function isImageLoadEventType(value: unknown): value is typeof SYSMON_IMAGE_LOAD_EVENT_TYPE {
  return value === SYSMON_IMAGE_LOAD_EVENT_TYPE;
}

export interface ImageLoadEvent {
  id: string;
  timestamp: string;
  source: 'sysmon';
  event_type: typeof SYSMON_IMAGE_LOAD_EVENT_TYPE;
  domain?: 'traditional';
  event_id: 7;
  host: string;
  src_ip?: string;

  process_name: string;
  image: string;
  process_id: number;
  process_guid: string;

  image_loaded: string;
  signed: string;
  signature: string;
  signature_status: string;
  // Sysmon's comma-joined wire string, carried verbatim: `MD5=…,SHA256=…,IMPHASH=…`.
  hashes?: string;
  [key: string]: unknown;
}

// ─── PowerShell Script Block Event Contract ─────────────────
// The extensibility lane. These events are parsed, validated, normalized, merged into
// the stream and keyed into the script-block-hash frequency table — and NO SCORER READS
// THEM IN v1, because none of the five candidate types looks at script blocks. The
// contract is named here rather than duck-typed because `schema/` is the documented
// ingest surface, and because writing the scorer that uses it should not also mean
// discovering what shape the events are in. See `docs/extending.md`.

export const POWERSHELL_SCRIPT_BLOCK_EVENT_TYPE = 'script_block' as const;
export function isPowerShellScriptBlockEventType(
  value: unknown,
): value is typeof POWERSHELL_SCRIPT_BLOCK_EVENT_TYPE {
  return value === POWERSHELL_SCRIPT_BLOCK_EVENT_TYPE;
}

export interface PowerShellScriptBlockEvent {
  id: string;
  timestamp: string;                // ISO 8601
  source: 'powershell';
  event_type: typeof POWERSHELL_SCRIPT_BLOCK_EVENT_TYPE;
  event_id: 4104;
  host: string;
  src_ip?: string;

  // Script-block identity. extractScriptBlockEntity() prefers script_block_hash,
  // then sha256(script_block_text), then `id:${script_block_id}` — at least one
  // must be present for the record to carry an entity.
  script_block_hash?: string;
  script_block_id?: string;
  script_block_text?: string;
  [key: string]: unknown;
}

/**
 * Pre-joined Zeek ssl.log + x509.log event — the input to TLS Anomaly scoring.
 * Contains both TLS handshake fields (SNI, JA3, cipher) and certificate fields
 * (validity, serial, subject, issuer). The join happens upstream (test-data-generator
 * produces pre-joined events; production pipeline joins ssl+x509 before scoring).
 *
 * When x509 data is absent: cert_* fields are null/default (cert_self_signed: false,
 * cert_expired: false, cert_validity_days: null, cert_san_dns: [], cert_chain_length: 0).
 */
export interface TlsSslEvent {
  id: string;
  timestamp: string;        // ISO 8601
  source: 'zeek';
  event_type: 'ssl';
  src_ip: string;
  dest_ip: string;
  dest_port: number;
  server_name: string | null;
  tls_version: string | null;
  cipher: string | null;
  ja3_hash: string | null;
  ja4_hash: string | null;
  ja3s_hash: string | null;
  ja4x_hash: string | null;
  sni_matches_cert: boolean | null;
  cert_subject: string | null;
  cert_issuer: string | null;
  cert_serial: string | null;
  cert_not_before: string | null;   // ISO 8601
  cert_not_after: string | null;    // ISO 8601
  cert_self_signed: boolean;
  cert_expired: boolean;
  cert_validity_days: number | null;
  cert_key_type: string | null;
  cert_key_length: number | null;
  cert_san_dns: string[];
  cert_chain_length: number;
  connection_to_ip: boolean;
  [key: string]: unknown;
}

/**
 * Generic event type — union of all event types.
 * Expanded as we add more candidate types.
 */
export type TelemetryEvent =
  | ConnLogEvent
  | ProcessCreateEvent
  | NetworkConnectEvent
  | ImageLoadEvent
  | PowerShellScriptBlockEvent
  | TlsSslEvent;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasNonEmptyString(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  return typeof value === 'string' && value.trim().length > 0;
}

function hasFiniteNumber(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  return typeof value === 'number' && Number.isFinite(value);
}

function hasAnyNonEmptyString(record: Record<string, unknown>, keys: string[]): boolean {
  return keys.some((key) => hasNonEmptyString(record, key));
}

function hasValidTimestamp(record: Record<string, unknown>): boolean {
  const value = record.timestamp;
  return typeof value === 'string' && value.trim().length > 0 && Number.isFinite(Date.parse(value));
}

function hasRequiredFields(record: Record<string, unknown>): boolean {
  if (!hasNonEmptyString(record, 'source')) return false;
  if (!hasNonEmptyString(record, 'event_type')) return false;
  if (!hasValidTimestamp(record)) return false;

  const source = String(record.source);
  const eventType = String(record.event_type);

  if (source === 'zeek') {
    if (eventType === 'conn') {
      return hasNonEmptyString(record, 'src_ip')
        && hasNonEmptyString(record, 'dest_ip')
        && hasFiniteNumber(record, 'dest_port')
        && hasNonEmptyString(record, 'proto');
    }

    if (eventType === 'ssl') {
      return hasNonEmptyString(record, 'src_ip')
        && hasNonEmptyString(record, 'dest_ip')
        && hasFiniteNumber(record, 'dest_port');
    }

    return false;
  }

  if (source === 'sysmon') {
    if (eventType === 'process_create') {
      return hasFiniteNumber(record, 'event_id')
        && hasNonEmptyString(record, 'host')
        && hasNonEmptyString(record, 'process_name')
        && hasNonEmptyString(record, 'process_path')
        && hasFiniteNumber(record, 'process_id')
        && hasNonEmptyString(record, 'process_guid')
        && hasNonEmptyString(record, 'parent_process_name')
        && hasNonEmptyString(record, 'parent_process_path')
        && hasFiniteNumber(record, 'parent_process_id')
        && hasNonEmptyString(record, 'parent_process_guid')
        && hasNonEmptyString(record, 'user')
        && hasNonEmptyString(record, 'command_line');
    }

    if (eventType === 'network_connect') {
      return hasFiniteNumber(record, 'event_id')
        && hasNonEmptyString(record, 'host')
        && hasNonEmptyString(record, 'src_ip')
        && hasFiniteNumber(record, 'src_port')
        && hasNonEmptyString(record, 'dest_ip')
        && hasFiniteNumber(record, 'dest_port')
        && hasNonEmptyString(record, 'protocol')
        && hasNonEmptyString(record, 'process_name')
        && hasFiniteNumber(record, 'process_id')
        && hasNonEmptyString(record, 'process_guid')
        && hasNonEmptyString(record, 'user');
    }

    if (eventType === 'image_load') {
      return hasFiniteNumber(record, 'event_id')
        && hasNonEmptyString(record, 'host')
        && hasNonEmptyString(record, 'process_name')
        && hasNonEmptyString(record, 'image')
        && hasFiniteNumber(record, 'process_id')
        && hasNonEmptyString(record, 'process_guid')
        && hasNonEmptyString(record, 'image_loaded')
        && hasNonEmptyString(record, 'signed')
        && hasNonEmptyString(record, 'signature')
        && hasNonEmptyString(record, 'signature_status');
    }

    return false;
  }

  // NEW IN ATHANOR — admits the 4104 lane (see PowerShellScriptBlockEvent above).
  // Additive: the course canon carries no 'powershell'-sourced records, so this
  // branch cannot move Pin A / Pin B.
  if (source === 'powershell') {
    if (eventType === 'script_block') {
      return hasFiniteNumber(record, 'event_id')
        && hasNonEmptyString(record, 'host')
        && hasAnyNonEmptyString(record, ['script_block_hash', 'script_block_text', 'script_block_id']);
    }

    return false;
  }

  return false;
}

// Raw-zeek ssl.log field name -> the normalized name the TLS-anomaly scorer reads.
// server_name is handled separately (it must fall back to null for an empty SNI).
const ZEEK_SSL_ALIASES: ReadonlyArray<readonly [normalized: string, raw: string]> = [
  ['ja3_hash', 'tls_ja3'],
  ['ja3s_hash', 'tls_ja3s'],
  ['cert_subject', 'tls_subject'],
  ['cert_issuer', 'tls_issuer'],
];

/**
 * Fill the TLS-anomaly scorer's normalized field names from the raw zeek ssl.log
 * naming when they are absent. The zeek-ssl generator emits the RAW naming
 * (tls_server_name, tls_ja3, tls_ja3s, tls_subject, tls_issuer) while the scorer
 * reads the NORMALIZED naming (server_name, ja3_hash, ja3s_hash, cert_subject,
 * cert_issuer). Without this ingest step a beacon-path ssl record reaches the
 * scorer with server_name === undefined and scores as sni_missing chaff.
 *
 * Fill-when-absent: an explicitly-set normalized value (including the tls-anomaly
 * generator's dual-writes and every committed fixture) is never overwritten, so
 * distillation output stays byte-identical. Cert booleans/validity are left to
 * explicit generator params — a benign ssl record legitimately has none.
 */
export function normalizeZeekSslRecord(record: Record<string, unknown>): void {
  if (record.event_type !== 'ssl') return;

  // server_name ??= tls_server_name || null  (an empty raw SNI resolves to null).
  if (record.server_name === undefined || record.server_name === null) {
    const raw = record.tls_server_name;
    record.server_name = typeof raw === 'string' && raw.length > 0 ? raw : null;
  }

  // Fingerprint + cert aliases: fill only from a usable raw value, so a record
  // that carried neither key keeps its shape (no invented null aliases).
  for (const [normalized, raw] of ZEEK_SSL_ALIASES) {
    const current = record[normalized];
    if (current !== undefined && current !== null) continue;
    const value = record[raw];
    if (value === undefined || value === null) continue;
    record[normalized] = value;
  }
}

/**
 * Load events from a JSON array file (events.json from test-data-generator).
 */
export async function loadEvents(path: string): Promise<TelemetryEvent[]> {
  const { readFile } = await import('node:fs/promises');
  const raw = await readFile(path, 'utf-8');
  return loadEventsFromArray(JSON.parse(raw) as unknown, path);
}

/**
 * The admission rules, applied to an already-parsed array.
 *
 * Split out of `loadEvents` so a caller that has the bytes already — folder ingest,
 * which decompresses a `.gz` before anything downstream sees it — admits records
 * through THIS function rather than through a second copy of the rules that could
 * drift from it. `loadEvents(path)` is now read + parse + this.
 */
export function loadEventsFromArray(parsed: unknown, path: string): TelemetryEvent[] {
  if (!Array.isArray(parsed)) {
    throw new Error(`events file must contain a JSON array: ${path}`);
  }

  const out: TelemetryEvent[] = [];
  for (let idx = 0; idx < parsed.length; idx += 1) {
    const item = parsed[idx];
    if (!isRecord(item)) continue;
    if (!hasRequiredFields(item)) continue;

    const id = hasNonEmptyString(item, 'id')
      ? String(item.id).trim()
      : `evt-synth-${String(idx + 1).padStart(6, '0')}`;

    const loaded: Record<string, unknown> = { ...item, id };
    normalizeZeekSslRecord(loaded);
    out.push(loaded as TelemetryEvent);
  }

  return out;
}
