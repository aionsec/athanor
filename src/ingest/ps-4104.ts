/**
 * PowerShell Script Block Logging (EID 4104) JSONL → normalized
 * `PowerShellScriptBlockEvent`.
 *
 * This is the extensibility lane, not part of the course canon: the canon dataset
 * carries no 4104 records, so the emitter DERIVES this file from the EncodedCommand
 * seen in an EID 1 command line (`evt-00676`) and writes it to `raw-aux/`, beside
 * rather than inside the pin folder. Inserting events mid-stream would shift every
 * later reconstructed id — see `fixtures/README.md`.
 *
 * Field map (inverse of the emitter's `renderScriptBlockLines`):
 *   TimeCreated    → timestamp        (ISO 8601)
 *   Computer       → host
 *   ScriptBlockId  → script_block_id
 *   ScriptBlockText→ script_block_text
 *   Path           → script_block_path  (empty string → omitted)
 *   MessageNumber  → message_number
 *   MessageTotal   → message_total
 *   (dialect)      → source 'powershell', event_type 'script_block', event_id 4104,
 *                    domain 'traditional'
 *
 * `script_block_hash` is NOT synthesized: the raw record does not carry one, and
 * `extractScriptBlockEntity` already falls back to sha256(script_block_text).
 */

import { compact, isoFromMs, type RawRecord, RecordReader } from './codecs.js';
import type { ParsedEvent } from './merge.js';

export const POWERSHELL_SCRIPT_BLOCK_DIALECT = 'powershell/script_block';

export const POWERSHELL_SCRIPT_BLOCK_EVENT_ID = 4104;

export function parsePowerShell4104Record(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const timestampMs = reader.isoTimestampMs('TimeCreated');

  const path = reader.optionalString('Path');

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'powershell',
    event_type: 'script_block',
    event_id: POWERSHELL_SCRIPT_BLOCK_EVENT_ID,
    host: reader.requiredString('Computer'),
    script_block_id: reader.optionalString('ScriptBlockId'),
    script_block_text: reader.optionalString('ScriptBlockText'),
    script_block_path: path !== undefined && path.length > 0 ? path : undefined,
    message_number: reader.optionalNumber('MessageNumber'),
    message_total: reader.optionalNumber('MessageTotal'),
    domain: 'traditional',
  });

  return { dialect: POWERSHELL_SCRIPT_BLOCK_DIALECT, timestampMs, event, origin: reader.label };
}

export function parsePowerShell4104(records: ReadonlyArray<RawRecord>): ParsedEvent[] {
  return records.map(parsePowerShell4104Record);
}
