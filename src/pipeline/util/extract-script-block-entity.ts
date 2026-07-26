import { createHash } from 'node:crypto';
import { normalizeString } from './normalize-string.js';

export interface ScriptBlockEntitySource {
  script_block_hash?: unknown;
  script_block_id?: unknown;
  script_block_text?: unknown;
}

function normalizeLower(value: unknown): string | null {
  const raw = normalizeString(value);
  return raw ? raw.toLowerCase() : null;
}

function normalizeScriptText(value: unknown): string | null {
  const raw = normalizeString(value);
  if (!raw) return null;

  // Keep textual identity stable across CRLF/LF platforms.
  return raw.replace(/\r\n/g, '\n');
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function extractScriptBlockEntity(source: ScriptBlockEntitySource): string | null {
  const explicitHash = normalizeLower(source.script_block_hash);
  if (explicitHash) return explicitHash;

  const scriptText = normalizeScriptText(source.script_block_text);
  if (scriptText) return sha256(scriptText);

  const scriptBlockId = normalizeLower(source.script_block_id);
  if (scriptBlockId) return `id:${scriptBlockId}`;

  return null;
}
