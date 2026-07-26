// Unit — PowerShell 4104 script-block parser. The extensibility lane: no scorer
// consumes these events in v1, so the contract that matters is that ingest names the
// fields the script-block entity extractor and the LFA rarity table read.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IngestError, parseJsonLines } from '../../src/ingest/codecs.js';
import { parsePowerShell4104Record } from '../../src/ingest/ps-4104.js';

const LINE = '{"TimeCreated":"2026-03-09T14:00:15.600Z","Computer":"DEVBOX-07",'
  + '"ScriptBlockId":"6e3b798a-5db3-9fc2-0bc2-09758dc05565","ScriptBlockText":"Write-Host hi",'
  + '"Path":"","MessageNumber":1,"MessageTotal":1}';

function parseOne(line: string, file = 'powershell-4104.jsonl') {
  return parsePowerShell4104Record(parseJsonLines(line, file)[0]!);
}

describe('ingest/ps-4104', () => {
  it('maps a 4104 line to the exact normalized record', () => {
    const parsed = parseOne(LINE);

    assert.equal(parsed.dialect, 'powershell/script_block');
    assert.equal(parsed.timestampMs, Date.parse('2026-03-09T14:00:15.600Z'));
    assert.deepEqual(parsed.event, {
      timestamp: '2026-03-09T14:00:15.600Z',
      // The three stamps the raw file does not carry.
      source: 'powershell',
      event_type: 'script_block',
      event_id: 4104,
      host: 'DEVBOX-07',
      script_block_id: '6e3b798a-5db3-9fc2-0bc2-09758dc05565',
      script_block_text: 'Write-Host hi',
      message_number: 1,
      message_total: 1,
      domain: 'traditional',
    });
  });

  it('omits an empty Path and keeps a real one', () => {
    assert.equal('script_block_path' in parseOne(LINE).event, false);
    const withPath = parseOne(LINE.replace('"Path":""', '"Path":"C:\\\\ops\\\\deploy.ps1"'));
    assert.equal(withPath.event.script_block_path, 'C:\\ops\\deploy.ps1');
  });

  it('synthesizes no script_block_hash — the extractor derives one from the text', () => {
    assert.equal('script_block_hash' in parseOne(LINE).event, false);
  });

  it('reports file:line on a malformed record', () => {
    assert.throws(
      () => parseOne('{"Computer":"DEVBOX-07","ScriptBlockText":"x"}'),
      (error: unknown) => error instanceof IngestError
        && /powershell-4104\.jsonl:1: expected non-empty string field "TimeCreated"/.test((error as Error).message),
    );
    assert.throws(
      () => parseOne('{"TimeCreated":"not a date","Computer":"DEVBOX-07"}'),
      (error: unknown) => error instanceof IngestError
        && /unparseable ISO timestamp "TimeCreated"/.test((error as Error).message),
    );
  });
});
