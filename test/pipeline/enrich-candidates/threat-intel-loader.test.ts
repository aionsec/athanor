// `loadThreatIntelFeedForDataset` has two branches and only one of them used to run: its
// callers passed directories containing no `feed.json`, so every execution took the
// bundled-table fallback. Both are pinned here, because the failure mode is silent — an
// empty feed produces `threat_intel_match: false` on every candidate, with no error and no
// warning to say the table was never loaded.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadThreatIntelFeed,
  loadThreatIntelFeedForDataset,
} from '../../../src/pipeline/enrich-candidates/threat-intel-loader.js';

/**
 * Builds a throwaway dataset directory and returns the `events.json` path inside it —
 * `loadThreatIntelFeedForDataset` takes the DATASET FILE path and looks for `feed.json`
 * beside it, not the directory.
 */
function withDatasetDir(
  feedJson: string | null,
  run: (datasetPath: string) => void,
): void {
  const dir = mkdtempSync(join(tmpdir(), 'athanor-feed-'));
  try {
    if (feedJson !== null) writeFileSync(join(dir, 'feed.json'), feedJson, 'utf-8');
    run(join(dir, 'events.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('loadThreatIntelFeedForDataset', () => {
  it('reads a dataset-local feed.json in the bare-array shape', () => {
    const entries = [
      { normalized_value: '203.0.113.77', match_type: 'ioc_ip' },
      { normalized_value: 'Evil.Example', match_type: 'ioc_domain' },
      { normalized_value: 'AABBCC0011', match_type: 'ioc_hash' },
      { normalized_value: 'https://Payload.Example/a.ps1', match_type: 'ioc_url' },
    ];

    withDatasetDir(JSON.stringify(entries), (datasetPath) => {
      const feed = loadThreatIntelFeedForDataset(datasetPath);

      assert.equal(feed.ips instanceof Set, true);
      assert.equal(feed.domains instanceof Set, true);
      assert.equal(feed.hashes instanceof Set, true);

      assert.deepEqual([...feed.ips].sort(), ['203.0.113.77']);
      // domains and hashes are lower-cased; an `ioc_url` contributes only its hostname.
      assert.deepEqual([...feed.domains].sort(), ['evil.example', 'payload.example']);
      assert.deepEqual([...feed.hashes].sort(), ['aabbcc0011']);
    });
  });

  it('reads a dataset-local feed.json in the {feeds: [...]} shape', () => {
    const wrapped = {
      feeds: [
        { normalized_value: '198.51.100.9', match_type: 'ioc_ip' },
        { normalized_value: 'wrapped.example', match_type: 'ioc_domain' },
      ],
    };

    withDatasetDir(JSON.stringify(wrapped), (datasetPath) => {
      const feed = loadThreatIntelFeedForDataset(datasetPath);

      assert.deepEqual([...feed.ips], ['198.51.100.9']);
      assert.deepEqual([...feed.domains], ['wrapped.example']);
      assert.deepEqual([...feed.hashes], []);
    });
  });

  it('drops entries whose normalized_value or match_type is missing, blank or non-string', () => {
    const entries = [
      { normalized_value: '203.0.113.77', match_type: 'ioc_ip' },
      { normalized_value: 12345, match_type: 'ioc_ip' },
      { normalized_value: '   ', match_type: 'ioc_ip' },
      { normalized_value: '203.0.113.78' },
      { match_type: 'ioc_ip' },
      { normalized_value: '203.0.113.79', match_type: 'ioc_unrecognised' },
      { normalized_value: 'not a url', match_type: 'ioc_url' },
      null,
      'nonsense',
    ];

    withDatasetDir(JSON.stringify(entries), (datasetPath) => {
      const feed = loadThreatIntelFeedForDataset(datasetPath);

      // Only the one well-formed ioc_ip survives; nothing throws.
      assert.deepEqual([...feed.ips], ['203.0.113.77']);
      assert.deepEqual([...feed.domains], []);
      assert.deepEqual([...feed.hashes], []);
    });
  });

  it('yields an empty feed for an unrecognised top-level shape', () => {
    withDatasetDir(JSON.stringify({ entries: [{ normalized_value: '203.0.113.77', match_type: 'ioc_ip' }] }), (datasetPath) => {
      const feed = loadThreatIntelFeedForDataset(datasetPath);

      assert.deepEqual([...feed.ips], []);
      assert.deepEqual([...feed.domains], []);
      assert.deepEqual([...feed.hashes], []);
    });
  });

  it('falls back to the default data/threat-intel/minimal.json table when no feed.json sits beside the dataset', () => {
    const fallback = loadThreatIntelFeed();

    withDatasetDir(null, (datasetPath) => {
      const feed = loadThreatIntelFeedForDataset(datasetPath);

      assert.deepEqual([...feed.ips].sort(), [...fallback.ips].sort());
      assert.deepEqual([...feed.domains].sort(), [...fallback.domains].sort());
      assert.deepEqual([...feed.hashes].sort(), [...fallback.hashes].sort());

      // This is the branch that produced the course goldens, so the vendored table itself is
      // pinned: an empty fallback would silently zero every `threat_intel_match`.
      assert.deepEqual([...feed.ips].sort(), ['198.51.100.200', '203.0.113.10']);
      assert.deepEqual([...feed.domains].sort(), ['api.bad.example', 'bad.example']);
      assert.deepEqual([...feed.hashes].sort(), ['9f86d081884c7d659a2feaa0c55ad015']);
    });
  });
});
