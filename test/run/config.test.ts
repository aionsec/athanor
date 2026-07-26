// Three suites over the config surface.
//
// The parser-rejection cases drive `parseAthanorConfig` directly and pin the shapes it
// refuses, along with the exact messages it refuses them with.
//
// The default-config cases pin athanor's baked-in defaults — the four emit floors, the
// candidate-type order, the DT / UPCA presentation prefixes — which are the configuration
// that produced the committed goldens.
//
// The merge suite is athanor's own. `--config` is a PER-KEY DEEP MERGE: a key the
// file names wins, a key it does not name keeps its canon default, and a key set to
// `null` is removed. The scenario that used to be the foot-gun — a partial
// `emit_floors` deleting the floors it did not mention — is pinned here as the
// behavior it now must NOT have.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  DEFAULT_ATHANOR_CONFIG,
  defaultAthanorConfig,
  loadAthanorConfig,
  loadAthanorConfigWithSummary,
  parseAthanorConfig,
  parseAthanorConfigWithSummary,
  resolveAthanorConfig,
} from '../../src/run/config.js';

/** Parses YAML text the way `--config` does, so the cases read as config files. */
function fromYaml(text: string) {
  return parseAthanorConfigWithSummary(parseYaml(text), 'athanor.yaml');
}

describe('athanor config defaults', () => {
  it('matches the curriculum-scenario-fundamentals canon', () => {
    // distill_candidates (YAML lines 31-36) — order is the emit order.
    assert.deepEqual(DEFAULT_ATHANOR_CONFIG.candidateTypes, [
      'beacon',
      'data_transfer',
      'tls_anomaly',
      'unusual_parent_child_anomaly',
      'powershell_invocation_anomaly',
    ]);
    // emit_floors (YAML lines 38-42) — four floors, NOT five: data_transfer has none.
    assert.deepEqual(DEFAULT_ATHANOR_CONFIG.emitFloors, {
      beacon: 0.40,
      powershell_invocation_anomaly: 0.60,
      unusual_parent_child_anomaly: 0.60,
      tls_anomaly: 0.40,
    });
    assert.equal('data_transfer' in DEFAULT_ATHANOR_CONFIG.emitFloors, false);
    // presentation_ids (YAML lines 44-48) — only the two types whose deterministic
    // prefix (DTR / UPC) differs from the taught prefix get an override.
    assert.deepEqual(DEFAULT_ATHANOR_CONFIG.presentationIds, {
      enabled: true,
      prefixes: { data_transfer: 'DT', unusual_parent_child_anomaly: 'UPCA' },
    });
  });

  it('hands out an independent copy so callers cannot mutate the canon', () => {
    const first = defaultAthanorConfig();
    first.emitFloors.beacon = 0.99;
    first.candidateTypes.push('nope');
    assert.equal(defaultAthanorConfig().emitFloors.beacon, 0.40);
    assert.equal(defaultAthanorConfig().candidateTypes.length, 5);
  });

  it('overlays a partial in-memory config on the canon defaults', () => {
    // The PROGRAMMATIC seam replaces per FIELD, unlike the YAML file's per-key merge:
    // a caller passing `emitFloors` hands over the whole map it wants, and a typed
    // object has no way to say "remove one key" that omitting it does not say better.
    const resolved = resolveAthanorConfig({ emitFloors: { beacon: 0.9 } });
    assert.deepEqual(resolved.emitFloors, { beacon: 0.9 });
    assert.deepEqual(resolved.candidateTypes, DEFAULT_ATHANOR_CONFIG.candidateTypes);
    assert.deepEqual(resolved.presentationIds, DEFAULT_ATHANOR_CONFIG.presentationIds);
  });
});

describe('athanor.yaml — the per-key deep merge', () => {
  it('keeps the floors a partial emit_floors block does not name', () => {
    // The old foot-gun, pinned as the behavior it must NOT have: a student
    // lowering the beacon floor to see more beacons used to delete the other three.
    const { config, summary } = fromYaml('emit_floors:\n  beacon: 0.2\n');

    assert.deepEqual(config.emitFloors, {
      beacon: 0.2,
      powershell_invocation_anomaly: 0.60,
      unusual_parent_child_anomaly: 0.60,
      tls_anomaly: 0.40,
    });
    assert.deepEqual(summary, { overridden: ['emit_floors.beacon'], removed: [] });
  });

  it('removes exactly the floor a null names, and keeps the rest', () => {
    const { config, summary } = fromYaml('emit_floors:\n  tls_anomaly: null\n  beacon: 0.2\n');

    assert.deepEqual(config.emitFloors, {
      beacon: 0.2,
      powershell_invocation_anomaly: 0.60,
      unusual_parent_child_anomaly: 0.60,
    });
    assert.equal('tls_anomaly' in config.emitFloors, false, 'null REMOVES the entry');
    assert.deepEqual(summary, {
      overridden: ['emit_floors.beacon'],
      removed: ['emit_floors.tls_anomaly'],
    });
  });

  it('adds a floor the canon does not declare', () => {
    // data_transfer deliberately has no canon floor; naming one adds it.
    const { config } = fromYaml('emit_floors:\n  data_transfer: 0.5\n');
    assert.equal(config.emitFloors.data_transfer, 0.5);
    assert.equal(config.emitFloors.beacon, 0.40, 'the canon four are untouched');
    assert.equal(Object.keys(config.emitFloors).length, 5);
  });

  it('clears every floor when the whole block is null', () => {
    const { config, summary } = fromYaml('emit_floors: null\n');
    assert.deepEqual(config.emitFloors, {});
    assert.deepEqual(summary.removed, ['emit_floors']);
    // A bare `emit_floors:` is the same thing — YAML reads it as null.
    assert.deepEqual(fromYaml('emit_floors:\n').config.emitFloors, {});
  });

  it('merges presentation_ids per key, prefixes included', () => {
    const { config, summary } = fromYaml('presentation_ids:\n  enabled: false\n');
    assert.deepEqual(config.presentationIds, {
      enabled: false,
      prefixes: { data_transfer: 'DT', unusual_parent_child_anomaly: 'UPCA' },
    });
    assert.deepEqual(summary.overridden, ['presentation_ids.enabled']);

    const withPrefix = fromYaml('presentation_ids:\n  prefixes:\n    beacon: B\n').config;
    assert.deepEqual(withPrefix.presentationIds, {
      enabled: true,
      prefixes: { data_transfer: 'DT', unusual_parent_child_anomaly: 'UPCA', beacon: 'B' },
    }, 'an unnamed enabled keeps the default, and the named prefix joins the defaults');
  });

  it('removes a single prefix, the whole prefix map, or the whole block', () => {
    const oneGone = fromYaml('presentation_ids:\n  prefixes:\n    data_transfer: null\n');
    assert.deepEqual(oneGone.config.presentationIds, {
      enabled: true,
      prefixes: { unusual_parent_child_anomaly: 'UPCA' },
    });
    assert.deepEqual(oneGone.summary.removed, ['presentation_ids.prefixes.data_transfer']);

    const allGone = fromYaml('presentation_ids:\n  prefixes: null\n');
    assert.deepEqual(allGone.config.presentationIds, { enabled: true, prefixes: {} });

    const blockGone = fromYaml('presentation_ids: null\n');
    assert.equal(blockGone.config.presentationIds, null, 'the rename is disabled entirely');
    assert.deepEqual(blockGone.summary.removed, ['presentation_ids']);
  });

  it('replaces distill_candidates whole — a list has no keys to merge', () => {
    const { config, summary } = fromYaml('distill_candidates:\n  - beacon\n  - tls_anomaly\n');
    assert.deepEqual(config.candidateTypes, ['beacon', 'tls_anomaly']);
    assert.deepEqual(summary.overridden, ['distill_candidates']);
  });

  it('refuses the two distill_candidates shapes that would distill nothing', () => {
    // A bare `distill_candidates:` is a blank key, not a decision to emit no
    // candidates at all — and silently falling back to the canon five would hide it.
    assert.throws(() => fromYaml('distill_candidates:\n'), /would distill nothing/);
    assert.throws(() => fromYaml('distill_candidates: []\n'), /would distill nothing/);
  });

  it('reports nothing changed for a config that only restates the defaults', () => {
    const { config, summary } = fromYaml(
      'emit_floors:\n  beacon: 0.4\n  powershell_invocation_anomaly: 0.6\n'
      + '  unusual_parent_child_anomaly: 0.6\n  tls_anomaly: 0.4\n',
    );
    assert.deepEqual(config.emitFloors, DEFAULT_ATHANOR_CONFIG.emitFloors);
    assert.equal(summary.overridden.length, 4, 'declared keys are reported as declared');
    assert.deepEqual(summary.removed, []);
  });

  it('reports an empty summary for a config that names nothing', () => {
    const { config, summary } = parseAthanorConfigWithSummary({}, 'athanor.yaml');
    assert.deepEqual(config, defaultAthanorConfig());
    assert.deepEqual(summary, { overridden: [], removed: [] });
  });
});

describe('athanor.yaml parsing', () => {
  it('reads an athanor.yaml over the canon defaults', () => {
    const dir = mkdtempSync(join(tmpdir(), 'athanor-config-'));
    try {
      const configPath = join(dir, 'athanor.yaml');
      writeFileSync(
        configPath,
        [
          'distill_candidates:',
          '  - beacon',
          '  - tls_anomaly',
          'emit_floors:',
          '  beacon: 0.75',
          '',
        ].join('\n'),
        'utf-8',
      );

      const config = loadAthanorConfig(configPath);
      assert.deepEqual(config.candidateTypes, ['beacon', 'tls_anomaly']);
      // The named floor wins; the three it did not name keep their canon values.
      assert.deepEqual(config.emitFloors, {
        beacon: 0.75,
        powershell_invocation_anomaly: 0.60,
        unusual_parent_child_anomaly: 0.60,
        tls_anomaly: 0.40,
      });
      // Untouched blocks keep their canon default.
      assert.deepEqual(config.presentationIds, DEFAULT_ATHANOR_CONFIG.presentationIds);

      const { summary } = loadAthanorConfigWithSummary(configPath);
      assert.deepEqual(summary, {
        overridden: ['distill_candidates', 'emit_floors.beacon'],
        removed: [],
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an out-of-range emit floor with a clear error', () => {
    assert.throws(
      () => parseAthanorConfig({ emit_floors: { beacon: 1.5 } }, 'athanor.yaml'),
      /emit_floors\.beacon/,
    );
  });

  it('rejects a non-boolean presentation_ids.enabled with a clear error', () => {
    assert.throws(
      () => parseAthanorConfig({ presentation_ids: { enabled: 'yes' } }, 'athanor.yaml'),
      /presentation_ids\.enabled must be a boolean/,
    );
  });

  it('rejects a non-string presentation_ids prefix override with a clear error', () => {
    assert.throws(
      () => parseAthanorConfig(
        { presentation_ids: { enabled: true, prefixes: { beacon: 7 } } },
        'athanor.yaml',
      ),
      /presentation_ids\.prefixes\.beacon must be a non-empty string/,
    );
  });
});
