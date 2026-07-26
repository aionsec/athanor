import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  STAGE2_APPLICABILITY_BY_EVENT_KEY,
  STAGE2_LABEL_CONTRACTS_BY_LABEL,
} from '../../../src/enrich-events/index.js';
import {
  ACTIVE_STAGE4_ENRICHMENT_LABELS,
  STAGE2_EVENT_ENRICHMENT_CONTRACTS,
  STAGE2_ENRICHMENT_SPEC,
  STAGE4_APPLICABILITY_BY_CANDIDATE,
  STAGE4_CANDIDATE_TYPES,
  STAGE4_ENRICHMENT_LABEL_SPECS,
  type Stage4EnrichmentLabel,
  type Stage4EnrichmentLabelSpec,
} from '../../../src/pipeline/spec/enrichment-spec.js';
import {
  assertActiveStage4StamperCoverage,
  STAGE4_STAMPER_BINDINGS,
} from '../../../src/pipeline/enrich-candidates/stamper-bindings.js';

// The Stage 2 and Stage 4 enrichment contracts, pinned directly.
//
// These are declaration tables, not logic, which makes them exactly the kind of thing that
// drifts without failing anything: a `valueType` edited here, an applicability entry added
// there, and the output shape changes with no test to notice. The cases below assert the
// declared field shape itself, so an edit to the spec has to be an edit to this file too.
const STAGE2_RATIONALE_REF = 'docs/design.md#stage-2-event-enrichment';

/** The Stage 2 contract, pinned. A `valueType` / `nullable` edit anywhere upstream fails here. */
const EXPECTED_STAGE2_CONTRACT = [
  { label: 'business_hours', required: true, valueType: 'boolean', nullable: true },
  { label: 'lolbas_match', required: true, valueType: 'boolean', nullable: true },
  { label: 'hijacklibs_match', required: true, valueType: 'boolean', nullable: true },
  { label: 'filesec_match', required: true, valueType: 'boolean', nullable: true },
  {
    label: 'persistence_path_class',
    required: true,
    valueType: 'enum',
    nullable: true,
    enumValues: ['registry', 'scheduled_task', 'service', 'startup', 'file_in_startup_dir'],
  },
  { label: 'security_tool_name', required: true, valueType: 'string', nullable: true },
  {
    label: 'account_type',
    required: true,
    valueType: 'enum',
    nullable: true,
    enumValues: ['user', 'admin', 'service'],
  },
];

const STAGE4_VALUE_TYPES = new Set(['boolean', 'number', 'string', 'enum', 'object']);

const stage4LabelEntries = Object.entries(STAGE4_ENRICHMENT_LABEL_SPECS) as Array<
  [Stage4EnrichmentLabel, Stage4EnrichmentLabelSpec]
>;

describe('enrichment spec contracts', () => {
  it('pins the field-level Stage 2 enrichment contract', () => {
    const projected = STAGE2_ENRICHMENT_SPEC.map((spec) => ({
      label: spec.label,
      required: spec.required,
      valueType: spec.valueType,
      nullable: spec.nullable,
      ...(spec.enumValues ? { enumValues: [...spec.enumValues] } : {}),
    }));

    assert.deepEqual(projected, EXPECTED_STAGE2_CONTRACT);

    for (const spec of STAGE2_ENRICHMENT_SPEC) {
      assert.equal(spec.stage, 'stage2_event', `${spec.label} must be a Stage 2 label`);
      assert.equal(spec.rationaleRef, STAGE2_RATIONALE_REF, `${spec.label} rationaleRef drifted`);
      assert.equal(
        spec.enumValues !== undefined,
        spec.valueType === 'enum',
        `${spec.label} must carry enumValues if and only if it is an enum`,
      );
      if (spec.enumValues) {
        assert.equal(spec.enumValues.length > 0, true, `${spec.label} declares an empty enum`);
        for (const value of spec.enumValues) {
          assert.equal(typeof value, 'string', `${spec.label} enum value must be a string`);
        }
      }
    }
  });

  it('derives every Stage 2 spec entry from its source label contract', () => {
    const sourceLabels = Object.keys(STAGE2_LABEL_CONTRACTS_BY_LABEL);

    assert.deepEqual(STAGE2_ENRICHMENT_SPEC.map((spec) => spec.label), sourceLabels);
    assert.equal(new Set(sourceLabels).size, sourceLabels.length, 'duplicate Stage 2 label');

    const contracts = STAGE2_LABEL_CONTRACTS_BY_LABEL as Record<
      string,
      { valueType: string; nullable: boolean; enumValues?: readonly string[] }
    >;

    for (const spec of STAGE2_ENRICHMENT_SPEC) {
      const contract = contracts[spec.label];
      assert.notEqual(contract, undefined, `${spec.label} has no source label contract`);
      assert.equal(spec.required, true, `${spec.label} must be required`);
      assert.equal(spec.valueType, contract.valueType, `${spec.label} valueType diverged from source`);
      assert.equal(spec.nullable, contract.nullable, `${spec.label} nullable diverged from source`);
      assert.deepEqual(spec.enumValues, contract.enumValues, `${spec.label} enumValues diverged from source`);
    }
  });

  it('derives Stage 2 per-event applicability and contracts from shared source', () => {
    assert.equal(
      STAGE2_EVENT_ENRICHMENT_CONTRACTS.length,
      Object.keys(STAGE2_APPLICABILITY_BY_EVENT_KEY).length,
    );

    for (const contract of STAGE2_EVENT_ENRICHMENT_CONTRACTS) {
      assert.deepEqual(
        contract.labels,
        (STAGE2_APPLICABILITY_BY_EVENT_KEY as Record<string, readonly string[]>)[contract.eventKey],
      );
    }

    // Every label an event key claims must be one the Stage 2 spec actually declares —
    // otherwise an event type promises an enrichment field nothing can produce.
    const declaredStage2Labels = new Set(STAGE2_ENRICHMENT_SPEC.map((spec) => spec.label));
    for (const contract of STAGE2_EVENT_ENRICHMENT_CONTRACTS) {
      assert.equal(contract.labels.length > 0, true, `${contract.eventKey} declares no Stage 2 labels`);
      for (const label of contract.labels) {
        assert.equal(
          declaredStage2Labels.has(label),
          true,
          `${contract.eventKey} references undeclared Stage 2 label '${label}'`,
        );
      }
    }
  });

  it('pins the Stage 4 label spec shape', () => {
    assert.equal(stage4LabelEntries.length > 0, true);

    for (const [label, spec] of stage4LabelEntries) {
      assert.equal(spec.stage, 'stage4_candidate', `${label} must be a Stage 4 label`);
      assert.equal(STAGE4_VALUE_TYPES.has(spec.valueType), true, `${label} declares an unknown valueType`);
      assert.equal(typeof spec.nullable, 'boolean', `${label} nullable must be a boolean`);
      assert.equal(
        spec.status === 'active' || spec.status === 'planned',
        true,
        `${label} declares an unknown status '${spec.status}'`,
      );
      assert.equal(typeof spec.rationaleRef, 'string', `${label} must carry a rationaleRef`);
      assert.equal(spec.rationaleRef.length > 0, true, `${label} rationaleRef is empty`);

      // The LFA naming convention the rarity stamper and the scorers both rely on.
      if (label.endsWith('_rarity')) {
        assert.equal(spec.valueType, 'number', `${label} must be a number`);
      }
      if (label.endsWith('_frequency')) {
        assert.equal(spec.valueType, 'object', `${label} must be an object`);
      }
    }

    // `protocol_mismatch` is the one Stage 4 label that may be null (protocol not determinable).
    assert.deepEqual(
      stage4LabelEntries.filter(([, spec]) => spec.nullable).map(([label]) => label),
      ['protocol_mismatch'],
    );

    assert.deepEqual(
      [...ACTIVE_STAGE4_ENRICHMENT_LABELS],
      stage4LabelEntries.filter(([, spec]) => spec.status === 'active').map(([label]) => label),
    );
  });

  it('keeps Stage 4 applicability keyed to exactly the five extracted candidate types', () => {
    assert.deepEqual(
      [...STAGE4_CANDIDATE_TYPES],
      [
        'beacon',
        'data_transfer',
        'tls_anomaly',
        'powershell_invocation_anomaly',
        'unusual_parent_child_anomaly',
      ],
    );

    assert.deepEqual(
      Object.keys(STAGE4_APPLICABILITY_BY_CANDIDATE).slice().sort(),
      [...STAGE4_CANDIDATE_TYPES].slice().sort(),
    );

    for (const [candidateType, labels] of Object.entries(STAGE4_APPLICABILITY_BY_CANDIDATE)) {
      assert.equal(
        new Set(labels as readonly string[]).size,
        labels.length,
        `${candidateType} lists a duplicate Stage 4 label`,
      );
    }
  });

  it('keeps Stage 4 applicability labels constrained to declared Stage 4 labels', () => {
    const declaredLabels = new Set(Object.keys(STAGE4_ENRICHMENT_LABEL_SPECS));

    for (const [candidateType, labels] of Object.entries(STAGE4_APPLICABILITY_BY_CANDIDATE)) {
      assert.equal(labels.length > 0, true, `${candidateType} must declare at least one Stage 4 label`);

      for (const label of labels) {
        assert.equal(declaredLabels.has(label), true, `${candidateType} references undeclared Stage 4 label '${label}'`);
      }
    }
  });

  it('binds every active Stage 4 label to a stamper binding', () => {
    assert.doesNotThrow(() => assertActiveStage4StamperCoverage());

    for (const label of ACTIVE_STAGE4_ENRICHMENT_LABELS) {
      assert.equal(
        Object.hasOwn(STAGE4_STAMPER_BINDINGS, label),
        true,
        `missing stamper binding for active label '${label}'`,
      );
    }
  });
});
