import {
  scoreUnusualParentChildAnomalyCandidates,
  resetCandidateCounter,
  loadUnusualParentChildAnomalyConfig,
  type UnusualParentChildAnomalyConfig,
} from '../../pipeline/score/unusual-parent-child-anomaly.js';
import { createDistillationRunner } from '../runner-factory.js';
import { selectTelemetryEvents } from '../select.js';

let cachedUnusualParentChildConfig: UnusualParentChildAnomalyConfig | null = null;

function unusualParentChildConfig(): UnusualParentChildAnomalyConfig {
  if (!cachedUnusualParentChildConfig) {
    cachedUnusualParentChildConfig = loadUnusualParentChildAnomalyConfig();
  }
  return cachedUnusualParentChildConfig;
}

export const runUnusualParentChildAnomalyDistillation = createDistillationRunner({
  candidateType: 'unusual_parent_child_anomaly',
  selectScorerInput: selectTelemetryEvents,
  scoreCandidates: (input) => {
    const processCreateEvents = input.filter(
      (event) => event.source === 'sysmon' && event.event_type === 'process_create',
    );
    return scoreUnusualParentChildAnomalyCandidates(
      processCreateEvents as import('../../schema/events.js').ProcessCreateEvent[],
      unusualParentChildConfig(),
    );
  },
  resetCandidateCounter,
});
