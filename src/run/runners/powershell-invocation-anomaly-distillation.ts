import {
  scorePowerShellInvocationAnomalyCandidates,
  resetCandidateCounter,
  loadPowerShellInvocationConfig,
  type PowerShellInvocationConfig,
} from '../../pipeline/score/powershell-invocation-anomaly.js';
import { createDistillationRunner } from '../runner-factory.js';
import { selectTelemetryEvents } from '../select.js';

let cachedPowerShellInvocationConfig: PowerShellInvocationConfig | null = null;

function powerShellInvocationConfig(): PowerShellInvocationConfig {
  if (!cachedPowerShellInvocationConfig) {
    cachedPowerShellInvocationConfig = loadPowerShellInvocationConfig();
  }
  return cachedPowerShellInvocationConfig;
}

export const runPowerShellInvocationAnomalyDistillation = createDistillationRunner({
  candidateType: 'powershell_invocation_anomaly',
  selectScorerInput: selectTelemetryEvents,
  scoreCandidates: (input) => scorePowerShellInvocationAnomalyCandidates(input, powerShellInvocationConfig()),
  resetCandidateCounter,
});
