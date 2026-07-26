import { scoreTlsAnomalyCandidates } from '../../pipeline/score/tls-anomaly.js';
import { createDistillationRunner } from '../runner-factory.js';
import { selectSslEvents } from '../select.js';

export const runTlsAnomalyDistillation = createDistillationRunner({
  candidateType: 'tls_anomaly',
  selectScorerInput: selectSslEvents,
  scoreCandidates: (input) => scoreTlsAnomalyCandidates(input),
});
