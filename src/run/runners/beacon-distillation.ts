import { scoreBeaconCandidates, resetCandidateCounter } from '../../pipeline/score/beacon.js';
import { createDistillationRunner } from '../runner-factory.js';
import { selectConnEvents } from '../select.js';

export const runBeaconDistillation = createDistillationRunner({
  candidateType: 'beacon',
  selectScorerInput: selectConnEvents,
  scoreCandidates: (input) => scoreBeaconCandidates(input),
  resetCandidateCounter,
});
