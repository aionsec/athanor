import { scoreDataTransferCandidates, resetCandidateCounter } from '../../pipeline/score/data-transfer.js';
import { createDistillationRunner } from '../runner-factory.js';
import { selectConnEvents } from '../select.js';

export const runDataTransferDistillation = createDistillationRunner({
  candidateType: 'data_transfer',
  selectScorerInput: selectConnEvents,
  scoreCandidates: (input) => scoreDataTransferCandidates(input),
  resetCandidateCounter,
});
