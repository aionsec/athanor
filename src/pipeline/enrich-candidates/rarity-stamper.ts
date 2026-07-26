import type { CandidateEnrichment } from '../../schema/candidates.js';
import type { FrequencyStats, LfaTables } from '../types/lfa-tables.js';
import { frequencyStats } from '../types/lfa-tables.js';
import type { EnrichmentLabel } from './applicability.js';

export interface RarityContext {
  processNames: string[];
  hashValues: string[];
  commandLineValues: string[];
  parentChildPairValues: string[];
  scriptBlockValues: string[];
  domains: string[];
  userAgents: string[];
  ja3Hashes: string[];
}

function firstNonEmpty(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function chooseMostRareFrequency(
  table: Map<string, number>,
  entities: string[],
  totalHosts: number,
): FrequencyStats | undefined {
  if (entities.length === 0 || totalHosts <= 0) return undefined;

  const values = entities
    .map((entity) => frequencyStats(table, entity, totalHosts))
    .filter((value): value is FrequencyStats => value !== undefined);

  if (values.length === 0) return undefined;
  return values.reduce((mostRare, current) => (
    current.rarity_score > mostRare.rarity_score ? current : mostRare
  ));
}

function hasEitherLabel(
  applicableLabels: ReadonlySet<EnrichmentLabel>,
  rarityLabel: EnrichmentLabel,
  frequencyLabel: EnrichmentLabel,
): boolean {
  return applicableLabels.has(rarityLabel) || applicableLabels.has(frequencyLabel);
}

function stampFrequency(
  enrichment: CandidateEnrichment,
  frequencyLabel: keyof CandidateEnrichment,
  rarityLabel: keyof CandidateEnrichment,
  stats: FrequencyStats | undefined,
): void {
  if (!stats) return;
  const target = enrichment as Record<string, unknown>;
  target[frequencyLabel] = stats;
  target[rarityLabel] = stats.rarity_score;
}

export function stampRarity(
  enrichment: CandidateEnrichment,
  candidate: Record<string, unknown>,
  lfaTables: LfaTables,
  context: RarityContext,
  applicableLabels: ReadonlySet<EnrichmentLabel>,
): void {
  if (lfaTables.totalHosts <= 0) return;

  const destination = hasEitherLabel(applicableLabels, 'destination_rarity', 'destination_frequency')
    ? firstNonEmpty(candidate.dest_ip)
    : null;
  if (destination) {
    stampFrequency(
      enrichment,
      'destination_frequency',
      'destination_rarity',
      frequencyStats(lfaTables.destination, destination, lfaTables.totalHosts),
    );
  }

  const processFrequency = hasEitherLabel(applicableLabels, 'process_rarity', 'process_frequency')
    ? chooseMostRareFrequency(lfaTables.process, context.processNames, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'process_frequency', 'process_rarity', processFrequency);

  const hashFrequency = hasEitherLabel(applicableLabels, 'hash_rarity', 'hash_frequency')
    ? chooseMostRareFrequency(lfaTables.hash, context.hashValues, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'hash_frequency', 'hash_rarity', hashFrequency);

  const commandLineFrequency = hasEitherLabel(applicableLabels, 'command_line_rarity', 'command_line_frequency')
    ? chooseMostRareFrequency(lfaTables.commandLine, context.commandLineValues, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'command_line_frequency', 'command_line_rarity', commandLineFrequency);

  const parentChildPairFrequency = hasEitherLabel(
    applicableLabels,
    'parent_child_pair_rarity',
    'parent_child_pair_frequency',
  )
    ? chooseMostRareFrequency(lfaTables.parentChildPair, context.parentChildPairValues, lfaTables.totalHosts)
    : undefined;
  stampFrequency(
    enrichment,
    'parent_child_pair_frequency',
    'parent_child_pair_rarity',
    parentChildPairFrequency,
  );

  const scriptBlockFrequency = hasEitherLabel(
    applicableLabels,
    'script_block_hash_rarity',
    'script_block_hash_frequency',
  )
    ? chooseMostRareFrequency(lfaTables.scriptBlockHash, context.scriptBlockValues, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'script_block_hash_frequency', 'script_block_hash_rarity', scriptBlockFrequency);

  const domainFrequency = hasEitherLabel(applicableLabels, 'domain_rarity', 'domain_frequency')
    ? chooseMostRareFrequency(lfaTables.domain, context.domains, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'domain_frequency', 'domain_rarity', domainFrequency);

  const userAgentFrequency = hasEitherLabel(applicableLabels, 'user_agent_rarity', 'user_agent_frequency')
    ? chooseMostRareFrequency(lfaTables.userAgent, context.userAgents, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'user_agent_frequency', 'user_agent_rarity', userAgentFrequency);

  const ja3Frequency = hasEitherLabel(applicableLabels, 'ja3_rarity', 'ja3_frequency')
    ? chooseMostRareFrequency(lfaTables.ja3, context.ja3Hashes, lfaTables.totalHosts)
    : undefined;
  stampFrequency(enrichment, 'ja3_frequency', 'ja3_rarity', ja3Frequency);
}
