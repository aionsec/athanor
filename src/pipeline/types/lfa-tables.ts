export interface LfaTables {
  totalHosts: number;
  destination: Map<string, number>;
  process: Map<string, number>;
  hash: Map<string, number>;
  commandLine: Map<string, number>;
  parentChildPair: Map<string, number>;
  scriptBlockHash: Map<string, number>;
  domain: Map<string, number>;
  userAgent: Map<string, number>;
  ja3: Map<string, number>;
  authPair: Map<string, number>;
}

export type RarityBucket = 'very_rare' | 'rare' | 'uncommon' | 'common' | 'ubiquitous';

export interface FrequencyStats {
  entity: string;
  host_count: number;
  population_host_count: number;
  prevalence: number;
  rarity_score: number;
  rarity_bucket: RarityBucket;
}

function clampUnitInterval(value: number): number {
  return Math.min(1, Math.max(0, value));
}

export function rarityBucket(rarityScore: number): RarityBucket {
  if (rarityScore > 0.95) return 'very_rare';
  if (rarityScore > 0.8) return 'rare';
  if (rarityScore > 0.5) return 'uncommon';
  if (rarityScore > 0.2) return 'common';
  return 'ubiquitous';
}

export function prevalence(table: Map<string, number>, entity: string, totalHosts: number): number {
  if (totalHosts <= 0) return 0;
  const hostCount = table.get(entity) ?? 0;
  return clampUnitInterval(hostCount / totalHosts);
}

export function rarityScore(table: Map<string, number>, entity: string, totalHosts: number): number {
  if (totalHosts <= 0) return 0;
  return 1 - prevalence(table, entity, totalHosts);
}

export function rarity(table: Map<string, number>, entity: string, totalHosts: number): number {
  return rarityScore(table, entity, totalHosts);
}

export function frequencyStats(
  table: Map<string, number>,
  entity: string,
  totalHosts: number,
): FrequencyStats | undefined {
  if (totalHosts <= 0) return undefined;

  const hostCount = table.get(entity);
  if (hostCount === undefined || hostCount <= 0) return undefined;

  const entityPrevalence = clampUnitInterval(hostCount / totalHosts);
  const entityRarityScore = 1 - entityPrevalence;

  return {
    entity,
    host_count: hostCount,
    population_host_count: totalHosts,
    prevalence: entityPrevalence,
    rarity_score: entityRarityScore,
    rarity_bucket: rarityBucket(entityRarityScore),
  };
}

export function createEmptyLfaTables(totalHosts = 0): LfaTables {
  return {
    totalHosts,
    destination: new Map(),
    process: new Map(),
    hash: new Map(),
    commandLine: new Map(),
    parentChildPair: new Map(),
    scriptBlockHash: new Map(),
    domain: new Map(),
    userAgent: new Map(),
    ja3: new Map(),
    authPair: new Map(),
  };
}
