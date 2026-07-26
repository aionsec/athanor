import type {
  PowerShellInvocationCmdlineClassification,
  PowerShellInvocationDataQualityFlag,
  PowerShellInvocationDominantDimension,
  PowerShellInvocationHostCategory,
  PowerShellInvocationParentCategory,
} from '../../schema/candidates.js';
import {
  getParameterValues,
  hasCanonicalFlag,
  tokenizePowerShellCommandLine,
} from './powershell-cmdline-tokenizer.js';
import { shannonEntropy } from '../../utils/entropy.js';

export interface HostAllowlistEntry {
  process_name: string;
  tier: 'canonical' | 'ms_alternate' | 'vendor_alternate' | 'lolbin';
  category: string;
  path_prefix?: string;
}

export interface ParentTaxonomyEntry {
  parent_basename: string;
  category: PowerShellInvocationParentCategory;
  score: number;
}

export interface RenameClassificationResult {
  score: number;
  force_host_category: PowerShellInvocationHostCategory | null;
  data_quality_flag: PowerShellInvocationDataQualityFlag | null;
}

export interface CustomHostClassificationResult {
  score: number;
  host_category: PowerShellInvocationHostCategory;
}

export interface ParentClassificationResult {
  score: number;
  parent_category: PowerShellInvocationParentCategory;
  data_quality_flag: PowerShellInvocationDataQualityFlag | null;
}

export interface CmdlineClassificationResult {
  score: number;
  cmdline_classification: PowerShellInvocationCmdlineClassification;
  cmdline_flags_detected: string[];
  encoded_command_entropy: number | null;
}

const CANONICAL_ORIGINAL_FILE_NAMES = new Set([
  'powershell.exe',
  'pwsh.dll',
  'powershell_ise.exe',
]);

const CANONICAL_HOST_PROCESSES = new Set([
  'powershell.exe',
  'powershell_ise.exe',
  'pwsh.exe',
  'wsmprovhost.exe',
  'winrshost.exe',
]);

export function normalizePath(value: string | null | undefined): string {
  return (value ?? '').trim().replace(/\//g, '\\').toLowerCase();
}

export function basenameFromPath(value: string | null | undefined): string {
  const normalized = normalizePath(value);
  if (normalized.length === 0) return '';
  const parts = normalized.split('\\').filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : normalized;
}

function isMissingVersionInfo(value: string | null | undefined): boolean {
  const normalized = (value ?? '').trim().toLowerCase();
  return normalized.length === 0 || normalized === '-' || normalized === 'unknown';
}

function normalizedStartsWith(value: string | null | undefined, prefix: string): boolean {
  return (value ?? '').trim().toLowerCase().startsWith(prefix.toLowerCase());
}

function normalizeCategoryScore(category: PowerShellInvocationHostCategory): number {
  switch (category) {
    case 'canonical':
      return 0.0;
    case 'ms_alternate':
      return 0.10;
    case 'vendor_alternate':
      return 0.20;
    case 'lolbin':
      return 0.95;
    case 'unknown':
      return 0.95;
    case 'renamed':
      return 0.0;
    default:
      return 0.95;
  }
}

export function classifyRename(
  processName: string | null | undefined,
  originalFileName: string | null | undefined,
  description: string | null | undefined,
  company: string | null | undefined,
): RenameClassificationResult {
  const processBasename = basenameFromPath(processName);
  const canonicalHost = CANONICAL_HOST_PROCESSES.has(processBasename);
  const originalNormalized = (originalFileName ?? '').trim().toLowerCase();

  if (!canonicalHost && CANONICAL_ORIGINAL_FILE_NAMES.has(originalNormalized)) {
    return {
      score: 1.0,
      force_host_category: 'renamed',
      data_quality_flag: null,
    };
  }

  const missingOriginal = isMissingVersionInfo(originalFileName);
  const fallbackDescriptionMatch = normalizedStartsWith(description, 'windows powershell')
    || normalizedStartsWith(description, 'pwsh');
  const fallbackCompanyMatch = (company ?? '').trim().toLowerCase() === 'microsoft corporation';
  if (!canonicalHost && missingOriginal && fallbackDescriptionMatch && fallbackCompanyMatch) {
    return {
      score: 0.95,
      force_host_category: 'renamed',
      data_quality_flag: null,
    };
  }

  if (missingOriginal && !(fallbackDescriptionMatch && fallbackCompanyMatch)) {
    return {
      score: 0.0,
      force_host_category: null,
      data_quality_flag: 'rename_uncheckable',
    };
  }

  return {
    score: 0.0,
    force_host_category: null,
    data_quality_flag: null,
  };
}

export function classifyHostCategory(
  processName: string | null | undefined,
  processPath: string | null | undefined,
  hostAllowlist: Map<string, HostAllowlistEntry[]>,
): PowerShellInvocationHostCategory {
  const normalizedPath = normalizePath(processPath);
  const processBasename = basenameFromPath(processName) || basenameFromPath(processPath);
  if (processBasename.length === 0) return 'unknown';
  if (CANONICAL_HOST_PROCESSES.has(processBasename)) return 'canonical';

  const entries = hostAllowlist.get(processBasename) ?? [];
  for (const entry of entries) {
    const prefix = normalizePath(entry.path_prefix ?? '');
    if (prefix.length > 0 && !normalizedPath.startsWith(prefix)) continue;
    return entry.tier;
  }

  return 'unknown';
}

export function classifyCustomHost(
  processName: string | null | undefined,
  processPath: string | null | undefined,
  hostAllowlist: Map<string, HostAllowlistEntry[]>,
  smaDllLoaded: boolean,
  forcedHostCategory: PowerShellInvocationHostCategory | null,
): CustomHostClassificationResult {
  if (forcedHostCategory === 'renamed') {
    return {
      score: 0.0,
      host_category: 'renamed',
    };
  }

  const hostCategory = classifyHostCategory(processName, processPath, hostAllowlist);
  if (!smaDllLoaded) {
    return {
      score: 0.0,
      host_category: hostCategory,
    };
  }

  return {
    score: normalizeCategoryScore(hostCategory),
    host_category: hostCategory,
  };
}

export function classifyParent(
  parentProcessName: string | null | undefined,
  parentProcessPath: string | null | undefined,
  commandLine: string | null | undefined,
  parentTaxonomy: Map<string, ParentTaxonomyEntry>,
): ParentClassificationResult {
  const parentBasename = basenameFromPath(parentProcessName) || basenameFromPath(parentProcessPath);
  if (parentBasename.length === 0) {
    return {
      score: 0.0,
      parent_category: 'unknown',
      data_quality_flag: 'parent_uncheckable',
    };
  }

  if (parentBasename === 'services.exe') {
    return {
      score: 0.50,
      parent_category: 'service_host',
      data_quality_flag: null,
    };
  }

  if (parentBasename === 'wmiprvse.exe') {
    const parentPath = normalizePath(parentProcessPath);
    const cmdLower = normalizePath(commandLine);
    const lowRisk = parentPath.includes('\\windows\\ccm\\')
      || cmdLower.includes('appvclient')
      || cmdLower.includes('winrm');
    return {
      score: lowRisk ? 0.0 : 0.50,
      parent_category: 'service_host',
      data_quality_flag: null,
    };
  }

  const taxonomyEntry = parentTaxonomy.get(parentBasename);
  if (taxonomyEntry) {
    return {
      score: taxonomyEntry.score,
      parent_category: taxonomyEntry.category,
      data_quality_flag: null,
    };
  }

  return {
    score: 0.30,
    parent_category: 'unknown',
    data_quality_flag: null,
  };
}

function isWindowStyleHidden(values: string[]): boolean {
  return values.some((value) => {
    const normalized = value.trim().toLowerCase();
    return normalized === 'hidden' || normalized === '1';
  });
}

function isExecutionPolicyBypass(values: string[]): boolean {
  return values.some((value) => value.trim().toLowerCase() === 'bypass');
}

function hasVersion2(values: string[]): boolean {
  return values.some((value) => value.trim().toLowerCase().startsWith('2'));
}

export function classifyCommandLine(commandLine: string | null | undefined): CmdlineClassificationResult {
  const tokenized = tokenizePowerShellCommandLine(commandLine ?? '');
  const encodedValues = getParameterValues(tokenized, 'EncodedCommand');
  const encoded_command_entropy = encodedValues.length > 0 ? shannonEntropy(encodedValues.join('')) : null;
  const windowStyleValues = getParameterValues(tokenized, 'WindowStyle');
  const executionPolicyValues = getParameterValues(tokenized, 'ExecutionPolicy');
  const versionValues = getParameterValues(tokenized, 'Version');

  const hasNoProfile = hasCanonicalFlag(tokenized, 'NoProfile');
  const hasSta = hasCanonicalFlag(tokenized, 'STA');
  const hasNonInteractive = hasCanonicalFlag(tokenized, 'NonInteractive');
  const hasEncoded = hasCanonicalFlag(tokenized, 'EncodedCommand');
  const hasHiddenWindow = isWindowStyleHidden(windowStyleValues);
  const hasEpBypass = isExecutionPolicyBypass(executionPolicyValues);
  const downgradeV2 = hasVersion2(versionValues);
  const encodedLongEnough = encodedValues.some((value) => value.trim().length >= 5);

  const suspiciousFlags = [
    hasNoProfile,
    hasHiddenWindow,
    hasNonInteractive,
    hasEpBypass,
    hasEncoded,
    hasSta,
  ];
  const suspiciousCount = suspiciousFlags.filter(Boolean).length;

  const tier1Fingerprint = hasEncoded && hasNoProfile && hasSta && hasHiddenWindow;
  if (tier1Fingerprint || downgradeV2) {
    return {
      score: 1.0,
      cmdline_classification: 'tier_1_offensive_fingerprint',
      cmdline_flags_detected: tokenized.canonical_flags,
      encoded_command_entropy,
    };
  }

  if (suspiciousCount >= 3) {
    return {
      score: 0.90,
      cmdline_classification: 'tier_2_combination',
      cmdline_flags_detected: tokenized.canonical_flags,
      encoded_command_entropy,
    };
  }

  if (hasEncoded && encodedLongEnough && (hasNoProfile || hasHiddenWindow || hasNonInteractive || hasEpBypass)) {
    return {
      score: 0.75,
      cmdline_classification: 'tier_3_encoded_with_other',
      cmdline_flags_detected: tokenized.canonical_flags,
      encoded_command_entropy,
    };
  }

  if (hasHiddenWindow && (hasEncoded || hasNonInteractive)) {
    return {
      score: 0.60,
      cmdline_classification: 'tier_4_partial_shape',
      cmdline_flags_detected: tokenized.canonical_flags,
      encoded_command_entropy,
    };
  }

  if (hasEncoded && encodedLongEnough && suspiciousCount === 1) {
    return {
      score: 0.40,
      cmdline_classification: 'tier_5_encoded_alone',
      cmdline_flags_detected: tokenized.canonical_flags,
      encoded_command_entropy,
    };
  }

  return {
    score: 0.0,
    cmdline_classification: 'benign',
    cmdline_flags_detected: tokenized.canonical_flags,
    encoded_command_entropy,
  };
}

export function dominantDimension(
  renameSuspicion: number,
  customHostSuspicion: number,
  parentSuspicion: number,
  commandlineSuspicion: number,
): PowerShellInvocationDominantDimension {
  const composite = Math.max(renameSuspicion, customHostSuspicion, parentSuspicion, commandlineSuspicion);
  if (composite <= 0) return 'none';
  if (renameSuspicion === composite) return 'rename';
  if (customHostSuspicion === composite) return 'custom_host';
  if (parentSuspicion === composite) return 'parent';
  return 'commandline';
}
