import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyCommandLine,
  classifyCustomHost,
  classifyParent,
  classifyRename,
  type HostAllowlistEntry,
  type ParentTaxonomyEntry,
} from '../../src/pipeline/score/powershell-invocation-anomaly-classifiers.js';
import { shannonEntropy } from '../../src/utils/entropy.js';

function hostAllowlist(entries: HostAllowlistEntry[]): Map<string, HostAllowlistEntry[]> {
  const out = new Map<string, HostAllowlistEntry[]>();
  for (const entry of entries) {
    const key = entry.process_name.toLowerCase();
    const bucket = out.get(key) ?? [];
    bucket.push(entry);
    out.set(key, bucket);
  }
  return out;
}

describe('PowerShell Invocation classifiers: rename', () => {
  it('Stage 1 scores 1.0 for renamed PowerShell binary by OriginalFileName', () => {
    const result = classifyRename('updater.exe', 'PowerShell.EXE', null, null);
    assert.equal(result.score, 1.0);
    assert.equal(result.force_host_category, 'renamed');
    assert.equal(result.data_quality_flag, null);
  });

  it('Stage 2 fallback scores 0.95 when OriginalFileName is unavailable', () => {
    const result = classifyRename('dropper.exe', '-', 'Windows PowerShell Host', 'Microsoft Corporation');
    assert.equal(result.score, 0.95);
    assert.equal(result.force_host_category, 'renamed');
  });

  it('Stage 3 marks rename_uncheckable when VERSIONINFO is absent', () => {
    const result = classifyRename('dropper.exe', null, null, null);
    assert.equal(result.score, 0.0);
    assert.equal(result.data_quality_flag, 'rename_uncheckable');
  });
});

describe('PowerShell Invocation classifiers: custom host', () => {
  const allowlist = hostAllowlist([
    { process_name: 'dsac.exe', tier: 'ms_alternate', category: 'ad_management' },
    {
      process_name: 'gc_worker.exe',
      tier: 'vendor_alternate',
      category: 'azure_arc',
      path_prefix: 'c:\\program files\\azureconnectedmachineagent\\',
    },
    { process_name: 'rundll32.exe', tier: 'lolbin', category: 'lolbin' },
  ]);

  it('canonical host loading SMA scores 0.0', () => {
    const result = classifyCustomHost('powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', allowlist, true, null);
    assert.equal(result.score, 0.0);
    assert.equal(result.host_category, 'canonical');
  });

  it('ms_alternate host loading SMA scores 0.1', () => {
    const result = classifyCustomHost('dsac.exe', 'C:\\Windows\\System32\\dsac.exe', allowlist, true, null);
    assert.equal(result.score, 0.1);
    assert.equal(result.host_category, 'ms_alternate');
  });

  it('vendor_alternate host with path match scores 0.2', () => {
    const result = classifyCustomHost('gc_worker.exe', 'C:\\Program Files\\AzureConnectedMachineAgent\\1.2.3\\gc_worker.exe', allowlist, true, null);
    assert.equal(result.score, 0.2);
    assert.equal(result.host_category, 'vendor_alternate');
  });

  it('lolbin host loading SMA scores 0.95', () => {
    const result = classifyCustomHost('rundll32.exe', 'C:\\Windows\\System32\\rundll32.exe', allowlist, true, null);
    assert.equal(result.score, 0.95);
    assert.equal(result.host_category, 'lolbin');
  });

  it('unknown host loading SMA scores 0.95', () => {
    const result = classifyCustomHost('mystery.exe', 'C:\\Users\\Public\\mystery.exe', allowlist, true, null);
    assert.equal(result.score, 0.95);
    assert.equal(result.host_category, 'unknown');
  });

  it('renamed override keeps host category renamed and score 0', () => {
    const result = classifyCustomHost('updater.exe', 'C:\\Users\\Public\\updater.exe', allowlist, true, 'renamed');
    assert.equal(result.score, 0.0);
    assert.equal(result.host_category, 'renamed');
  });
});

describe('PowerShell Invocation classifiers: parent', () => {
  const taxonomy = new Map<string, ParentTaxonomyEntry>([
    ['winword.exe', { parent_basename: 'winword.exe', category: 'office', score: 0.95 }],
    ['wscript.exe', { parent_basename: 'wscript.exe', category: 'script_host', score: 0.85 }],
  ]);

  it('returns parent_uncheckable when parent context is missing', () => {
    const result = classifyParent(null, null, '', taxonomy);
    assert.equal(result.score, 0.0);
    assert.equal(result.parent_category, 'unknown');
    assert.equal(result.data_quality_flag, 'parent_uncheckable');
  });

  it('uses taxonomy score when present', () => {
    const result = classifyParent('WINWORD.EXE', '', '', taxonomy);
    assert.equal(result.score, 0.95);
    assert.equal(result.parent_category, 'office');
  });

  it('downgrades wmiprvse CCM/WinRM contexts to 0', () => {
    const result = classifyParent('WmiPrvSE.exe', 'C:\\Windows\\CCM\\WmiPrvSE.exe', 'powershell.exe -Command winrm enumerate', taxonomy);
    assert.equal(result.score, 0.0);
    assert.equal(result.parent_category, 'service_host');
  });

  it('scores wmiprvse non-CCM context at 0.5', () => {
    const result = classifyParent('WmiPrvSE.exe', 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', 'powershell.exe -enc SQBFAFgA', taxonomy);
    assert.equal(result.score, 0.5);
    assert.equal(result.parent_category, 'service_host');
  });
});

describe('PowerShell Invocation classifiers: command line tiers', () => {
  it('Tier 1 offensive fingerprint scores 1.0', () => {
    const result = classifyCommandLine('powershell.exe -NoProfile -sta -w hidden -enc SQBFAFgA');
    assert.equal(result.score, 1.0);
    assert.equal(result.cmdline_classification, 'tier_1_offensive_fingerprint');
  });

  it('Tier 1 downgrade (-Version 2) scores 1.0', () => {
    const result = classifyCommandLine('powershell.exe -Version 2 -Command whoami');
    assert.equal(result.score, 1.0);
    assert.equal(result.cmdline_classification, 'tier_1_offensive_fingerprint');
  });

  it('Tier 2 combination scores 0.90', () => {
    const result = classifyCommandLine('powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive');
    assert.equal(result.score, 0.9);
    assert.equal(result.cmdline_classification, 'tier_2_combination');
  });

  it('Tier 3 encoded with another suspicious flag scores 0.75', () => {
    const result = classifyCommandLine('powershell.exe -enc SQBFAFgA -NoProfile');
    assert.equal(result.score, 0.75);
    assert.equal(result.cmdline_classification, 'tier_3_encoded_with_other');
  });

  it('Tier 4 hidden window + noninteractive scores 0.60', () => {
    const result = classifyCommandLine('powershell.exe -WindowStyle Hidden -NonInteractive');
    assert.equal(result.score, 0.6);
    assert.equal(result.cmdline_classification, 'tier_4_partial_shape');
  });

  it('Tier 5 encoded alone scores 0.40', () => {
    const result = classifyCommandLine('powershell.exe -EncodedCommand SQBFAFgA');
    assert.equal(result.score, 0.4);
    assert.equal(result.cmdline_classification, 'tier_5_encoded_alone');
  });

  it('single-flag invocations score 0 (benign)', () => {
    assert.equal(classifyCommandLine('powershell.exe -ExecutionPolicy Bypass').score, 0.0);
    assert.equal(classifyCommandLine('powershell.exe -WindowStyle Hidden').score, 0.0);
    assert.equal(classifyCommandLine('powershell.exe -NoProfile').score, 0.0);
  });
});

describe('classifyCommandLine: encoded-command entropy', () => {
  it('returns the Shannon entropy of the EncodedCommand value', () => {
    const encoded = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const result = classifyCommandLine(`powershell.exe -NoProfile -EncodedCommand ${encoded}`);
    assert.notEqual(result.encoded_command_entropy, null);
    assert.equal(result.encoded_command_entropy, shannonEntropy(encoded));
  });

  it('returns null entropy when no encoded command is present', () => {
    const result = classifyCommandLine('powershell.exe -NoProfile -Command Get-Process');
    assert.equal(result.encoded_command_entropy, null);
  });
});

