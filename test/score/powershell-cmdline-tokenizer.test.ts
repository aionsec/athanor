import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  getParameterValues,
  splitPowerShellCommandLine,
  tokenizePowerShellCommandLine,
} from '../../src/pipeline/score/powershell-cmdline-tokenizer.js';

describe('PowerShell cmdline tokenizer: splitting', () => {
  it('respects quoted payloads', () => {
    const tokens = splitPowerShellCommandLine('powershell.exe -Command "Write-Host \'hello world\'" -NoProfile');
    assert.deepEqual(tokens, ['powershell.exe', '-Command', "Write-Host 'hello world'", '-NoProfile']);
  });

  it('returns empty list for blank command line', () => {
    assert.deepEqual(splitPowerShellCommandLine('   '), []);
  });
});

describe('PowerShell cmdline tokenizer: parameter normalization', () => {
  it('normalizes unicode dashes and slash prefixes', () => {
    const tokenized = tokenizePowerShellCommandLine('powershell.exe –NoProfile /WindowStyle Hidden');
    assert.equal(tokenized.canonical_flags.includes('NoProfile'), true);
    assert.equal(tokenized.canonical_flags.includes('WindowStyle:hidden'), true);
  });

  it('resolves Bohannon-style NoProfile prefixes', () => {
    const variants = ['-NoPr', '-NoPro', '-NoProf', '-NoProfi', '-NoProfil'];
    for (const variant of variants) {
      const tokenized = tokenizePowerShellCommandLine(`powershell.exe ${variant} -Command whoami`);
      assert.equal(tokenized.canonical_flags.includes('NoProfile'), true);
    }
  });

  it('extracts parameter values for execution policy and encoded command', () => {
    const tokenized = tokenizePowerShellCommandLine('powershell.exe -ExecutionPolicy Bypass -Enc SQBFAFgA');
    assert.deepEqual(getParameterValues(tokenized, 'ExecutionPolicy'), ['Bypass']);
    assert.deepEqual(getParameterValues(tokenized, 'EncodedCommand'), ['SQBFAFgA']);
  });

  it('supports short aliases -w, -e, and -v', () => {
    const tokenized = tokenizePowerShellCommandLine('powershell.exe -w 1 -e AAAA -v 2');
    assert.equal(tokenized.canonical_flags.includes('WindowStyle:1'), true);
    assert.equal(tokenized.canonical_flags.includes('EncodedCommand'), true);
    assert.equal(tokenized.canonical_flags.includes('Version:2'), true);
  });
});

