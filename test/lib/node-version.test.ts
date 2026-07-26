// Unit — the entry-point Node check. `engines` is advisory (npm warns and installs
// anyway), so the CLI checks for itself; this is the predicate it checks with.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { nodeVersionComplaint } from '../../src/lib/node-version.js';

describe('nodeVersionComplaint', () => {
  it('says nothing on a supported runtime', () => {
    assert.equal(nodeVersionComplaint('v22.22.0'), undefined);
    assert.equal(nodeVersionComplaint('22.12.0'), undefined);
    assert.equal(nodeVersionComplaint('v24.0.0'), undefined);
    assert.equal(nodeVersionComplaint(process.versions.node), undefined, 'the test runner qualifies');
  });

  it('names the runtime AND the fix on an old one', () => {
    const complaint = nodeVersionComplaint('v20.18.1');
    assert.match(String(complaint), /needs Node 22 or newer; this is Node v20\.18\.1/);
    assert.match(String(complaint), /nvm install 22/, 'the message says what to do about it');
  });

  it('stays quiet on a version string it cannot read', () => {
    // A runtime that reports something unexpected is not a runtime to refuse over.
    assert.equal(nodeVersionComplaint('not-a-version'), undefined);
    assert.equal(nodeVersionComplaint(''), undefined);
  });
});
