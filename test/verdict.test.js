// Deterministic unit tests for the verdict mapping. These cover every branch
// (including `trusted`) with synthetic ManifestStore objects, so they need no
// network, no trust list, and no real signed file — and they assert exactly one
// expected outcome per input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveVerdict, verdictToNodeVerdict } from '../dist/digest/verdict.js';

test('deriveVerdict maps the engine validation_state authoritatively', () => {
  assert.equal(deriveVerdict({ validation_state: 'Invalid' }, true), 'invalid');
  assert.equal(deriveVerdict({ validation_state: 'Trusted' }, true), 'trusted');
  assert.equal(deriveVerdict({ validation_state: 'Valid' }, true), 'valid_untrusted');
  assert.equal(deriveVerdict({ validation_state: 'Valid' }, false), 'valid_trust_unknown');
});

test('deriveVerdict trusts the engine failure bucket when validation_state is absent', () => {
  const store = {
    validation_results: {
      activeManifest: {
        // An error the code table does not know about must still read as invalid.
        failure: [{ code: 'some.future.unknownError' }],
        informational: [],
        success: [],
      },
    },
  };
  assert.equal(deriveVerdict(store, true), 'invalid');
});

test('deriveVerdict falls back to valid when nothing failed and no state is given', () => {
  assert.equal(deriveVerdict({}, true), 'valid_untrusted');
  assert.equal(deriveVerdict({}, false), 'valid_trust_unknown');
});

test('verdictToNodeVerdict collapses the root verdict to a node verdict', () => {
  assert.equal(verdictToNodeVerdict('trusted'), 'trusted');
  assert.equal(verdictToNodeVerdict('valid_untrusted'), 'valid');
  assert.equal(verdictToNodeVerdict('valid_trust_unknown'), 'valid');
  assert.equal(verdictToNodeVerdict('invalid'), 'invalid');
  assert.equal(verdictToNodeVerdict('no_credentials'), 'unknown');
  assert.equal(verdictToNodeVerdict('error'), 'unknown');
});
