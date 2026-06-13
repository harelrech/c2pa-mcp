// Verdict mapping, as explicit 1:1 tables. Each row pins one set of inputs to one
// expected outcome. Deterministic and offline (no engine, no network).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveVerdict, verdictToNodeVerdict } from '../dist/digest/verdict.js';

// (engine validation_state, trust evaluated?) -> verdict
const VERDICT_CASES = [
  { state: 'Invalid', trust: true, verdict: 'invalid' },
  { state: 'Invalid', trust: false, verdict: 'invalid' },
  { state: 'Trusted', trust: true, verdict: 'trusted' },
  { state: 'Trusted', trust: false, verdict: 'valid_trust_unknown' },
  { state: 'Valid', trust: true, verdict: 'valid_untrusted' },
  { state: 'Valid', trust: false, verdict: 'valid_trust_unknown' },
];
for (const { state, trust, verdict } of VERDICT_CASES) {
  test(`validation_state=${state} trustEvaluated=${trust} -> ${verdict}`, () => {
    assert.equal(deriveVerdict({ validation_state: state }, trust), verdict);
  });
}

// No validation_state: the engine's own failure bucket is authoritative.
test('no validation_state + a failure-bucket entry -> invalid', () => {
  const store = {
    validation_results: { activeManifest: { failure: [{ code: 'x.unknownFuture' }], informational: [], success: [] } },
  };
  assert.equal(deriveVerdict(store, true), 'invalid');
});

// No validation_state and nothing failed -> conservative valid, keyed on trust.
const FALLBACK_CASES = [
  { trust: true, verdict: 'valid_untrusted' },
  { trust: false, verdict: 'valid_trust_unknown' },
];
for (const { trust, verdict } of FALLBACK_CASES) {
  test(`no validation_state, no failures, trustEvaluated=${trust} -> ${verdict}`, () => {
    assert.equal(deriveVerdict({}, trust), verdict);
  });
}

// root verdict -> per-node verdict
const NODE_CASES = [
  ['trusted', 'trusted'],
  ['valid_untrusted', 'valid'],
  ['valid_trust_unknown', 'valid'],
  ['invalid', 'invalid'],
  ['no_credentials', 'unknown'],
  ['error', 'unknown'],
];
for (const [verdict, node] of NODE_CASES) {
  test(`verdictToNodeVerdict(${verdict}) -> ${node}`, () => {
    assert.equal(verdictToNodeVerdict(verdict), node);
  });
}
