// Live trust-list tests. These hit the real C2PA / CAI endpoints, so they are
// opt-in: `C2PA_LIVE_TRUST_TESTS=1 npm test`. The rest of the suite forces trust
// off (fixtures.test.js) and stays hermetic.
//
// They pin the one thing the offline suite cannot: that the five trust inputs
// (conformance anchors + TSA anchors + CAI interim anchors + allow-list + EKU
// config) produce the same `trusted` verdicts as c2paviewer.com.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const LIVE = process.env.C2PA_LIVE_TRUST_TESTS === '1';
const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

let verifyAsset;
async function verify(file) {
  if (!verifyAsset) ({ verifyAsset } = await import('../dist/engine/verify.js'));
  return verifyAsset({ path: join(FIX, file) });
}

test('all five trust inputs load (no partial evaluation)', { skip: !LIVE }, async () => {
  const d = await verify('valid-v3-chain-clean.jpg');
  assert.equal(d.trust.evaluated, true);
  assert.equal(d.trust.partial, false, d.trust.reason);
  assert.equal(d.trust.listSource.split(', ').length, 5);
});

// Fastly's signing cert chains to no anchor; it is trusted only via the CAI
// allow-list of end-entity hashes. Before 0.2.0 this read valid_untrusted.
test('allow-listed signer (Fastly) -> trusted', { skip: !LIVE }, async () => {
  const d = await verify('trusted-allowlist-signer.avif');
  assert.equal(d.verdict, 'trusted', d.summary);
  assert.equal(d.signer.trusted, true);
  assert.ok(!d.issues.some((i) => i.code === 'signingCredential.untrusted'));
});

test('conformance-anchored signer (Google) -> trusted', { skip: !LIVE }, async () => {
  const d = await verify('valid-v3-chain-clean.jpg');
  assert.equal(d.verdict, 'trusted', d.summary);
});
