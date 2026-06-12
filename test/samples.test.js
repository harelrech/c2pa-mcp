// End-to-end digest verification against known C2PA test files.
// Run after `npm run build` (the suite imports the compiled output in dist/).
// Requires network access on first run to fetch the trust list.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyAsset } from '../dist/engine/verify.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

test('no C2PA data -> no_credentials', async () => {
  const d = await verifyAsset({ path: join(FIX, 'no-credentials.jpg') });
  assert.equal(d.verdict, 'no_credentials');
  assert.equal(d.signer, null);
  assert.equal(d.provenance.length, 0);
});

test('valid but untrusted signer -> valid_untrusted', async () => {
  const d = await verifyAsset({ path: join(FIX, 'valid-untrusted.jpg') });
  // With the live trust list loaded the test cert is either untrusted or, if it
  // ever lands on the list, trusted. It must never be invalid.
  assert.ok(['valid_untrusted', 'trusted', 'valid_trust_unknown'].includes(d.verdict), `got ${d.verdict}`);
  assert.notEqual(d.verdict, 'invalid');
  assert.ok(d.signer, 'a signer should be present');
  assert.ok(d.provenance.length >= 1);
});

test('deep provenance chain builds multiple lineage nodes', async () => {
  const d = await verifyAsset({ path: join(FIX, 'valid-deep-chain.jpg') });
  assert.notEqual(d.verdict, 'invalid');
  assert.ok(d.provenance.length > 2, `expected a multi-node chain, got ${d.provenance.length}`);
  assert.equal(d.provenance[0].depth, 0);
  assert.equal(d.provenance[0].relationship, 'This file');
});

test('tampered signature -> invalid with claimSignature.mismatch', async () => {
  const d = await verifyAsset({ path: join(FIX, 'invalid-signature.jpg') });
  assert.equal(d.verdict, 'invalid');
  assert.ok(d.issues.some((i) => i.code === 'claimSignature.mismatch'), 'expected claimSignature.mismatch');
  // Every reported issue must carry a plain-language explanation.
  assert.ok(d.issues.every((i) => i.explanation && i.explanation.length > 0));
});

test('tampered content -> invalid with assertion.dataHash.mismatch', async () => {
  const d = await verifyAsset({ path: join(FIX, 'invalid-datahash.jpg') });
  assert.equal(d.verdict, 'invalid');
  assert.ok(d.issues.some((i) => i.code === 'assertion.dataHash.mismatch'), 'expected assertion.dataHash.mismatch');
});

test('includeRaw attaches the raw manifest store', async () => {
  const d = await verifyAsset({ path: join(FIX, 'valid-untrusted.jpg') }, true);
  assert.ok(d.raw, 'raw manifest store should be present when requested');
});
