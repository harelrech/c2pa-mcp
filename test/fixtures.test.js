// End-to-end fixture verification, as a 1:1 table (one fixture -> one verdict).
//
// Trust is forced OFF here (an unreachable trust URL + zero TTL) so every fixture
// resolves to a single deterministic verdict with no network dependency and no
// branching. The trusted-vs-untrusted distinction, which requires a live trust
// list, is covered deterministically by the unit table in verdict.test.js.
//
// node --test isolates each file in its own process, so these env vars only apply
// here and must be set before the engine module is imported (it reads them at load).
process.env.C2PA_TRUST_LIST_URL = 'https://127.0.0.1/unreachable.pem';
process.env.C2PA_TRUST_TTL_SECONDS = '0';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

let verifyAsset;
async function verify(file, includeRaw) {
  if (!verifyAsset) ({ verifyAsset } = await import('../dist/engine/verify.js'));
  return verifyAsset({ path: join(FIX, file) }, includeRaw);
}

// fixture -> exactly one verdict (trust-unavailable regime)
const CASES = [
  { file: 'no-credentials.jpg', verdict: 'no_credentials' },
  { file: 'valid-untrusted.jpg', verdict: 'valid_trust_unknown' },
  { file: 'valid-deep-chain.jpg', verdict: 'valid_trust_unknown' },
  { file: 'invalid-signature.jpg', verdict: 'invalid' },
  { file: 'invalid-datahash.jpg', verdict: 'invalid' },
];
for (const { file, verdict } of CASES) {
  test(`${file} -> ${verdict}`, async () => {
    const d = await verify(file);
    assert.equal(d.verdict, verdict);
  });
}

// fixture -> the specific validation code it must surface (1:1)
const CODE_CASES = [
  { file: 'invalid-signature.jpg', code: 'claimSignature.mismatch' },
  { file: 'invalid-datahash.jpg', code: 'assertion.dataHash.mismatch' },
];
for (const { file, code } of CODE_CASES) {
  test(`${file} reports ${code} (explained)`, async () => {
    const d = await verify(file);
    assert.ok(d.issues.some((i) => i.code === code), `expected ${code}`);
    assert.ok(d.issues.every((i) => i.explanation && i.explanation.length > 0));
  });
}

test('valid-deep-chain.jpg builds a multi-node provenance lineage rooted at the file', async () => {
  const d = await verify('valid-deep-chain.jpg');
  assert.ok(d.provenance.length > 2, `got ${d.provenance.length}`);
  assert.equal(d.provenance[0].depth, 0);
  assert.equal(d.provenance[0].relationship, 'This file');
});

test('trust degrades loudly to not-evaluated when the list is unreachable', async () => {
  const d = await verify('valid-untrusted.jpg');
  assert.equal(d.trust.evaluated, false);
  assert.ok(d.trust.reason && d.trust.reason.length > 0);
});

test('includeRaw=true attaches the raw manifest store', async () => {
  const d = await verify('valid-untrusted.jpg', true);
  assert.ok(d.raw);
});
