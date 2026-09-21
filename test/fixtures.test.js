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

// ── Provenance-chain fixtures (C2PA 2.2 §15.11) ──────────────────────────────
//
// A failing ingredient must be REPORTED but must never repaint the file's own
// verdict or its `issues`. These assertions are trust-independent: they check
// chain codes, node verdicts and error-severity only, never warnings (an
// ingredient off the live trust list is a legitimate warning).

const nonRoot = (d) => d.provenance.filter((n) => n.depth > 0);
const chainCodes = (d) => d.ingredientIssues.flatMap((i) => i.codes.map((c) => c.code));

test('valid-resigned-broken-chain-v1.jpg: broken ingredient reported on its own channel', async () => {
  const d = await verify('valid-resigned-broken-chain-v1.jpg');
  assert.notEqual(d.verdict, 'invalid');
  assert.ok(!d.issues.some((i) => i.severity === 'error'), `file-level errors: ${d.issues.map((i) => i.code)}`);
  const broken = d.ingredientIssues.find((i) => i.codes.some((c) => c.code === 'claimSignature.mismatch'));
  assert.ok(broken, 'claimSignature.mismatch missing from ingredientIssues');
  assert.equal(broken.worstSeverity, 'error');
  assert.equal(broken.ingredientTitle, 'E-sig-CA.jpg');
  const invalidNodes = nonRoot(d).filter((n) => n.verdict === 'invalid');
  assert.equal(invalidNodes.length, 1);
  assert.ok(invalidNodes[0].issues.some((c) => c.code === 'claimSignature.mismatch'));
  assert.match(d.summary, /earlier version in its provenance chain failed/);
});

for (const file of ['valid-v3-chain-clean.jpg', 'valid-untrusted-info-only-ingredient.jpg']) {
  test(`${file}: clean chain has no chain errors and no invalid node`, async () => {
    const d = await verify(file);
    const errs = d.ingredientIssues.flatMap((i) => i.codes).filter((c) => c.severity === 'error');
    assert.deepEqual(errs.map((c) => c.code), []);
    assert.deepEqual(nonRoot(d).filter((n) => n.verdict === 'invalid').map((n) => n.title), []);
    assert.doesNotMatch(d.summary, /provenance chain failed/);
  });
}

// Unconditional invariant, every fixture: an info-severity code is a PASSING
// check (e.g. signingCredential.ocsp.notRevoked) and must never be presented
// as a chain issue or a node issue.
const ALL_FIXTURES = [
  ...CASES.map((c) => c.file),
  'valid-resigned-broken-chain-v1.jpg',
  'valid-v3-chain-clean.jpg',
  'valid-untrusted-info-only-ingredient.jpg',
];
for (const file of ALL_FIXTURES) {
  test(`${file}: no info-severity code leaks into chain or node issues`, async () => {
    const d = await verify(file);
    const leaked = [
      ...d.ingredientIssues.flatMap((i) => i.codes),
      ...d.provenance.flatMap((n) => n.issues),
    ].filter((c) => c.severity === 'info');
    assert.deepEqual(leaked.map((c) => c.code), []);
    assert.ok(d.provenance.every((n) => Array.isArray(n.issues)));
    assert.deepEqual(d.provenance[0]?.issues ?? [], []);
  });
}
