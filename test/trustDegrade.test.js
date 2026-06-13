// Verifies the "degrade loudly" trust behavior: when the trust list cannot be
// loaded, verification still runs but reports that trust was not evaluated.
//
// node --test runs each test file in its own process, so setting these env vars
// here only affects this file. They must be set before the dynamic import of the
// engine, because trust.ts reads them at module-load time. TTL=0 forces a fetch
// (bypassing any cache); the private-host URL makes that fetch fail safely.
process.env.C2PA_TRUST_LIST_URL = 'https://127.0.0.1/trust.pem';
process.env.C2PA_TRUST_TTL_SECONDS = '0';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

test('degrades loudly when the trust list cannot be loaded', async () => {
  const { verifyAsset } = await import('../dist/engine/verify.js');
  const d = await verifyAsset({ path: join(FIX, 'valid-untrusted.jpg') });
  assert.equal(d.trust.evaluated, false);
  assert.ok(d.trust.reason && d.trust.reason.length > 0, 'should explain why trust was not evaluated');
  // A cryptographically valid file with trust unevaluated is "valid_trust_unknown",
  // never silently "trusted" and never wrongly "invalid".
  assert.equal(d.verdict, 'valid_trust_unknown');
});
