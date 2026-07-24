// Verifies a fetch that hits our own timeout reports a clear, labeled message
// (mentioning the timeout and the C2PA_FETCH_TIMEOUT_MS env var) rather than
// Node's generic AbortError text. `fetchRemoteAsset` validates the URL string
// synchronously (no DNS), so global fetch can be mocked without real network.
//
// node --test isolates each file in its own process, so the env var only
// applies here and must be set before the module (which reads it at load) is
// imported.
process.env.C2PA_FETCH_TIMEOUT_MS = '50';

import { test } from 'node:test';
import assert from 'node:assert/strict';

const originalFetch = globalThis.fetch;

function neverResolvingFetch(_url, opts) {
  return new Promise((_resolve, reject) => {
    opts.signal.addEventListener('abort', () => {
      const err = new Error('This operation was aborted');
      err.name = 'AbortError';
      reject(err);
    });
  });
}

test('reports our own timeout distinctly, naming the env var', async () => {
  globalThis.fetch = neverResolvingFetch;
  try {
    const { fetchRemoteAsset } = await import('../dist/net/safeFetch.js');
    const result = await fetchRemoteAsset('https://example.com/slow.jpg');
    assert.equal(result.ok, false);
    assert.match(result.detail, /timed out after 50ms/);
    assert.match(result.detail, /C2PA_FETCH_TIMEOUT_MS/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
