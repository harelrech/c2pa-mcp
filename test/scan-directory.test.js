// scan_c2pa_directory must explain every skip with a per-file `reason`, not just
// drop it silently or hide it behind an aggregate count.
//
// node --test isolates each file in its own process, so these env vars only
// apply here and must be set before the tools/engine modules (which read them
// at load) are imported.
process.env.C2PA_TRUST_LIST_URL = 'https://127.0.0.1/unreachable.pem';
process.env.C2PA_TRUST_TTL_SECONDS = '0';
process.env.C2PA_MAX_FILE_BYTES = '1'; // force every fixture to be "too large"

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

test('oversized files are recorded with a reason instead of only an aggregate count', async () => {
  const { scanDirectoryTool } = await import('../dist/tools.js');
  const result = await scanDirectoryTool({ directory: FIX });
  const files = result.structuredContent.files;

  assert.ok(files.length > 0, 'expected fixture files to be recorded');
  for (const entry of files) {
    assert.equal(entry.verdict, 'error');
    assert.equal(entry.reason, 'exceeds size limit');
  }
  // Nothing was actually handed to the engine, so "scanned" excludes these.
  assert.equal(result.structuredContent.scanned, 0);
  assert.equal(result.structuredContent.skipped.tooLarge, files.length);
});
