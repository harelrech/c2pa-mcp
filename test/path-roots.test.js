// resolveLocalPath containment tests WITH C2PA_ALLOWED_ROOTS set. Each test file
// runs in its own process, so this env only affects this file; it must be set
// before the tool module is imported (roots are read at module load).
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(tmpdir(), 'c2pa-mcp-roots-test');
process.env.C2PA_ALLOWED_ROOTS = ROOT;

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';

let resolveLocalPath;
async function load() {
  if (!resolveLocalPath) ({ resolveLocalPath } = await import('../dist/tools.js'));
  return resolveLocalPath;
}

test('accepts a path inside an allowed root', async () => {
  await mkdir(ROOT, { recursive: true });
  await writeFile(join(ROOT, 'a.jpg'), 'x');
  const fn = await load();
  const r = await fn(join(ROOT, 'a.jpg'));
  assert.equal(r.ok, true);
});

test('rejects a traversal that escapes the allowed root', async () => {
  await mkdir(ROOT, { recursive: true });
  const fn = await load();
  const r = await fn(join(ROOT, '..', 'escape.jpg'));
  assert.equal(r.ok, false);
  assert.match(r.reason, /allowed roots/);
});

test('rejects a sibling whose name only prefixes the root', async () => {
  await mkdir(ROOT, { recursive: true });
  const fn = await load();
  const r = await fn(`${ROOT}_evil/x.jpg`);
  assert.equal(r.ok, false);
});
