// resolveLocalPath input-safety tests (no allowed-roots configured). Pure path
// logic: rejects UNC and remote file:// authorities, accepts local paths.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveLocalPath } from '../dist/tools.js';

test('rejects a UNC backslash path (SMB egress)', async () => {
  const r = await resolveLocalPath('\\\\server\\share\\x.jpg');
  assert.equal(r.ok, false);
  assert.match(r.reason, /UNC/);
});

test('rejects a UNC forward-slash path', async () => {
  const r = await resolveLocalPath('//server/share/x.jpg');
  assert.equal(r.ok, false);
});

test('rejects a file:// URL with a remote host authority', async () => {
  const r = await resolveLocalPath('file://evil.example.com/share/x.jpg');
  assert.equal(r.ok, false);
  assert.match(r.reason, /host authority/);
});

test('accepts a local file:// URL (empty/localhost host)', async () => {
  const url = process.platform === 'win32' ? 'file:///C:/temp/x.jpg' : 'file:///tmp/x.jpg';
  const r = await resolveLocalPath(url);
  assert.equal(r.ok, true);
});

test('accepts a normal absolute path when no roots are configured', async () => {
  const p = process.platform === 'win32' ? 'C:/temp/x.jpg' : '/tmp/x.jpg';
  const r = await resolveLocalPath(p);
  assert.equal(r.ok, true);
});
