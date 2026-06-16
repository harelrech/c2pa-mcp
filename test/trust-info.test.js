// trustInfoFor: how a successful (possibly partial) trust evaluation is reported.
// Pure and offline — no engine, no network. The total-failure case (zero lists
// loaded) is handled by the fetchAllPems throw path, not this helper, and is
// covered end-to-end by the "degrades loudly" test in fixtures.test.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { trustInfoFor } from '../dist/engine/trust.js';

const A = 'https://example.com/a.pem';
const B = 'https://example.com/b.pem';

test('all configured lists loaded -> evaluated, not partial', () => {
  const info = trustInfoFor([A, B], [A, B]);
  assert.equal(info.evaluated, true);
  assert.equal(info.partial, false);
  assert.equal(info.listSource, `${A}, ${B}`);
  assert.ok(!info.reason);
});

test('only one of two loaded -> partial, listSource is just the loaded list', () => {
  const info = trustInfoFor([A], [A, B]);
  assert.equal(info.evaluated, true);
  assert.equal(info.partial, true);
  assert.equal(info.listSource, A); // never claims B
  assert.match(info.reason, /1 of 2/);
  assert.match(info.reason, new RegExp(B.replace(/[.\/]/g, '\\$&'))); // names the missing list
});

test('single configured list loaded -> not partial', () => {
  const info = trustInfoFor([A], [A]);
  assert.equal(info.partial, false);
  assert.equal(info.listSource, A);
});
