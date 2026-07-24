// Engine-load-failure unit tests. Uses the test-only DI seam in engine.ts to
// simulate a corrupt/missing native binding without touching the real one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getEngineStatus,
  requireEngine,
  setEngineLoaderForTest,
  resetEngineCacheForTest,
} from '../dist/engine/engine.js';

test('getEngineStatus reports loaded:true when the loader succeeds', async () => {
  resetEngineCacheForTest();
  setEngineLoaderForTest(async () => ({}));
  const status = await getEngineStatus();
  assert.equal(status.loaded, true);
  resetEngineCacheForTest();
  setEngineLoaderForTest(null);
});

test('getEngineStatus reports loaded:false with the underlying reason on a failing loader', async () => {
  resetEngineCacheForTest();
  setEngineLoaderForTest(async () => {
    throw new Error('boom: corrupt index.node');
  });
  const status = await getEngineStatus();
  assert.equal(status.loaded, false);
  assert.match(status.reason, /boom: corrupt index\.node/);
  resetEngineCacheForTest();
  setEngineLoaderForTest(null);
});

test('requireEngine throws a labeled error when the loader fails', async () => {
  resetEngineCacheForTest();
  setEngineLoaderForTest(async () => {
    throw new Error('boom');
  });
  await assert.rejects(() => requireEngine(), /engine failed to load: boom/);
  resetEngineCacheForTest();
  setEngineLoaderForTest(null);
});

test('the load result is cached: a later loader change has no effect until reset', async () => {
  resetEngineCacheForTest();
  setEngineLoaderForTest(async () => ({}));
  assert.equal((await getEngineStatus()).loaded, true);

  setEngineLoaderForTest(async () => {
    throw new Error('should not be used');
  });
  assert.equal((await getEngineStatus()).loaded, true, 'cached result should still be loaded:true');

  resetEngineCacheForTest();
  assert.equal((await getEngineStatus()).loaded, false, 'after reset, the new (failing) loader takes effect');
  resetEngineCacheForTest();
  setEngineLoaderForTest(null);
});
