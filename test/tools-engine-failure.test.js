// A broken native engine must be reported distinctly from a genuinely missing
// path — not collapsed into the same "Cannot access the requested path." message
// (see the anti-oracle comments in tools.ts). Uses the engine.ts DI seam to
// simulate a corrupt/missing native binding.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyFileTool, scanDirectoryTool, infoTool } from '../dist/tools.js';
import { setEngineLoaderForTest, resetEngineCacheForTest } from '../dist/engine/engine.js';

function withFailingEngine(fn) {
  return async () => {
    resetEngineCacheForTest();
    setEngineLoaderForTest(async () => {
      throw new Error('dlopen failed: corrupt index.node');
    });
    try {
      await fn();
    } finally {
      resetEngineCacheForTest();
      setEngineLoaderForTest(null);
    }
  };
}

test(
  'verifyFileTool reports engine failure distinctly, not the generic path message',
  withFailingEngine(async () => {
    const result = await verifyFileTool({ path: '/does/not/exist.jpg' });
    assert.equal(result.isError, true);
    const text = result.content[0].text;
    assert.match(text, /Verification engine failed to load/);
    assert.match(text, /dlopen failed: corrupt index\.node/);
    assert.doesNotMatch(text, /Cannot access the requested path/);
  }),
);

test(
  'scanDirectoryTool reports engine failure distinctly, not the generic directory message',
  withFailingEngine(async () => {
    const result = await scanDirectoryTool({ directory: '/does/not/exist' });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Verification engine failed to load/);
    assert.doesNotMatch(result.content[0].text, /Cannot access the requested directory/);
  }),
);

test(
  'infoTool reports FAILED engine status with the reason',
  withFailingEngine(async () => {
    const result = await infoTool('0.5.5', '0.1.2');
    assert.match(result.content[0].text, /FAILED: dlopen failed: corrupt index\.node/);
    assert.equal(result.structuredContent.engineStatus.loaded, false);
  }),
);
