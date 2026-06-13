// Unit tests for the pure digest functions, driven by synthetic ManifestStore
// objects (no native engine, no network).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProvenance } from '../dist/digest/provenance.js';
import { extractAi, extractWatermarks } from '../dist/digest/extract.js';
import { collectIssues } from '../dist/digest/verdict.js';

const AI_SOURCE = 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia';

test('buildProvenance flattens the lineage with depths and relationship labels', () => {
  const store = {
    active_manifest: 'm0',
    manifests: {
      m0: {
        title: 'Root',
        format: 'image/jpeg',
        signature_info: { common_name: 'Signer A' },
        ingredients: [
          { title: 'Edited Source', relationship: 'parentOf', active_manifest: 'm1' },
          { title: 'A Leaf', relationship: 'componentOf' },
        ],
      },
      m1: { title: 'Source', signature_info: { common_name: 'Signer B' }, ingredients: [] },
    },
  };
  const nodes = buildProvenance(store, 'trusted');
  assert.equal(nodes.length, 3);
  assert.deepEqual(
    nodes.map((n) => [n.depth, n.relationship]),
    [
      [0, 'This file'],
      [1, 'Edited from'],
      [1, 'Placed ingredient'],
    ],
  );
  assert.equal(nodes[0].verdict, 'trusted');
  assert.equal(nodes[0].signer, 'Signer A');
  assert.equal(nodes[1].title, 'Edited Source');
  assert.equal(nodes[1].signer, 'Signer B');
});

test('buildProvenance renders a manifest cycle as a leaf instead of looping', () => {
  const store = {
    active_manifest: 'a',
    manifests: {
      a: { title: 'A', signature_info: { common_name: 'S' }, ingredients: [{ active_manifest: 'b', relationship: 'parentOf' }] },
      b: { title: 'B', signature_info: { common_name: 'S' }, ingredients: [{ active_manifest: 'a', relationship: 'parentOf' }] },
    },
  };
  const nodes = buildProvenance(store, 'valid');
  assert.equal(nodes.length, 3); // a -> b -> (a already visited, rendered as leaf)
  assert.equal(nodes[2].depth, 2);
});

test('extractAi detects trained-algorithmic source and names the tool', () => {
  const store = {
    active_manifest: 'm',
    manifests: {
      m: { assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', softwareAgent: { name: 'DALL-E' }, digitalSourceType: AI_SOURCE }] } }] },
    },
  };
  const ai = extractAi(store);
  assert.equal(ai.isAI, true);
  assert.ok(ai.tools.includes('DALL-E'));
  assert.deepEqual(ai.digitalSourceTypes, [AI_SOURCE]);
});

test('extractAi reports not-AI when no AI source type is declared', () => {
  const store = {
    active_manifest: 'm',
    manifests: { m: { assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.color_adjustments', softwareAgent: 'Photoshop' }] } }] } },
  };
  assert.equal(extractAi(store).isAI, false);
});

test('extractWatermarks flags a declared SynthID assertion', () => {
  const store = { manifests: { m: { assertions: [{ label: 'com.google.synthid', data: { alg: 'synthid-v1' } }] } } };
  const w = extractWatermarks(store);
  assert.equal(w.length, 1);
  assert.equal(w[0].kind, 'synthid');
});

test('collectIssues keeps same-code issues that differ by url', () => {
  const store = {
    validation_status: [
      { code: 'assertion.dataHash.mismatch', url: 'self#jumbf=/c2pa/m/assertions/a1' },
      { code: 'assertion.dataHash.mismatch', url: 'self#jumbf=/c2pa/m/assertions/a2' },
    ],
  };
  const mismatches = collectIssues(store).filter((i) => i.code === 'assertion.dataHash.mismatch');
  assert.equal(mismatches.length, 2);
});
