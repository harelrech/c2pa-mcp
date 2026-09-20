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

test('buildProvenance keeps distinct same-title ingredients (dedupes only by instance_id)', () => {
  const store = {
    active_manifest: 'm0',
    manifests: {
      m0: {
        title: 'Root',
        signature_info: { common_name: 'S' },
        ingredients: [
          { title: 'Untitled', relationship: 'componentOf' },
          { title: 'Untitled', relationship: 'componentOf' },
        ],
      },
    },
  };
  const nodes = buildProvenance(store, 'valid');
  // root + two distinct "Untitled" leaves — the second must not be suppressed.
  assert.equal(nodes.length, 3);
});

test('buildProvenance never elevates a node to trusted from a status code', () => {
  const store = {
    active_manifest: 'm0',
    manifests: {
      m0: {
        title: 'Root',
        signature_info: { common_name: 'S' },
        ingredients: [
          { title: 'Ing', relationship: 'parentOf', active_manifest: 'm1', validation_status: [{ code: 'signingCredential.trusted' }] },
        ],
      },
      m1: { title: 'Ing', signature_info: { common_name: 'S' }, ingredients: [] },
    },
  };
  const nodes = buildProvenance(store, 'valid_trust_unknown');
  const ing = nodes.find((n) => n.relationship === 'Edited from');
  assert.equal(ing.verdict, 'valid'); // falls back to valid, not 'trusted'
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

// ── Ingredient-chain channel (C2PA 2.2 §15.11) ───────────────────────────────
// Synthetic stores ported from c2paviewer.com's conformance suite (cases b…b6).

import { collectIngredientIssues } from '../dist/digest/ingredients.js';
import { buildDigest } from '../dist/digest/digest.js';
import { buildSummary } from '../dist/digest/verdict.js';

const TRUST = { evaluated: true, listSource: 'test' };
const chainCodes = (d) => d.ingredientIssues.flatMap((i) => i.codes.map((c) => c.code));

test('(b) a flat validation_status failure on an ingredient never reaches Digest.issues', () => {
  const store = {
    validation_state: 'Trusted',
    active_manifest: 'm0',
    manifests: {
      m0: {
        signature_info: { common_name: 'S' },
        ingredients: [{ title: 'Ing', relationship: 'parentOf', active_manifest: 'm1', validation_status: [{ code: 'ingredient.hashedURI.mismatch' }] }],
      },
      m1: { signature_info: { common_name: 'S' } },
    },
  };
  const d = buildDigest(store, { trust: TRUST });
  assert.equal(d.verdict, 'trusted');
  assert.deepEqual(d.issues, []);
  assert.deepEqual(chainCodes(d), ['ingredient.hashedURI.mismatch']);
  assert.equal(d.ingredientIssues[0].manifestLabel, 'm1');
  const node = d.provenance.find((n) => n.title === 'Ing');
  assert.equal(node.verdict, 'invalid');
  assert.deepEqual(node.issues.map((c) => c.code), ['ingredient.hashedURI.mismatch']);
});

test('(b2) Ingredient V3 wrapper: codes under .activeManifest surface; success bucket does not', () => {
  const store = {
    validation_state: 'Trusted',
    active_manifest: 'm0',
    manifests: {
      m0: {
        signature_info: { common_name: 'S' },
        ingredients: [{
          title: 'V3', relationship: 'parentOf', active_manifest: 'm1',
          validation_results: {
            activeManifest: {
              success: [{ code: 'assertion.hashedURI.match' }],
              informational: [],
              failure: [{ code: 'signingCredential.invalid' }, { code: 'claimSignature.mismatch' }],
            },
            ingredientDeltas: [],
          },
        }],
      },
      m1: { signature_info: { common_name: 'S' } },
    },
  };
  const d = buildDigest(store, { trust: TRUST });
  assert.deepEqual(d.issues, []);
  const codes = chainCodes(d);
  assert.ok(codes.includes('signingCredential.invalid') && codes.includes('claimSignature.mismatch'));
  assert.ok(!codes.includes('assertion.hashedURI.match'));
});

test('(b3) store-level delta is attributed by the failure url, not ingredientAssertionURI', () => {
  const store = {
    validation_state: 'Trusted',
    active_manifest: 'urn:parent',
    manifests: {
      'urn:parent': { signature_info: { common_name: 'S' }, ingredients: [{ title: 'Child', active_manifest: 'urn:child' }] },
      'urn:child': { signature_info: { common_name: 'S' } },
    },
    validation_results: {
      activeManifest: { success: [], informational: [], failure: [] },
      ingredientDeltas: [{
        ingredientAssertionURI: 'self#jumbf=/c2pa/urn:parent/c2pa.assertions/c2pa.ingredient',
        validationDeltas: { success: [], informational: [], failure: [{ code: 'claimSignature.mismatch', url: 'self#jumbf=/c2pa/urn:child/c2pa.signature' }] },
      }],
    },
  };
  const { issues } = collectIngredientIssues(store);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].manifestLabel, 'urn:child');
  assert.equal(issues[0].worstSeverity, 'error');
  const d = buildDigest(store, { trust: TRUST });
  assert.deepEqual(d.issues, []);
  assert.equal(d.provenance.find((n) => n.title === 'Child').verdict, 'invalid');
});

test('(b4) a clean chain yields no ingredient issues', () => {
  const store = {
    validation_state: 'Trusted',
    active_manifest: 'm0',
    manifests: {
      m0: { signature_info: { common_name: 'S' }, ingredients: [{ title: 'Ing', active_manifest: 'm1', validation_status: [{ code: 'claimSignature.validated' }] }] },
      m1: { signature_info: { common_name: 'S' } },
    },
  };
  assert.deepEqual(collectIngredientIssues(store).issues, []);
});

test('ocsp.notRevoked under informational is a passing check: node stays valid, no issues', () => {
  const store = {
    validation_state: 'Trusted',
    active_manifest: 'm0',
    manifests: {
      m0: {
        signature_info: { common_name: 'S' },
        ingredients: [{
          title: 'Ing', active_manifest: 'm1',
          validation_results: { activeManifest: { success: [], informational: [{ code: 'signingCredential.ocsp.notRevoked' }], failure: [] }, ingredientDeltas: [] },
        }],
      },
      m1: { signature_info: { common_name: 'S' } },
    },
  };
  const d = buildDigest(store, { trust: TRUST });
  const node = d.provenance.find((n) => n.title === 'Ing');
  assert.equal(node.verdict, 'valid');
  assert.deepEqual(node.issues, []);
  assert.deepEqual(d.ingredientIssues, []);
});

test('(b6) an untrusted timestamp authority is not described as an untrusted signer', () => {
  const base = { active_manifest: 'm0', manifests: { m0: { signature_info: { common_name: 'Good Signer' } } } };
  const tsa = buildDigest({ ...base, validation_state: 'Valid', validation_status: [{ code: 'timeStamp.untrusted' }] }, { trust: TRUST });
  assert.equal(tsa.verdict, 'valid_untrusted');
  assert.doesNotMatch(tsa.summary, /signer .* is not on/i);
  assert.match(tsa.summary, /timestamp authority/);
  const signer = buildDigest({ ...base, validation_state: 'Valid', validation_status: [{ code: 'signingCredential.untrusted' }] }, { trust: TRUST });
  assert.match(signer.summary, /signer .* is not on the C2PA trust list/i);
  // Default (no issue list consulted) keeps the historical sentence.
  assert.match(buildSummary('valid_untrusted', { name: 'X' }, false, []), /signer \(X\) is not on/);
});

test('ingredient failures never change the root verdict, even when validation_state is absent', () => {
  const store = {
    active_manifest: 'm0',
    manifests: {
      m0: { signature_info: { common_name: 'S' }, ingredients: [{ title: 'Ing', active_manifest: 'm1' }] },
      m1: { signature_info: { common_name: 'S' } },
    },
    validation_results: {
      activeManifest: { success: [], informational: [], failure: [] },
      ingredientDeltas: [{ validationDeltas: { failure: [{ code: 'claimSignature.mismatch', url: 'self#jumbf=/c2pa/m1/c2pa.signature' }] } }],
    },
  };
  const d = buildDigest(store, { trust: TRUST });
  assert.notEqual(d.verdict, 'invalid');
  assert.deepEqual(d.issues, []);
  assert.deepEqual(chainCodes(d), ['claimSignature.mismatch']);
});
