// Assemble the LLM-ready digest from a raw ManifestStore plus the trust context
// under which it was verified. This is the one place that stitches the verdict,
// signer, AI, provenance, edits, watermarks, and issues together.

import type { Reader as ManifestStore, Manifest } from '@contentauth/c2pa-types';
import type { Digest, TrustInfo } from '../types.js';
import { buildProvenance } from './provenance.js';
import { collectIngredientIssues } from './ingredients.js';
import { extractAi, extractEdits, extractGenerator, extractWatermarks } from './extract.js';
import {
  buildSummary,
  chainSummarySuffix,
  collectIssues,
  deriveVerdict,
  extractSigner,
  hasUntrustedSigner,
  verdictToNodeVerdict,
} from './verdict.js';

export interface BuildDigestOptions {
  trust: TrustInfo;
  includeRaw?: boolean;
}

/** No C2PA manifest was present in the asset. */
export function noCredentialsDigest(trust: TrustInfo): Digest {
  return {
    verdict: 'no_credentials',
    summary: 'No C2PA Content Credentials were found in this asset.',
    title: null,
    format: null,
    generator: null,
    signer: null,
    aiGenerated: { isAI: false, tools: [], digitalSourceTypes: [] },
    provenance: [],
    edits: [],
    watermarks: [],
    issues: [],
    ingredientIssues: [],
    trust,
  };
}

export function buildDigest(store: ManifestStore, opts: BuildDigestOptions): Digest {
  const { trust, includeRaw } = opts;

  const verdict = deriveVerdict(store, trust.evaluated);
  const trusted = verdict === 'trusted';
  const signer = extractSigner(store, trusted);
  const ai = extractAi(store);

  const activeLabel = store.active_manifest || undefined;
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const active = (activeLabel && manifests[activeLabel]) || undefined;

  // The file's own issues and the chain's issues are two channels on purpose
  // (C2PA 2.2 §15.11): an ingredient's failure is reported, but it never
  // repaints this file's verdict or its issue list.
  const issues = collectIssues(store);
  const chain = collectIngredientIssues(store);
  if (chain.depthExceeded) {
    issues.push({
      code: 'security.maxDepthReached',
      severity: 'warning',
      explanation: 'The provenance chain is deeper than this verifier walks; ingredients beyond the cap were not evaluated.',
    });
  }

  return {
    verdict,
    summary:
      buildSummary(verdict, signer, ai.isAI, ai.tools, hasUntrustedSigner(issues)) +
      chainSummarySuffix(chain.issues),
    title: active?.title || null,
    format: active?.format || null,
    generator: extractGenerator(store),
    signer,
    aiGenerated: ai,
    provenance: buildProvenance(store, verdictToNodeVerdict(verdict), chain.issues),
    edits: extractEdits(store),
    watermarks: extractWatermarks(store),
    issues,
    ingredientIssues: chain.issues,
    trust,
    ...(includeRaw ? { raw: store } : {}),
  };
}
