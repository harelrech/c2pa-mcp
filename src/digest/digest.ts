// Assemble the LLM-ready digest from a raw ManifestStore plus the trust context
// under which it was verified. This is the one place that stitches the verdict,
// signer, AI, provenance, edits, watermarks, and issues together.

import type { Reader as ManifestStore, Manifest } from '@contentauth/c2pa-types';
import type { Digest, TrustInfo } from '../types.js';
import { buildProvenance } from './provenance.js';
import { extractAi, extractEdits, extractGenerator, extractWatermarks } from './extract.js';
import {
  buildSummary,
  collectIssues,
  deriveVerdict,
  extractSigner,
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

  return {
    verdict,
    summary: buildSummary(verdict, signer, ai.isAI, ai.tools),
    title: active?.title || null,
    format: active?.format || null,
    generator: extractGenerator(store),
    signer,
    aiGenerated: ai,
    provenance: buildProvenance(store, verdictToNodeVerdict(verdict)),
    edits: extractEdits(store),
    watermarks: extractWatermarks(store),
    issues: collectIssues(store),
    trust,
    ...(includeRaw ? { raw: store } : {}),
  };
}
