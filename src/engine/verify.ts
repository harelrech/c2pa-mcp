// The shared verification core used by every tool: read an asset with the c2pa
// engine under the current trust settings and return a finished digest.

import { Reader } from '@contentauth/c2pa-node';
import type { Reader as ManifestStore } from '@contentauth/c2pa-types';
import type { Digest, TrustInfo } from '../types.js';
import { buildDigest, noCredentialsDigest } from '../digest/digest.js';
import { getTrustSettings } from './trust.js';

/** A buffer (with MIME) or a filesystem path (MIME inferred from extension). */
export type VerifyAsset =
  | { buffer: Buffer; mimeType: string }
  | { path: string; mimeType?: string };

function errorDigest(message: string, trust: TrustInfo): Digest {
  return {
    verdict: 'error',
    summary: `Could not verify Content Credentials: ${message}`,
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

/**
 * Verify one asset. Resolves the trust list (cached), reads the manifest store,
 * and builds the digest. A `null` reader means the asset has no C2PA data; an
 * engine error is reported as an `error` verdict rather than thrown.
 */
export async function verifyAsset(asset: VerifyAsset, includeRaw = false): Promise<Digest> {
  const trust = await getTrustSettings();
  try {
    const reader = await Reader.fromAsset(asset, trust.settingsJson);
    if (!reader) return noCredentialsDigest(trust.info);
    const store = reader.json() as ManifestStore;
    return buildDigest(store, { trust: trust.info, includeRaw });
  } catch (err) {
    return errorDigest((err as Error).message || 'unknown engine error', trust.info);
  }
}
