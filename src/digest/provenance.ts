// Build the provenance lineage from a ManifestStore.
//
// Ported from c2paviewer.com's `buildProvenanceTree`, but adapted to the single
// canonical `@contentauth/c2pa-types` shape and FLATTENED into a pre-order list
// with a `depth` field. A flat, indented list reads better for an LLM than
// nested JSON, and thumbnails (useless to a model) are dropped.

import type { Reader as ManifestStore, Manifest, Ingredient, SignatureInfo } from '@contentauth/c2pa-types';
import type { NodeVerdict, ProvenanceEntry } from '../types.js';

// The C2PA spec requires recursive ingredient validation but sets no depth bound,
// which is a DoS vector via deeply nested chains. Cap recursion defensively.
const MAX_INGREDIENT_DEPTH = 20;

// Depth alone doesn't bound the tree: ingredients fan out per level. Cap the
// total number of lineage nodes the walk will emit.
const MAX_PROVENANCE_NODES = 500;

/** Signer display name: common name, else the Organization (O=) from the issuer DN. */
export function signerNameOf(manifest: Manifest | undefined | null): string | null {
  const si = manifest?.signature_info as SignatureInfo | undefined | null;
  if (!si) return null;
  if (si.common_name) return si.common_name;
  if (typeof si.issuer === 'string') {
    const org = /(?:^|,)\s*O=([^,]+)/.exec(si.issuer)?.[1]?.trim();
    if (org) return org;
    return si.issuer;
  }
  return null;
}

/** Human label for an ingredient relationship. */
function relationshipLabel(rel: string | undefined): string {
  switch (rel) {
    case 'parentOf':
      return 'Edited from';
    case 'componentOf':
      return 'Placed ingredient';
    case 'inputTo':
      return 'Input';
    default:
      return rel || 'Ingredient';
  }
}

/** Roll a validation_status array up to a single node verdict (worst wins). */
function verdictFromStatus(
  status: { code?: string }[] | null | undefined,
  fallback: NodeVerdict,
): NodeVerdict {
  if (!Array.isArray(status) || status.length === 0) return fallback;
  let v: NodeVerdict = fallback;
  let sawTrusted = false;
  for (const s of status) {
    const code = String(s?.code || '').toLowerCase();
    if (/mismatch|invalid|expired|revoked|malformed|outsidevalidity|\.missing/.test(code)) return 'invalid';
    if (code.includes('untrusted')) v = 'warning';
    else if (code.includes('trusted')) sawTrusted = true;
  }
  if (v === fallback && sawTrusted) return 'trusted';
  return v;
}

/**
 * Flatten the provenance lineage to a pre-order list of entries.
 * @param store the raw ManifestStore from `reader.json()`
 * @param rootVerdict the authoritative node verdict for the active asset (from the
 *   store-level validation_state), so the root never contradicts the overall result.
 */
export function buildProvenance(
  store: ManifestStore | null | undefined,
  rootVerdict: NodeVerdict,
): ProvenanceEntry[] {
  if (!store) return [];
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const activeLabel = store.active_manifest || undefined;
  const activeManifest = (activeLabel && manifests[activeLabel]) || undefined;
  if (!activeManifest) return [];

  const out: ProvenanceEntry[] = [];
  const visited = new Set<string>();

  const walk = (
    manifest: Manifest,
    relationship: string,
    ingredientMeta: Ingredient | null,
    nodeVerdict: NodeVerdict,
    depth: number,
  ) => {
    // Depth is capped, but breadth is not: a crafted file can fan out many
    // ingredients per level. Cap total nodes so the digest can't be ballooned.
    if (out.length >= MAX_PROVENANCE_NODES) return;
    out.push({
      depth,
      title:
        ingredientMeta?.title ||
        manifest?.title ||
        (depth === 0 ? 'This file' : 'Untitled'),
      relationship,
      signer: signerNameOf(manifest),
      format: ingredientMeta?.format || manifest?.format || null,
      verdict: nodeVerdict,
    });

    if (depth >= MAX_INGREDIENT_DEPTH) return;

    const ingredients = Array.isArray(manifest?.ingredients) ? manifest.ingredients : [];
    for (const ing of ingredients) {
      const idKey = ing?.instance_id || ing?.active_manifest || ing?.title || undefined;
      if (idKey && visited.has(idKey)) continue;
      if (idKey) visited.add(idKey);

      const childRel = relationshipLabel(ing?.relationship);
      const childManifest =
        (ing?.active_manifest && manifests[ing.active_manifest]) || undefined;

      if (childManifest) {
        const childVerdict = verdictFromStatus(
          ing?.validation_status,
          childManifest.signature_info ? 'valid' : 'unknown',
        );
        walk(childManifest, childRel, ing, childVerdict, depth + 1);
      } else {
        // Ingredient with no resolvable manifest: still show it as a leaf so the
        // lineage stays complete.
        out.push({
          depth: depth + 1,
          title: ing?.title || 'Ingredient',
          relationship: childRel,
          signer: null,
          format: ing?.format || null,
          verdict: verdictFromStatus(ing?.validation_status, 'unknown'),
        });
      }
    }
  };

  walk(activeManifest, 'This file', null, rootVerdict, 0);
  return out;
}
