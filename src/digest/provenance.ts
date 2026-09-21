// Build the provenance lineage from a ManifestStore.
//
// Ported from c2paviewer.com's `buildProvenanceTree`, but adapted to the single
// canonical `@contentauth/c2pa-types` shape and FLATTENED into a pre-order list
// with a `depth` field. A flat, indented list reads better for an LLM than
// nested JSON, and thumbnails (useless to a model) are dropped.

import type { Reader as ManifestStore, Manifest, Ingredient, SignatureInfo } from '@contentauth/c2pa-types';
import type { IngredientIssue, IssueEntry, NodeVerdict, ProvenanceEntry } from '../types.js';
import { MAX_INGREDIENT_DEPTH, activeStatusOf, statusCodesToGraded } from './ingredients.js';
import type { ChainIssues } from './ingredients.js';

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

const VERDICT_RANK: Record<NodeVerdict, number> = {
  unknown: 0,
  trusted: 1,
  valid: 2,
  warning: 3,
  invalid: 4,
};

function worseVerdict(a: NodeVerdict, b: NodeVerdict): NodeVerdict {
  return VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a;
}

// Worst verdict across a list of already-classified codes.
//
// Severity comes from classifyValidationCode's spec lookup table, NOT from
// substring matching on the code string. Substring matching is actively unsafe
// here: `signingCredential.ocsp.notRevoked` — a code that means the revocation
// check PASSED — contains "revoked", so a `/…|revoked|…/` regex graded a
// healthy Google-signed ingredient as Invalid while CAI showed it clean.
export function verdictFromCodes(codes: IssueEntry[], fallback: NodeVerdict): NodeVerdict {
  let v: NodeVerdict = fallback;
  for (const c of codes) {
    if (c.severity === 'error') return 'invalid';
    if (c.severity === 'warning') v = 'warning';
  }
  // Deliberately never elevate a node to 'trusted' from a status code. Trust is
  // a store-level decision; the root node carries the authoritative verdict,
  // and a per-ingredient 'trusted' must not contradict an overall
  // valid_trust_unknown.
  return v;
}

// Verdict for one node from a flat validation_status array, a StatusCodes
// object, or an Ingredient V3 ValidationResults wrapper.
function verdictFromStatus(status: unknown, fallback: NodeVerdict): NodeVerdict {
  const graded = statusCodesToGraded(activeStatusOf(status));
  return graded.length ? verdictFromCodes(graded, fallback) : fallback;
}

// An ingredient's own verdict from the shapes it carries: the V3 wrapper first
// (unwrapped to its `.activeManifest` bucket), then the v1/v2 flat array.
function ingredientVerdict(ing: Ingredient, fallback: NodeVerdict): NodeVerdict {
  const fromResults = verdictFromStatus(ing?.validation_results, fallback);
  return worseVerdict(fromResults, verdictFromStatus(ing?.validation_status, fallback));
}

/**
 * Flatten the provenance lineage to a pre-order list of entries.
 * @param store the raw ManifestStore from `reader.json()`
 * @param rootVerdict the authoritative node verdict for the active asset (from the
 *   store-level validation_state), so the root never contradicts the overall result.
 * @param chain problems already collected by collectIngredientIssues (or a bare
 *   issue list); consulted for every non-root node so a failure that only
 *   exists in store-level deltas still paints the right node.
 */
export function buildProvenance(
  store: ManifestStore | null | undefined,
  rootVerdict: NodeVerdict,
  chain: ChainIssues | IngredientIssue[] = [],
): ProvenanceEntry[] {
  if (!store) return [];
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const activeLabel = store.active_manifest || undefined;
  const activeManifest = (activeLabel && manifests[activeLabel]) || undefined;
  if (!activeManifest) return [];

  const ingredientIssues = Array.isArray(chain) ? chain : chain.issues;
  const byIngredient = Array.isArray(chain) ? new WeakMap<object, IngredientIssue>() : chain.byIngredient;
  const issuesByLabel = new Map<string, IngredientIssue>();
  for (const issue of ingredientIssues) {
    if (issue.manifestLabel) issuesByLabel.set(issue.manifestLabel, issue);
  }

  const out: ProvenanceEntry[] = [];
  const visited = new Set<string>();
  // Manifest labels already on the walked path, so an A->B->A manifest cycle is
  // rendered once as a leaf instead of fanning out to the depth cap.
  const visitedManifests = new Set<string>();
  if (activeLabel) visitedManifests.add(activeLabel);

  // One constructor for every node so the three push sites below (recurse,
  // cycle-leaf, unresolvable-leaf) can't drift apart. `own` is the verdict from
  // the node's own status shapes; collected issues can only make it worse.
  const nodeFor = (
    depth: number,
    title: string,
    relationship: string,
    manifest: Manifest | undefined,
    ing: Ingredient | null,
    label: string | undefined,
    own: NodeVerdict,
  ): ProvenanceEntry => {
    // By manifest label first; an ingredient with no resolvable label is
    // looked up by identity so its own failures still land on its node.
    const collected = (label ? issuesByLabel.get(label) : undefined) ?? (ing ? byIngredient.get(ing) : undefined);
    const issues = collected?.codes ?? [];
    return {
      depth,
      title,
      relationship,
      signer: signerNameOf(manifest),
      format: ing?.format || manifest?.format || null,
      verdict: collected ? worseVerdict(own, verdictFromCodes(issues, own)) : own,
      manifestLabel: label ?? null,
      issues,
    };
  };

  const walk = (
    manifest: Manifest,
    label: string | undefined,
    relationship: string,
    ingredientMeta: Ingredient | null,
    nodeVerdict: NodeVerdict,
    depth: number,
  ) => {
    // Depth is capped, but breadth is not: a crafted file can fan out many
    // ingredients per level. Cap total nodes so the digest can't be ballooned.
    if (out.length >= MAX_PROVENANCE_NODES) return;
    const title = ingredientMeta?.title || manifest?.title || (depth === 0 ? 'This file' : 'Untitled');
    if (depth === 0) {
      // The root's own problems are Digest.issues; never attach chain issues here.
      out.push({
        depth,
        title,
        relationship,
        signer: signerNameOf(manifest),
        format: manifest?.format || null,
        verdict: nodeVerdict,
        manifestLabel: label ?? null,
        issues: [],
      });
    } else {
      out.push(nodeFor(depth, title, relationship, manifest, ingredientMeta, label, nodeVerdict));
    }

    if (depth >= MAX_INGREDIENT_DEPTH) return;

    const ingredients = Array.isArray(manifest?.ingredients) ? manifest.ingredients : [];
    for (const ing of ingredients) {
      // Dedupe genuinely-identical ingredients by their canonical instance_id only.
      // Manifest cycles are handled by visitedManifests; conflating active_manifest
      // or title here would wrongly suppress distinct ingredients (e.g. two
      // "Untitled" components, or two ingredients sharing one manifest reference).
      const idKey = ing?.instance_id || undefined;
      if (idKey && visited.has(idKey)) continue;
      if (idKey) visited.add(idKey);

      const childRel = relationshipLabel(ing?.relationship);
      const childLabel = ing?.active_manifest || undefined;
      const childManifest = (childLabel && manifests[childLabel]) || undefined;

      if (childManifest && childLabel && !visitedManifests.has(childLabel)) {
        visitedManifests.add(childLabel);
        const childVerdict = ingredientVerdict(ing, childManifest.signature_info ? 'valid' : 'unknown');
        walk(childManifest, childLabel, childRel, ing, childVerdict, depth + 1);
      } else if (childManifest) {
        // Already-walked manifest (cycle): show it as a leaf, don't recurse.
        out.push(
          nodeFor(
            depth + 1,
            ing?.title || childManifest.title || 'Ingredient',
            childRel,
            childManifest,
            ing,
            childLabel,
            ingredientVerdict(ing, 'unknown'),
          ),
        );
      } else {
        // Ingredient with no resolvable manifest: still show it as a leaf so the
        // lineage stays complete.
        out.push(
          nodeFor(
            depth + 1,
            ing?.title || 'Ingredient',
            childRel,
            undefined,
            ing,
            childLabel,
            ingredientVerdict(ing, 'unknown'),
          ),
        );
      }
    }
  };

  walk(activeManifest, activeLabel, 'This file', null, rootVerdict, 0);
  return out;
}
