// Collect validation problems per ingredient in the provenance chain.
//
// Ported from c2paviewer.com's `collectIngredientIssues`, trimmed to the shapes
// c2pa-node actually emits (no camelCase legacy fallbacks — those exist on the
// site for c2pa-web-era data and the engine here never produces them).
//
// C2PA 2.2 §15.11: a failing ingredient does NOT invalidate the active manifest,
// but the validator must still report it. These issues therefore travel on their
// own channel (`Digest.ingredientIssues`, `ProvenanceEntry.issues`) and never
// touch `deriveVerdict` or `Digest.issues`. Matches what CAI Verify renders.
//
// c2pa-rs reports ingredient problems in THREE shapes, and all three occur in the
// wild — read all of them:
//   1. store-level `validation_results.ingredientDeltas[]`
//   2. per-ingredient `validation_status[]` (Ingredient v1/v2)
//   3. per-ingredient `validation_results` (Ingredient V3 — the ValidationResults
//      WRAPPER, whose codes live at `.activeManifest.failure`, not `.failure`)

import type { Reader as ManifestStore, Manifest, Ingredient } from '@contentauth/c2pa-types';
import type { IngredientIssue, IssueEntry } from '../types.js';
import { classifyValidationCode, explainCode } from './validationCodes.js';

// The C2PA spec requires recursive ingredient validation but sets no depth bound,
// which is a DoS vector via deeply nested chains. Same cap as provenance.ts.
export const MAX_INGREDIENT_DEPTH = 20;

type LooseRecord = Record<string, unknown>;

/** `self#jumbf=/c2pa/<manifest-label>/…` → `<manifest-label>` */
const JUMBF_MANIFEST_LABEL = /self#jumbf=\/c2pa\/([^/]+)\//;

export function manifestLabelFromJumbfUri(uri: unknown): string | undefined {
  if (typeof uri !== 'string') return undefined;
  const m = JUMBF_MANIFEST_LABEL.exec(uri);
  return m ? m[1] : undefined;
}

/**
 * c2pa-rs has TWO distinct shapes that both live under a `validation_results`
 * key, and conflating them silently reads real failures as none:
 *
 *   ValidationResults  { activeManifest: StatusCodes, ingredientDeltas: [...] }
 *   StatusCodes        { success, informational, failure }
 *
 * An **Ingredient V3's** `validation_results` is the outer *wrapper*, so its
 * codes live at `.activeManifest.failure` — not at `.failure`. Reading it as a
 * bare StatusCodes yields an empty list every time (verified against a real
 * Google-signed Gemini chain, where every ingredient carries the wrapper).
 *
 * Returns the StatusCodes to grade for THIS node. Nested `ingredientDeltas` are
 * deliberately not merged in: they describe the node's own children, which get
 * their own nodes and their own buckets, so folding them here would blame a
 * parent for a grandchild's problem.
 */
export function activeStatusOf(source: unknown): unknown {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return source;
  const s = source as LooseRecord;
  // Only the wrapper has these keys; a bare StatusCodes passes straight through.
  if ('activeManifest' in s || 'ingredientDeltas' in s) return s.activeManifest;
  return source;
}

/** The `ingredientDeltas` array of a ValidationResults wrapper, if present. */
export function deltasOf(source: unknown): unknown[] {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return [];
  const d = (source as LooseRecord).ingredientDeltas;
  return Array.isArray(d) ? d : [];
}

/** A raw status entry graded by the spec table, carrying its `url` for attribution. */
export interface GradedCode extends IssueEntry {
  url: string;
}

function toGradedCodes(source: unknown): GradedCode[] {
  if (!Array.isArray(source)) return [];
  const out: GradedCode[] = [];
  for (const raw of source) {
    if (!raw || typeof raw !== 'object') continue;
    const s = raw as LooseRecord;
    const code = typeof s.code === 'string' && s.code ? s.code : 'unknown';
    const { severity } = classifyValidationCode(code);
    out.push({
      code,
      severity,
      explanation: explainCode(code, typeof s.explanation === 'string' ? s.explanation : null),
      url: typeof s.url === 'string' ? s.url : '',
    });
  }
  return out;
}

/**
 * Grade a flat status array OR a StatusCodes object. `success` is skipped: those
 * are passing checks by definition, and an unrecognised success code would
 * otherwise default to `warning` and paint a clean node amber.
 */
export function statusCodesToGraded(source: unknown): GradedCode[] {
  if (!source || typeof source !== 'object') return [];
  if (Array.isArray(source)) return toGradedCodes(source);
  const sc = source as LooseRecord;
  return [...toGradedCodes(sc.failure), ...toGradedCodes(sc.informational)];
}

const SEVERITY_RANK: Record<IssueEntry['severity'], number> = { info: 1, warning: 2, error: 3 };

interface Bucket {
  ingredientTitle: string | null;
  manifestLabel: string | null;
  codes: IssueEntry[];
}

/**
 * Walk the provenance chain and collect validation problems per ingredient.
 *
 * Attribution note (verified against real c2pa-node output): a delta's
 * `ingredientAssertionURI` names the manifest that *contains* the ingredient
 * assertion — i.e. the parent — not the ingredient's own manifest. The failing
 * manifest is identified by the label embedded in each failure's `url`, so
 * codes are grouped by that, falling back to the delta's first derivable label.
 */
export function collectIngredientIssues(
  store: ManifestStore | null | undefined,
): { issues: IngredientIssue[]; depthExceeded: boolean } {
  if (!store) return { issues: [], depthExceeded: false };
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const activeLabel = store.active_manifest || undefined;

  const buckets = new Map<string, Bucket>();
  let depthExceeded = false;

  const bucketFor = (label: string | undefined, path: string, title?: string | null): Bucket => {
    const key = label || path;
    let b = buckets.get(key);
    if (!b) {
      b = { ingredientTitle: null, manifestLabel: label || null, codes: [] };
      buckets.set(key, b);
    }
    if (!b.ingredientTitle && title) b.ingredientTitle = title;
    return b;
  };

  // Dedupe by code alone: the same code recurs once per assertion/URI, and the
  // model wants one line per distinct problem, not one per occurrence.
  //
  // Info-severity codes are dropped outright. They are passing checks, not
  // problems — c2pa-rs files `signingCredential.ocsp.notRevoked` ("signing cert
  // not revoked", i.e. the revocation check SUCCEEDED) under `informational`,
  // and surfacing it as an issue flags a perfectly healthy node. A bucket left
  // with no codes is filtered out below, so a clean ingredient produces nothing.
  const addCodes = (bucket: Bucket, codes: GradedCode[]) => {
    for (const c of codes) {
      if (c.severity === 'info') continue;
      if (bucket.codes.some((existing) => existing.code === c.code)) continue;
      bucket.codes.push({ code: c.code, severity: c.severity, explanation: c.explanation });
    }
  };

  // Group an `ingredientDeltas` array onto the manifests it actually blames.
  // Shared by the store-level results and the per-ingredient V3 wrapper.
  const addDeltas = (deltas: unknown[], pathPrefix: string) => {
    deltas.forEach((rawDelta, index) => {
      const delta = (rawDelta || {}) as LooseRecord;
      const codes = statusCodesToGraded(delta.validationDeltas);
      if (!codes.length) return;
      // A code's own url names the failing manifest; if a code has no derivable
      // label (e.g. url "Cose_Sign1"), fall back to the delta's first one.
      const primaryLabel = codes.map((c) => manifestLabelFromJumbfUri(c.url)).find(Boolean);
      const grouped = new Map<string, GradedCode[]>();
      for (const c of codes) {
        const label = manifestLabelFromJumbfUri(c.url) || primaryLabel || '';
        if (!grouped.has(label)) grouped.set(label, []);
        grouped.get(label)!.push(c);
      }
      for (const [label, groupCodes] of grouped) {
        addCodes(
          bucketFor(label || undefined, label ? `manifest.${label}` : `${pathPrefix}.${index}`),
          groupCodes,
        );
      }
    });
  };

  // Pass 1: the ingredient walk from the active manifest.
  const visited = new Set<string>();
  const walk = (manifest: Manifest | undefined, path: string, depth: number) => {
    if (!manifest) return;
    if (depth >= MAX_INGREDIENT_DEPTH) {
      depthExceeded = true;
      return;
    }
    const ingredients = Array.isArray(manifest.ingredients) ? manifest.ingredients : [];
    ingredients.forEach((ing: Ingredient, index) => {
      if (!ing || typeof ing !== 'object') return;
      const childPath = `${path}.ingredient.${index}`;
      const label = ing.active_manifest || undefined;
      const bucket = bucketFor(label, childPath, ing.title);
      addCodes(bucket, statusCodesToGraded(ing.validation_status));
      // Ingredient V3: `validation_results` is the ValidationResults wrapper —
      // this node's own codes are under `.activeManifest`, and its nested
      // deltas belong to its children, not to it.
      const ingResults = ing.validation_results;
      addCodes(bucket, statusCodesToGraded(activeStatusOf(ingResults)));
      addDeltas(deltasOf(ingResults), `${childPath}.delta`);

      const visitKey = label || childPath;
      if (visited.has(visitKey)) return;
      visited.add(visitKey);
      walk(label ? manifests[label] : undefined, childPath, depth + 1);
    });
  };
  walk(activeLabel ? manifests[activeLabel] : undefined, 'activeManifest', 0);

  // Pass 2: non-active manifests' own status, for chains the walk can't reach
  // (e.g. an ingredient whose `active_manifest` pointer is missing).
  for (const [label, manifest] of Object.entries(manifests)) {
    if (label === activeLabel) continue;
    const mResults = manifest?.validation_results;
    const codes = [
      ...statusCodesToGraded(manifest?.validation_status),
      ...statusCodesToGraded(activeStatusOf(mResults)),
    ];
    if (codes.length) addCodes(bucketFor(label, `manifest.${label}`, manifest?.title), codes);
    addDeltas(deltasOf(mResults), `manifest.${label}.delta`);
  }

  // Pass 3: store-level deltas — failures that never appear on the ingredient
  // object itself.
  addDeltas(deltasOf(store.validation_results), 'ingredientDelta');

  const issues: IngredientIssue[] = [];
  for (const b of buckets.values()) {
    if (!b.codes.length) continue;
    const worst = b.codes.reduce<'error' | 'warning'>(
      (w, c) => (SEVERITY_RANK[c.severity] > SEVERITY_RANK[w] ? (c.severity as 'error' | 'warning') : w),
      'warning',
    );
    issues.push({
      ingredientTitle: b.ingredientTitle,
      manifestLabel: b.manifestLabel,
      codes: b.codes,
      worstSeverity: worst,
    });
  }
  return { issues, depthExceeded };
}
