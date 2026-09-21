// Turn a ManifestStore's validation result into a single authoritative verdict,
// a signer summary, and a list of explained issues.
//
// The c2pa engine hands us an authoritative `validation_state` ("Invalid" |
// "Valid" | "Trusted"), which is far cleaner than the per-assertion guessing the
// browser SDK forced on c2paviewer.com. We trust it, then enrich with the
// granular status codes for the human-readable issue list.

import type {
  Reader as ManifestStore,
  Manifest,
  ValidationStatus,
  SignatureInfo,
} from '@contentauth/c2pa-types';
import type { IngredientIssue, IssueEntry, NodeVerdict, SignerInfo, Verdict } from '../types.js';
import { classifyValidationCode, explainCode } from './validationCodes.js';
import { manifestLabelFromJumbfUri } from './ingredients.js';

function activeManifest(store: ManifestStore): Manifest | undefined {
  const label = store.active_manifest || undefined;
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  return (label && manifests[label]) || undefined;
}

// Exact code match, deliberately not `code.includes('untrusted')`. TWO codes
// contain that word and they mean different things:
//
//   signingCredential.untrusted → the SIGNER is not on the trust list  ← this
//   timeStamp.untrusted         → the TIMESTAMP AUTHORITY is not trusted
//
// The substring form conflated them, so a file with a perfectly trusted signer
// and an untrusted TSA was told "the signer is not on the C2PA trust list" —
// the wrong sentence about the wrong certificate.
export const UNTRUSTED_SIGNER_CODE = 'signingCredential.untrusted';

/** True when the active manifest's own issues say the SIGNER is off the trust list. */
export function hasUntrustedSigner(issues: IssueEntry[]): boolean {
  return issues.some((i) => i.code === UNTRUSTED_SIGNER_CODE);
}

/**
 * Gather the ACTIVE manifest's status entries, deduped by code+url.
 *
 * `store.validation_status` is the engine's store-level AGGREGATE: it also lists
 * a nested manifest's codes, each with a url naming that manifest. Those belong
 * to the chain (collectIngredientIssues reads them) and are dropped here, with
 * one exception — when the engine's own verdict is `Invalid` and the entry is
 * an error, it is (part of) the reason for that verdict and stays, so the
 * digest never says "invalid" with an empty issue list. `ingredientDeltas` are
 * never read here (C2PA 2.2 §15.11).
 */
function allStatuses(store: ManifestStore): ValidationStatus[] {
  const seen = new Set<string>();
  const out: ValidationStatus[] = [];
  const push = (arr: ValidationStatus[] | null | undefined) => {
    if (!Array.isArray(arr)) return;
    for (const s of arr) {
      const code = s?.code;
      if (!code) continue;
      // Dedupe by code+url, not code alone: the same code can legitimately recur
      // for different assertions (e.g. two tampered assertions), and dropping the
      // repeat would understate the issues to the model.
      const key = `${code}|${s?.url ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(s);
    }
  };

  const activeLabel = store.active_manifest || undefined;
  const engineInvalid = store.validation_state === 'Invalid';
  const own = (store.validation_status || []).filter((s) => {
    const label = manifestLabelFromJumbfUri(s?.url);
    // No active label means nothing can be attributed away; keep everything.
    if (!activeLabel || !label || label === activeLabel) return true;
    return engineInvalid && classifyValidationCode(s.code).severity === 'error';
  });
  push(own);
  const results = store.validation_results;
  if (results?.activeManifest) {
    push(results.activeManifest.failure);
    push(results.activeManifest.informational);
    push(results.activeManifest.success);
  }
  return out;
}

/** Errors + warnings only, each rendered in plain language. Info is dropped as noise. */
export function collectIssues(store: ManifestStore): IssueEntry[] {
  const out: IssueEntry[] = [];
  for (const s of allStatuses(store)) {
    const code = s.code;
    const { severity } = classifyValidationCode(code);
    if (severity === 'info') continue;
    out.push({ code, severity, explanation: explainCode(code, s.explanation) });
  }
  return out;
}

/**
 * Derive the single root verdict. `validation_state` is authoritative; when it
 * is absent we fall back conservatively so we never silently pass a tampered file.
 */
export function deriveVerdict(store: ManifestStore, trustEvaluated: boolean): Verdict {
  const state = store.validation_state;

  if (state === 'Invalid') return 'invalid';
  // 'Trusted' only stands when we actually evaluated trust; otherwise stay
  // honest (defensive — the engine can't emit Trusted without anchors today,
  // but a future settings change must not surface trusted with trust unevaluated).
  if (state === 'Trusted') return trustEvaluated ? 'trusted' : 'valid_trust_unknown';
  if (state === 'Valid') return trustEvaluated ? 'valid_untrusted' : 'valid_trust_unknown';

  // No authoritative state (older engine / edge case): fail safe. Trust the
  // engine's OWN failure bucket first — if it placed anything there, the asset is
  // invalid regardless of how our code table happens to classify the code (a new
  // engine code we don't know yet must not be downgraded to a warning and slip
  // through). Then fall back to our own error classification.
  const failures = store.validation_results?.activeManifest?.failure;
  if (Array.isArray(failures) && failures.length > 0) return 'invalid';
  const issues = collectIssues(store);
  if (issues.some((i) => i.severity === 'error')) return 'invalid';
  return trustEvaluated ? 'valid_untrusted' : 'valid_trust_unknown';
}

/** Map the root verdict to the (looser) per-node verdict used in the lineage. */
export function verdictToNodeVerdict(verdict: Verdict): NodeVerdict {
  switch (verdict) {
    case 'trusted':
      return 'trusted';
    case 'valid_untrusted':
    case 'valid_trust_unknown':
      return 'valid';
    case 'invalid':
      return 'invalid';
    default:
      return 'unknown';
  }
}

/** Signer summary from the active manifest's signature info. */
export function extractSigner(store: ManifestStore, trusted: boolean): SignerInfo | null {
  const si = activeManifest(store)?.signature_info as SignatureInfo | undefined | null;
  if (!si) return null;
  let name: string | null = si.common_name || null;
  if (!name && typeof si.issuer === 'string') {
    name = /(?:^|,)\s*O=([^,]+)/.exec(si.issuer)?.[1]?.trim() || si.issuer;
  }
  return {
    name,
    issuer: si.issuer || null,
    certSerial: si.cert_serial_number || null,
    timestamp: si.time || null,
    trusted,
  };
}

/**
 * Sentence appended to the summary when an earlier version in the chain failed.
 * Warnings (e.g. an ingredient signed off the trust list) are left to the
 * structured list; only hard failures earn a mention in the one-liner.
 */
export function chainSummarySuffix(ingredientIssues: IngredientIssue[]): string {
  const failed = ingredientIssues.filter((i) => i.worstSeverity === 'error').length;
  if (!failed) return '';
  const noun = failed === 1 ? 'earlier version' : 'earlier versions';
  return ` ${failed} ${noun} in its provenance chain failed validation; this file's own signature is unaffected.`;
}

/** One-sentence, plain-language summary of the verdict. */
export function buildSummary(
  verdict: Verdict,
  signer: SignerInfo | null,
  isAI: boolean,
  aiTools: string[],
  // Whether the engine flagged the SIGNER itself (signingCredential.untrusted).
  // `validation_state: 'Valid'` also results from an untrusted timestamp
  // authority with a perfectly trusted signer; that case must not be described
  // as a signer problem. Defaults to true for the common case.
  signerUntrusted = true,
): string {
  const who = signer?.name ? ` (${signer.name})` : '';
  const ai =
    isAI
      ? ` It declares AI-generated content${aiTools.length ? ` (${aiTools.join(', ')})` : ''}.`
      : '';

  switch (verdict) {
    case 'trusted':
      return `Content Credentials are valid and the signer${who} is on the C2PA trust list.${ai}`;
    case 'valid_untrusted':
      if (!signerUntrusted) {
        return `Content Credentials are cryptographically valid${signer?.name ? `, signed by ${signer.name}` : ''}, but a certificate in the signature chain (such as the timestamp authority) is not on the C2PA trust list, so the file does not reach Trusted.${ai}`;
      }
      return `Content Credentials are cryptographically valid, but the signer${who} is not on the C2PA trust list, so the signer's identity is unverified.${ai}`;
    case 'valid_trust_unknown':
      return `Content Credentials are cryptographically valid${signer?.name ? `, signed by ${signer.name}` : ''}, but the trust list could not be checked, so signer trust is unconfirmed.${ai}`;
    case 'invalid':
      return `Content Credentials are INVALID: an integrity or signature check failed, so the content cannot be attributed to the claimed signer.${ai}`;
    case 'no_credentials':
      return 'No C2PA Content Credentials were found in this asset.';
    default:
      return 'Content Credentials could not be verified.';
  }
}
