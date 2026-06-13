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
import type { IssueEntry, NodeVerdict, SignerInfo, Verdict } from '../types.js';
import { classifyValidationCode, explainCode } from './validationCodes.js';

function activeManifest(store: ManifestStore): Manifest | undefined {
  const label = store.active_manifest || undefined;
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  return (label && manifests[label]) || undefined;
}

/** Gather every status entry across the store, deduped by code. */
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

  push(store.validation_status);
  const results = store.validation_results;
  if (results?.activeManifest) {
    push(results.activeManifest.failure);
    push(results.activeManifest.informational);
    push(results.activeManifest.success);
  }
  for (const delta of results?.ingredientDeltas || []) {
    push(delta?.validationDeltas?.failure);
    push(delta?.validationDeltas?.informational);
    push(delta?.validationDeltas?.success);
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
  if (state === 'Trusted') return 'trusted';
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

/** One-sentence, plain-language summary of the verdict. */
export function buildSummary(
  verdict: Verdict,
  signer: SignerInfo | null,
  isAI: boolean,
  aiTools: string[],
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
