// Shared types for the digest the MCP returns. This is the LLM-facing contract:
// a compact, plain-language summary of what a C2PA manifest store proves, derived
// from the raw `ManifestStore` that `@contentauth/c2pa-node` produces.

/** The single authoritative call for a verified asset. */
export type Verdict =
  | 'trusted' // signed, cryptographically valid, signer on the C2PA trust list
  | 'valid_untrusted' // valid signature, signer NOT on the trust list
  | 'valid_trust_unknown' // valid signature, trust list could not be evaluated
  | 'invalid' // signature or content-integrity check failed
  | 'no_credentials' // no C2PA manifest present in the asset
  | 'error'; // verification could not be performed

/** Per-node verdict in the provenance lineage (less strict than the root Verdict). */
export type NodeVerdict = 'trusted' | 'valid' | 'warning' | 'invalid' | 'unknown';

export type IssueSeverity = 'error' | 'warning' | 'info';

export interface SignerInfo {
  /** Best display name for the signer (common name, else org from the issuer DN). */
  name: string | null;
  /** Full issuer distinguished name, when present. */
  issuer: string | null;
  certSerial: string | null;
  /** Signing time (or trusted-timestamp time) in ISO 8601, when present. */
  timestamp: string | null;
  /** True only when the signer resolved against the C2PA trust list. */
  trusted: boolean;
}

export interface AiInfo {
  /** True when an action declares trained-algorithmic (generative AI) source. */
  isAI: boolean;
  /** Software agents named in AI-generating actions. */
  tools: string[];
  /** Raw IPTC digitalSourceType URIs found, for transparency. */
  digitalSourceTypes: string[];
}

export interface ProvenanceEntry {
  /** 0 for the asset itself, increasing for each ingredient generation. */
  depth: number;
  title: string;
  /** Human relationship label: 'This file', 'Edited from', 'Placed ingredient', ... */
  relationship: string;
  signer: string | null;
  format: string | null;
  verdict: NodeVerdict;
  /** Label of this node's manifest in the store's `manifests` map, when resolvable. */
  manifestLabel: string | null;
  /**
   * Validation problems reported against THIS node (errors + warnings, never
   * info). Always present; `[]` for a clean node. The root node's own problems
   * live in `Digest.issues`, so its list is always empty.
   */
  issues: IssueEntry[];
}

/**
 * Validation problems belonging to an *ingredient* in the provenance chain,
 * kept deliberately separate from the active manifest's own `issues`.
 *
 * C2PA 2.2 §15.11: a failing ingredient does NOT invalidate the active manifest,
 * but a validator must still report it. Folding these into `Digest.issues`
 * would let an earlier version's failure read as this file's own failure —
 * the model would see "verdict: valid" next to "[x] claimSignature.mismatch".
 */
export interface IngredientIssue {
  /** Ingredient title, when the ingredient object itself was reachable. */
  ingredientTitle: string | null;
  /** Label of the failing manifest in the store's `manifests` map, when derivable. */
  manifestLabel: string | null;
  /** Errors + warnings only, deduped by code. */
  codes: IssueEntry[];
  worstSeverity: 'error' | 'warning';
}

export interface EditEntry {
  /** Human action label, e.g. 'Created', 'Cropped', 'Edited'. */
  label: string;
  agent: string;
  /** Formatted UTC timestamp, or '' when absent. */
  when: string;
  detail: string;
}

export interface WatermarkEntry {
  kind: 'synthid' | 'soft-binding' | 'watermark';
  assertionLabel: string;
  algorithm: string;
}

export interface IssueEntry {
  code: string;
  severity: IssueSeverity;
  explanation: string;
}

export interface TrustInfo {
  /** True when the trust list was loaded and applied during verification. */
  evaluated: boolean;
  /** The trust-list URL(s) that actually loaded, when one was applied. */
  listSource: string | null;
  /**
   * True when some, but not all, configured trust lists loaded. The verdict was
   * evaluated against fewer anchors than configured, so a signer that only the
   * missing list recognizes can read as untrusted. `reason` names what is missing.
   */
  partial?: boolean;
  /**
   * Why trust was not evaluated (when `evaluated` is false), or which configured
   * lists are missing (when `partial` is true).
   */
  reason?: string | null;
}

export interface Digest {
  verdict: Verdict;
  /** One-sentence, plain-language explanation of the verdict. */
  summary: string;
  /** Source filename/title of the active manifest, when present. */
  title: string | null;
  /** MIME type of the asset as recorded in the manifest. */
  format: string | null;
  /** Software/hardware that produced the active claim (claim generator). */
  generator: string | null;
  signer: SignerInfo | null;
  aiGenerated: AiInfo;
  /** Provenance lineage flattened pre-order; depth conveys hierarchy. */
  provenance: ProvenanceEntry[];
  /** Edit/creation actions recorded in the active manifest. */
  edits: EditEntry[];
  /** Declared (not pixel-verified) watermarks such as SynthID. */
  watermarks: WatermarkEntry[];
  /**
   * Validation issues that matter (errors + warnings) for the ACTIVE manifest —
   * this file's own signature and content. Problems found on earlier versions
   * in the chain are reported in `ingredientIssues` instead.
   */
  issues: IssueEntry[];
  /**
   * Problems found on ingredients (earlier versions / components) in the
   * provenance chain. Never affects `verdict` — see IngredientIssue.
   */
  ingredientIssues: IngredientIssue[];
  trust: TrustInfo;
  /** The full raw ManifestStore, only when the caller asked for it. */
  raw?: unknown;
}
