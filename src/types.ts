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
  /** The trust-list URL used, when one was applied. */
  listSource: string | null;
  /** Why trust was not evaluated, when `evaluated` is false. */
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
  /** Validation issues that matter (errors + warnings), each explained. */
  issues: IssueEntry[];
  trust: TrustInfo;
  /** The full raw ManifestStore, only when the caller asked for it. */
  raw?: unknown;
}
