// C2PA validation status codes -> {severity, category} + plain-English meaning.
//
// The raw c2pa engine emits terse codes like `assertion.dataHash.mismatch`. The
// whole point of this MCP over a raw-JSON dump is turning those into something an
// LLM (and a human) can act on. This table classifies each code and the
// EXPLANATIONS map renders the important ones in plain language.
//
// Ported from c2paviewer.com's classifier and kept in sync with the C2PA spec's
// validation status code list (spec.c2pa.org, §"Validation").

export type ValidationSeverity = 'error' | 'warning' | 'info';
export type ValidationCategory =
  | 'signature'
  | 'assertion'
  | 'ingredient'
  | 'format'
  | 'general';

export interface ValidationCodeEntry {
  severity: ValidationSeverity;
  category: ValidationCategory;
}

export const C2PA_VALIDATION_CODES: Readonly<Record<string, ValidationCodeEntry>> = Object.freeze({
  // ── Claim signature ──────────────────────────────────────────────────────
  'claimSignature.validated': { severity: 'info', category: 'signature' },
  'claimSignature.insideValidity': { severity: 'info', category: 'signature' },
  'claimSignature.missing': { severity: 'error', category: 'signature' },
  'claimSignature.mismatch': { severity: 'error', category: 'signature' },
  'claimSignature.outsideValidity': { severity: 'error', category: 'signature' },

  // ── Signing credential ───────────────────────────────────────────────────
  'signingCredential.trusted': { severity: 'info', category: 'signature' },
  'signingCredential.untrusted': { severity: 'warning', category: 'signature' },
  'signingCredential.invalid': { severity: 'error', category: 'signature' },
  'signingCredential.expired': { severity: 'error', category: 'signature' },
  'signingCredential.ocsp.notRevoked': { severity: 'info', category: 'signature' },
  'signingCredential.ocsp.revoked': { severity: 'error', category: 'signature' },
  'signingCredential.ocsp.unknown': { severity: 'warning', category: 'signature' },
  'signingCredential.ocsp.skipped': { severity: 'info', category: 'signature' },
  'signingCredential.ocsp.inaccessible': { severity: 'warning', category: 'signature' },

  // ── Timestamp ────────────────────────────────────────────────────────────
  'timeStamp.validated': { severity: 'info', category: 'signature' },
  'timeStamp.trusted': { severity: 'info', category: 'signature' },
  'timeStamp.mismatch': { severity: 'error', category: 'signature' },
  'timeStamp.malformed': { severity: 'error', category: 'signature' },
  'timeStamp.outsideValidity': { severity: 'error', category: 'signature' },
  'timeStamp.untrusted': { severity: 'warning', category: 'signature' },
  'timeOfSigning.insideValidity': { severity: 'info', category: 'signature' },

  // ── Claim ────────────────────────────────────────────────────────────────
  'claim.malformed': { severity: 'error', category: 'signature' },
  'claim.missing': { severity: 'error', category: 'signature' },
  'claim.multiple': { severity: 'error', category: 'signature' },
  'claim.required.missing': { severity: 'error', category: 'signature' },
  'claim.cbor.invalid': { severity: 'error', category: 'signature' },
  'claim.hardBindings.missing': { severity: 'error', category: 'signature' },

  // ── Hashed URI ───────────────────────────────────────────────────────────
  'hashedURI.missing': { severity: 'error', category: 'assertion' },
  'hashedURI.mismatch': { severity: 'error', category: 'assertion' },

  // ── Assertions ───────────────────────────────────────────────────────────
  'assertion.hashedURI.match': { severity: 'info', category: 'assertion' },
  'assertion.hashedURI.mismatch': { severity: 'error', category: 'assertion' },
  'assertion.dataHash.match': { severity: 'info', category: 'assertion' },
  'assertion.dataHash.mismatch': { severity: 'error', category: 'assertion' },
  'assertion.dataHash.malformed': { severity: 'error', category: 'assertion' },
  'assertion.dataHash.redacted': { severity: 'error', category: 'assertion' },
  'assertion.dataHash.additionalExclusionsPresent': { severity: 'info', category: 'assertion' },
  'assertion.bmffHash.match': { severity: 'info', category: 'assertion' },
  'assertion.bmffHash.mismatch': { severity: 'error', category: 'assertion' },
  'assertion.bmffHash.malformed': { severity: 'error', category: 'assertion' },
  'assertion.boxesHash.match': { severity: 'info', category: 'assertion' },
  'assertion.boxesHash.mismatch': { severity: 'error', category: 'assertion' },
  'assertion.boxesHash.unknownBox': { severity: 'error', category: 'assertion' },
  'assertion.boxesHash.malformed': { severity: 'error', category: 'assertion' },
  'assertion.collectionHash.match': { severity: 'info', category: 'assertion' },
  'assertion.collectionHash.mismatch': { severity: 'error', category: 'assertion' },
  'assertion.collectionHash.incorrectFileCount': { severity: 'error', category: 'assertion' },
  'assertion.collectionHash.invalidURI': { severity: 'error', category: 'assertion' },
  'assertion.collectionHash.malformed': { severity: 'error', category: 'assertion' },
  'assertion.accessible': { severity: 'info', category: 'assertion' },
  'assertion.missing': { severity: 'error', category: 'assertion' },
  'assertion.undeclared': { severity: 'error', category: 'assertion' },
  'assertion.inaccessible': { severity: 'error', category: 'assertion' },
  'assertion.notRedacted': { severity: 'error', category: 'assertion' },
  'assertion.selfRedacted': { severity: 'error', category: 'assertion' },
  'assertion.required.missing': { severity: 'error', category: 'assertion' },
  'assertion.json.invalid': { severity: 'error', category: 'assertion' },
  'assertion.cbor.invalid': { severity: 'error', category: 'assertion' },
  'assertion.outsideManifest': { severity: 'error', category: 'assertion' },
  'assertion.multipleHardBindings': { severity: 'error', category: 'assertion' },
  'assertion.action.malformed': { severity: 'error', category: 'assertion' },
  'assertion.action.ingredientMismatch': { severity: 'error', category: 'assertion' },
  'assertion.action.redactionMismatch': { severity: 'error', category: 'assertion' },
  'assertion.action.redacted': { severity: 'error', category: 'assertion' },
  'assertion.cloud-data.hardBinding': { severity: 'error', category: 'assertion' },
  'assertion.cloud-data.actions': { severity: 'error', category: 'assertion' },
  'assertion.cloud-data.malformed': { severity: 'error', category: 'assertion' },
  'assertion.ingredient.malformed': { severity: 'error', category: 'assertion' },
  'assertion.metadata.disallowed': { severity: 'error', category: 'assertion' },
  'assertion.timestamp.malformed': { severity: 'error', category: 'assertion' },

  // ── Manifest ─────────────────────────────────────────────────────────────
  'manifest.inaccessible': { severity: 'warning', category: 'general' },
  'manifest.multipleParents': { severity: 'error', category: 'general' },
  'manifest.update.invalid': { severity: 'error', category: 'general' },
  'manifest.update.wrongParents': { severity: 'error', category: 'general' },
  'manifest.timestamp.invalid': { severity: 'error', category: 'general' },
  'manifest.timestamp.wrongParents': { severity: 'error', category: 'general' },
  'manifest.compressed.invalid': { severity: 'error', category: 'general' },
  'manifest.unknownProvenance': { severity: 'warning', category: 'general' },
  'manifest.unreferenced': { severity: 'info', category: 'general' },

  // ── Ingredient ───────────────────────────────────────────────────────────
  'ingredient.manifest.validated': { severity: 'info', category: 'ingredient' },
  'ingredient.manifest.missing': { severity: 'error', category: 'ingredient' },
  'ingredient.manifest.mismatch': { severity: 'error', category: 'ingredient' },
  'ingredient.hashedURI.mismatch': { severity: 'error', category: 'ingredient' },
  'ingredient.claimSignature.validated': { severity: 'info', category: 'ingredient' },
  'ingredient.claimSignature.missing': { severity: 'error', category: 'ingredient' },
  'ingredient.claimSignature.mismatch': { severity: 'error', category: 'ingredient' },
  'ingredient.unknownProvenance': { severity: 'info', category: 'ingredient' },

  // ── Algorithm / general ──────────────────────────────────────────────────
  'algorithm.deprecated': { severity: 'warning', category: 'format' },
  'algorithm.unsupported': { severity: 'error', category: 'format' },
  'general.error': { severity: 'error', category: 'general' },

  // ── Legacy / vendor ──────────────────────────────────────────────────────
  'com.adobe.prerelease': { severity: 'warning', category: 'general' },
});

// Plain-language meaning for the codes that actually change a verdict or that a
// user is likely to ask about. Codes not listed fall back to the engine's own
// `explanation` field, then to a humanized version of the code itself.
export const CODE_EXPLANATIONS: Readonly<Record<string, string>> = Object.freeze({
  'claimSignature.mismatch':
    'The signature does not match the manifest. The file or its credentials were altered after signing.',
  'claimSignature.missing': 'The manifest has no signature, so nothing can be cryptographically verified.',
  'claimSignature.outsideValidity':
    'The asset was signed outside the validity window of the signing certificate.',
  'assertion.dataHash.mismatch':
    'The media content was changed after it was signed. The bytes no longer match what the signer certified.',
  'assertion.bmffHash.mismatch':
    'The video/audio content was changed after it was signed. It no longer matches what the signer certified.',
  'assertion.boxesHash.mismatch':
    'The file structure was changed after signing. The content no longer matches what the signer certified.',
  'assertion.hashedURI.mismatch':
    'A signed assertion was altered after signing and no longer matches its recorded hash.',
  'assertion.dataHash.malformed': 'A content-integrity hash in the manifest is malformed and cannot be checked.',
  'signingCredential.untrusted':
    "The signature is cryptographically valid, but the signer's certificate is not on the C2PA trust list, so the signer's identity is not vouched for.",
  'signingCredential.expired':
    'The signing certificate had expired at the time the content was validated.',
  'signingCredential.invalid': 'The signing certificate is invalid.',
  'signingCredential.ocsp.revoked': 'The signing certificate has been revoked by its issuer.',
  'signingCredential.ocsp.skipped':
    'Online certificate-revocation (OCSP) was not checked, so revocation status is unconfirmed.',
  'timeStamp.mismatch': 'The trusted timestamp does not match the signature.',
  'timeStamp.untrusted': 'The signature timestamp is from a timestamp authority that is not trusted.',
  'claim.missing': 'The manifest is missing its claim, the core signed record of provenance.',
  'claim.malformed': 'The manifest claim is malformed and cannot be parsed.',
  'ingredient.manifest.mismatch':
    "An ingredient's credentials do not match the reference recorded in this manifest.",
  'ingredient.manifest.missing': 'An ingredient referenced by this manifest has no recoverable credentials.',
  'algorithm.deprecated': 'The signature uses a cryptographic algorithm that is now deprecated.',
  'algorithm.unsupported': 'The signature uses a cryptographic algorithm this validator does not support.',
  'manifest.unknownProvenance': 'The provenance of this manifest could not be established.',
  'general.error': 'A general validation error occurred while checking this manifest.',
});

/** Classify a code, defaulting unknown codes to a non-fatal warning. */
export function classifyValidationCode(code: string): ValidationCodeEntry {
  return C2PA_VALIDATION_CODES[code] ?? { severity: 'warning', category: 'general' };
}

/**
 * Best human-readable explanation for a status entry: our curated text first,
 * then the engine's own `explanation`, then a humanized form of the code.
 */
export function explainCode(code: string, engineExplanation?: string | null): string {
  if (CODE_EXPLANATIONS[code]) return CODE_EXPLANATIONS[code];
  if (engineExplanation && engineExplanation.trim()) return engineExplanation.trim();
  // Humanize: "assertion.dataHash.mismatch" -> "assertion dataHash mismatch"
  return code.replace(/\./g, ' ');
}
