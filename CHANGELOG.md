# Changelog

## 0.2.0 — 2026-09-20

Aligns provenance-chain reporting with c2paviewer.com and C2PA 2.2 §15.11.

### Changed (schema)
- `issues` now describes the **active manifest only**. Failures on ingredients no
  longer appear there — previously a re-signed file whose original had a broken
  signature reported `verdict: valid_untrusted` next to `[x] claimSignature.mismatch`,
  which reads as a contradiction.
- New top-level `ingredientIssues[]` (`ingredientTitle`, `manifestLabel`, `codes[]`,
  `worstSeverity`) carries those problems instead.
- `provenance[]` entries gain `manifestLabel` and `issues[]` (always present).
- `summary` appends "N earlier version(s) in its provenance chain failed validation;
  this file's own signature is unaffected." when applicable.
- Rendered text gains a "Provenance chain issues" block and per-node codes.

### Fixed
- Ingredient problems are read from all three shapes c2pa-rs emits: store-level
  `validation_results.ingredientDeltas[]`, per-ingredient `validation_status[]`
  (v1/v2) and the per-ingredient Ingredient V3 `validation_results` wrapper
  (codes at `.activeManifest.failure`, not `.failure`). Delta failures are
  attributed by each failure's own `url`, not `ingredientAssertionURI` (which
  names the parent).
- Node verdicts are graded from the spec code table, not by substring matching
  on the code name. `signingCredential.ocsp.notRevoked` (a passing check) was
  latently gradable as `invalid`.
- Info-severity codes never surface as chain or node issues.
- `timeStamp.untrusted` is no longer described as "the signer is not on the
  C2PA trust list"; only `signingCredential.untrusted` triggers that sentence.

### Dependencies
- `@contentauth/c2pa-node` 0.5.5 → 0.6.3 (pinned). 0.5.5 reported an active
  manifest as `Invalid` when only an Ingredient V3 chain member failed and
  bubbled the ingredient's codes into the store aggregate; 0.6.3 keeps them
  separate, matching the site's verifier.

## 0.1.3 — 2026-07-24
- Detect a broken native engine instead of crashing or misreporting it.
