# Test fixtures

These images come from the public [`c2pa-org/public-testfiles`](https://github.com/c2pa-org/public-testfiles)
set (the `adobe-20220124-*` series), renamed by the behavior they exercise:

| File | Origin | Expected verdict |
|------|--------|------------------|
| `no-credentials.jpg` | `adobe-20220124-A.jpg` | `no_credentials` |
| `valid-untrusted.jpg` | `adobe-20220124-CA.jpg` | `valid_untrusted` (test signer, not on the trust list) |
| `valid-deep-chain.jpg` | `adobe-20220124-CACAICAICICA.jpg` | `valid_untrusted`, multi-generation provenance |
| `invalid-signature.jpg` | `adobe-20220124-E-sig-CA.jpg` | `invalid` (`claimSignature.mismatch`) |
| `invalid-datahash.jpg` | `adobe-20220124-E-dat-CA.jpg` | `invalid` (`assertion.dataHash.mismatch`) |

They are signed with C2PA test certificates that are intentionally not on the
production trust list, so a fully valid file reports `valid_untrusted` rather than
`trusted`.
