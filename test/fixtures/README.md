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

## License

These fixture images are redistributed **unmodified** (renamed only) from
[`c2pa-org/public-testfiles`](https://github.com/c2pa-org/public-testfiles) and are
licensed under [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).
This license applies to the image files in this directory only; all source code in
this repository is licensed under MIT OR Apache-2.0 (see the repository root).
