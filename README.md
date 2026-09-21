# c2pa-mcp

**An MCP server that verifies C2PA Content Credentials and returns an LLM-ready verdict.**

Point any MCP client (Claude Desktop, Claude Code, Cursor, ...) at a local file or a URL and get back a plain-language answer: is this image/video/audio **trusted, valid, tampered, or unsigned**? Who signed it? Is it **AI-generated**? What's its edit history and provenance lineage?

Built by [c2paviewer.com](https://c2paviewer.com). Verification runs locally on the [official C2PA Rust engine](https://github.com/contentauth/c2pa-rs) via `@contentauth/c2pa-node`. Files never leave your machine.

> **Read-only.** This server verifies and inspects Content Credentials. It does not sign or create them.

## Install

No global install needed. Add it to your MCP client config and it runs via `npx`:

```json
{
  "mcpServers": {
    "c2pa": {
      "command": "npx",
      "args": ["-y", "@c2paviewer/c2pa-mcp"]
    }
  }
}
```

- **Claude Desktop**: Settings → Developer → Edit Config, add the block above.
- **Claude Code**: `claude mcp add c2pa -- npx -y @c2paviewer/c2pa-mcp`
- **Cursor / others**: add the same `mcpServers` entry to the client's MCP config.

Requires Node.js 22+ (the `@contentauth/c2pa-node` engine requires it).

> **First run:** the underlying engine (`@contentauth/c2pa-node`) downloads a ~18MB native binary on first install. On a slow connection this can outlast an MCP client's startup timeout — if the very first launch seems to hang, let the download finish and relaunch; subsequent runs are instant.

## Tools

| Tool | What it does |
|------|--------------|
| `verify_c2pa_file` | Verify a local image/video/audio/PDF by path. |
| `verify_c2pa_url` | Download a public https media URL and verify it (SSRF-guarded). |
| `scan_c2pa_directory` | Audit a folder: which files have credentials, their verdict, signer, AI status. |
| `c2pa_info` | Report engine version, supported media types, and trust-list status. |

Each verify tool returns a human-readable summary plus a structured digest:

```jsonc
{
  "verdict": "valid_untrusted",    // trusted | valid_untrusted | valid_trust_unknown | invalid | no_credentials | error
  "summary": "Content Credentials are cryptographically valid, but the signer ... 1 earlier version in its provenance chain failed validation; this file's own signature is unaffected.",
  "signer": { "name": "Example Signer", "trusted": false },
  "aiGenerated": { "isAI": true, "tools": ["DALL-E"], "digitalSourceTypes": ["...trainedAlgorithmicMedia"] },
  "provenance": [
    { "depth": 0, "title": "This file", "relationship": "This file", "verdict": "valid", "manifestLabel": "urn:...", "issues": [] },
    { "depth": 1, "title": "source.jpg", "relationship": "Edited from", "verdict": "invalid", "manifestLabel": "urn:...",
      "issues": [ { "code": "claimSignature.mismatch", "severity": "error", "explanation": "..." } ] }
  ],
  "edits": [ { "label": "Created", "agent": "Photoshop", "when": "...", "detail": "" } ],
  "watermarks": [ { "kind": "synthid", "assertionLabel": "...", "algorithm": "" } ],
  "issues": [ { "code": "signingCredential.untrusted", "severity": "warning",   // THIS file's own problems (plus whatever drove an Invalid verdict)
               "explanation": "The signature is cryptographically valid, but ..." } ],
  "ingredientIssues": [                                                           // problems on earlier versions in the chain
    { "ingredientTitle": "source.jpg", "manifestLabel": "urn:...", "worstSeverity": "error",
      "codes": [ { "code": "claimSignature.mismatch", "severity": "error", "explanation": "..." } ] }
  ],
  "trust": { "evaluated": true, "partial": false, "listSource": "https://.../C2PA-TRUST-LIST.pem, ..." }
}
```

### Provenance chain vs. the file itself

`issues` and `verdict` describe the **active manifest** — this file's own signature and content. Problems found on **ingredients** (earlier versions or components the file was made from) are reported separately in `ingredientIssues` and on the matching `provenance[].issues`, and never change the file's verdict. This follows C2PA 2.2 §15.11 (a validator must report a failing ingredient, but the active manifest keeps its own result) and matches what [CAI Verify](https://verify.contentauthenticity.org) shows. So a file re-signed from a tampered original can legitimately be `trusted` while its lineage shows an `invalid` node — the model should read both.

Pass `"includeRaw": true` to also get the full raw manifest store.

## Trust list

To report a signer as **`trusted`** (not just cryptographically valid), the server checks the signing certificate against the **same five trust inputs c2paviewer.com uses**, **fetched live and cached** (24h TTL) so decisions stay current without a release:

**Official C2PA Conformance Program** (going-forward signers)
- [`C2PA-TRUST-LIST.pem`](https://github.com/c2pa-org/conformance-public) — CA anchors for claim signers
- [`C2PA-TSA-TRUST-LIST.pem`](https://github.com/c2pa-org/conformance-public) — CA anchors for Time-Stamp Authorities (folded into the same anchor bundle; without it valid files can carry `timeStamp.untrusted`)

**CAI Interim Trust List** (frozen Jan 2026, officially temporary, but still the only thing that recognizes pre-conformance signers — Adobe, Leica, Truepic, Canon, Samsung, Fastly, and most real-world content today)
- [`anchors.pem`](https://verify.contentauthenticity.org/trust/anchors.pem) — legacy CA anchors
- [`allowed.sha256.txt`](https://verify.contentauthenticity.org/trust/allowed.sha256.txt) — allow-list of specific end-entity certificate hashes; a signer whose leaf cert is listed is trusted even when nothing chains to an anchor
- [`store.cfg`](https://verify.contentauthenticity.org/trust/store.cfg) — accepted Extended Key Usage OIDs

Without the interim group, mainstream signed content reads as `valid_untrusted`.

If an input can't be fetched, the server **degrades loudly**: with at least one anchor list loaded it still evaluates trust but sets `trust.partial: true` and names the missing input in `trust.reason` (signers recognized only by that input will read as untrusted); with no anchors at all the verdict becomes `valid_trust_unknown` and `trust.evaluated` is `false`. It never silently treats an unknown signer as trusted, and never silently uses a stale snapshot.

Environment overrides:

| Variable | Default | Purpose |
|----------|---------|---------|
| `C2PA_TRUST_LIST_URL` | conformance + TSA + ITL anchors | Comma-separated PEM URLs. Replaces the default anchor set. |
| `C2PA_TRUST_ALLOWED_LIST_URL` | CAI `allowed.sha256.txt` | End-entity allow-list URL. Set to an empty string to disable. |
| `C2PA_TRUST_CONFIG_URL` | CAI `store.cfg` | EKU config URL. Set to an empty string to disable. |
| `C2PA_TRUST_TTL_SECONDS` | `86400` | Cache lifetime for the fetched trust list. |
| `C2PA_MAX_FETCH_BYTES` | `104857600` | Max download size for `verify_c2pa_url` (100 MB). |
| `C2PA_MAX_FILE_BYTES` | `524288000` | Max size of a local file the file/scan tools will verify (500 MB). |
| `C2PA_ALLOWED_ROOTS` | (unset) | Comma/semicolon-separated absolute paths. When set, `verify_c2pa_file` and `scan_c2pa_directory` refuse any path outside these roots. |

## Security

- **Local processing.** Files are read and verified on your machine; nothing is uploaded.
- **SSRF-guarded URL fetching.** `verify_c2pa_url` allows only public `https`, pins the resolved IP against DNS rebinding, re-validates every redirect, sends no cookies or auth, and enforces a content-type allowlist plus size cap.
- **Local path safety.** The file/scan tools reject remote `file://` and UNC paths, resolve symlinks before the allowed-roots check, and return a generic error for inaccessible paths.
- **Set `C2PA_ALLOWED_ROOTS` in any untrusted context.** The file/scan tools expose the host filesystem by design, so a prompt-injected model could point them anywhere. Confining them to a specific directory is the single most important hardening setting.
- **Trust integrity.** Trust lists are fetched over HTTPS (integrity rests on TLS and the upstream sources); the cache is per-user (`0700`/`0600`, ownership-checked) and bound to the configured URL set.

## Limitations

- **Experimental. Not legal evidence.** C2PA tooling and trust infrastructure are still evolving. Do not rely on these verdicts for legal, compliance, or safety-critical decisions.
- **Watermarks are reported as declared, not pixel-verified.** A `synthid` entry means the manifest *declares* a SynthID watermark; confirming the signal in the pixels requires the vendor's detector.
- **AI-generation reflects what the manifest declares** via IPTC `digitalSourceType`. Absence of an AI declaration is not proof the content is not AI-generated.

## Troubleshooting

- **Every verification fails with "Verification engine failed to load".** The native `@contentauth/c2pa-node` binary was interrupted or corrupted during install (common on slow/unreliable connections). Run `c2pa_info` — it reports `engine: FAILED: <reason>` when this happens. Fix: reinstall the dependency (delete `node_modules/@contentauth/c2pa-node` and reinstall, or `npm cache clean --force` then re-run). Checksum/retry hardening of that download lives in the upstream `@contentauth/c2pa-node` postinstall script, which this project doesn't control.
- **`verify_c2pa_url` fails with "timed out after ...ms".** The fetch exceeded `C2PA_FETCH_TIMEOUT_MS` (default 30000). Raise it if you're verifying URLs from a slow host.

## Development

```bash
npm install
npm run build
npm test          # builds, then runs unit + end-to-end tests (network needed for the trust list)
```

## License

Source code is dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.

The test images under [`test/fixtures/`](./test/fixtures/) are redistributed unmodified from [`c2pa-org/public-testfiles`](https://github.com/c2pa-org/public-testfiles) and are licensed separately under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

> Note: if you publish under an unscoped name instead of `@c2paviewer/c2pa-mcp`, change `name` in `package.json` and the `args` in the install block above; nothing else depends on the package name.
