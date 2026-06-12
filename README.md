# c2pa-mcp

**An MCP server that verifies C2PA Content Credentials and returns an LLM-ready verdict.**

Point any MCP client (Claude Desktop, Claude Code, Cursor, ...) at a local file or a URL and get back a plain-language answer: is this image/video/audio **trusted, valid, tampered, or unsigned**? Who signed it? Is it **AI-generated**? What's its edit history and provenance lineage?

Built by [c2paviewer.com](https://c2paviewer.com). Verification runs locally on the [official C2PA Rust engine](https://github.com/contentauth/c2pa-rs) via `@contentauth/c2pa-node`. Files never leave your machine.

> **Read-only.** This server verifies and inspects Content Credentials. It does not sign or create them.

## Why this one

The C2PA standard already has an official, low-level MCP server ([`contentauth/c2pa-mcp`](https://github.com/contentauth/c2pa-mcp), Rust, returns raw manifest JSON). This project is a different tool for a different need:

| | this project | the official `contentauth/c2pa-mcp` |
|---|---|---|
| Install | **`npx`, zero install** | `.mcpb` bundle / cargo build (needs Rust) |
| Output | **digested verdict + plain-English explanations** | raw manifest JSON |
| AI-generation detection | **yes** | no |
| Provenance lineage, edits, watermarks | **yes** | no |
| Trust list | yes (live, conformance) | yes (conformance + ITL) |

If you want raw manifest data straight from the canonical engine, use the official one. If you want an agent to get a **clear verdict it can reason over and cite**, with no toolchain to install, use this one.

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

Requires Node.js 18+.

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
  "verdict": "invalid",            // trusted | valid_untrusted | valid_trust_unknown | invalid | no_credentials
  "summary": "Content Credentials are INVALID: an integrity or signature check failed ...",
  "signer": { "name": "Truepic", "trusted": true },
  "aiGenerated": { "isAI": true, "tools": ["DALL-E"], "digitalSourceTypes": ["...trainedAlgorithmicMedia"] },
  "provenance": [ { "depth": 0, "title": "This file", "relationship": "This file", "verdict": "invalid" } ],
  "edits": [ { "label": "Created", "agent": "Photoshop", "when": "...", "detail": "" } ],
  "watermarks": [ { "kind": "synthid", "assertionLabel": "...", "algorithm": "" } ],
  "issues": [ { "code": "assertion.dataHash.mismatch", "severity": "error",
               "explanation": "The media content was changed after it was signed. ..." } ],
  "trust": { "evaluated": true, "listSource": "https://.../C2PA-TRUST-LIST.pem" }
}
```

Pass `"includeRaw": true` to also get the full raw manifest store.

## Trust list

To report a signer as **`trusted`** (not just cryptographically valid), the server checks the signing certificate against the official [C2PA Conformance trust list](https://github.com/c2pa-org/conformance-public), **fetched live and cached** (24h TTL) so trust decisions stay current without a release.

If the trust list can't be fetched, the server **degrades loudly**: verification still runs, but the verdict becomes `valid_trust_unknown` and `trust.evaluated` is `false` with a reason. It never silently treats an unknown signer as trusted, and never silently uses a stale snapshot.

Environment overrides:

| Variable | Default | Purpose |
|----------|---------|---------|
| `C2PA_TRUST_LIST_URL` | conformance list | Comma-separated PEM URLs. Add the Interim Trust List (ITL) here to verify pre-2026 content. |
| `C2PA_TRUST_TTL_SECONDS` | `86400` | Cache lifetime for the fetched trust list. |
| `C2PA_MAX_FETCH_BYTES` | `104857600` | Max download size for `verify_c2pa_url` (100 MB). |

## Security

- **Local processing.** Files are read and verified on your machine; nothing is uploaded.
- **SSRF-guarded URL fetching.** `verify_c2pa_url` accepts only public `https` URLs, refuses private/loopback/link-local/cloud-metadata hosts, re-validates every redirect hop, sends no cookies or auth, enforces a content-type allowlist (image/video/audio/PDF) and a size cap.

## Limitations

- **Experimental. Not legal evidence.** C2PA tooling and trust infrastructure are still evolving. Do not rely on these verdicts for legal, compliance, or safety-critical decisions.
- **Watermarks are reported as declared, not pixel-verified.** A `synthid` entry means the manifest *declares* a SynthID watermark; confirming the signal in the pixels requires the vendor's detector.
- **AI-generation reflects what the manifest declares** via IPTC `digitalSourceType`. Absence of an AI declaration is not proof the content is not AI-generated.

## Development

```bash
npm install
npm run build
npm test          # builds, then runs unit + end-to-end tests (network needed for the trust list)
```

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.

> Note: if you publish under an unscoped name instead of `@c2paviewer/c2pa-mcp`, change `name` in `package.json` and the `args` in the install block above; nothing else depends on the package name.
