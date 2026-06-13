// The four MCP tool handlers. Each returns a human-readable text block (what the
// model reads) plus structuredContent (the machine-readable digest).

import { readdir, stat } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Digest } from './types.js';
import { verifyAsset } from './engine/verify.js';
import { mimeFromPath, SUPPORTED_MIME_TYPES, EXTENSION_TO_MIME } from './engine/formats.js';
import { trustListStatus } from './engine/trust.js';
import { fetchRemoteAsset, FetchErrorCode } from './net/safeFetch.js';
import { renderSummary } from './render.js';

interface ToolResult {
  content: { type: 'text'; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  // The SDK's CallToolResult carries a string index signature; match it so our
  // handlers are structurally assignable to the registerTool callback return.
  [key: string]: unknown;
}

function ok(text: string, structured?: Record<string, unknown>): ToolResult {
  return { content: [{ type: 'text', text }], ...(structured ? { structuredContent: structured } : {}) };
}

function fail(text: string, structured?: Record<string, unknown>): ToolResult {
  return { content: [{ type: 'text', text }], isError: true, ...(structured ? { structuredContent: structured } : {}) };
}

// Largest file these tools will hand to the native engine. Beyond this the parse
// could hang/OOM the MCP subprocess on a steered path.
const MAX_FILE_BYTES = Number(process.env.C2PA_MAX_FILE_BYTES || 500 * 1024 * 1024);

// Optional path confinement. When set (comma/semicolon-separated absolute roots),
// the file/scan tools refuse any path outside these roots — useful because an
// LLM can be steered into pointing them at arbitrary host paths.
const ALLOWED_ROOTS: string[] = (process.env.C2PA_ALLOWED_ROOTS || '')
  .split(/[,;]/)
  .map((s) => s.trim())
  .filter(Boolean)
  .map((p) => resolve(p));

type PathResult = { ok: true; path: string } | { ok: false; reason: string };

/**
 * Resolve a tool-supplied path safely. Accepts absolute/relative paths and
 * local `file://` URIs, but refuses remote `file://` authorities and UNC paths
 * (which trigger outbound SMB / NTLM-leak on Windows) and enforces C2PA_ALLOWED_ROOTS.
 */
function resolveLocalPath(input: string): PathResult {
  let p = input;
  if (p.startsWith('file://')) {
    let u: URL;
    try {
      u = new URL(p);
    } catch {
      return { ok: false, reason: 'invalid file:// URI' };
    }
    if (u.hostname && u.hostname !== 'localhost') {
      return { ok: false, reason: `refusing file:// URL with a host authority (${u.hostname})` };
    }
    p = fileURLToPath(u);
  }
  // Reject UNC paths (\\server\share or //server/share): opening one egresses to
  // the host over SMB, bypassing every network guard.
  if (/^[\\/]{2}/.test(p)) return { ok: false, reason: 'refusing UNC path' };

  const abs = resolve(p);
  if (ALLOWED_ROOTS.length > 0) {
    const within = ALLOWED_ROOTS.some((root) => abs === root || abs.startsWith(root + sep));
    if (!within) return { ok: false, reason: 'path is outside the allowed roots (C2PA_ALLOWED_ROOTS)' };
  }
  return { ok: true, path: abs };
}

const FETCH_ERROR_HELP: Record<string, string> = {
  [FetchErrorCode.MissingUrl]: 'No URL was provided.',
  [FetchErrorCode.InvalidUrl]: 'The URL is not a valid absolute URL.',
  [FetchErrorCode.MixedContent]: 'Only https URLs are allowed.',
  [FetchErrorCode.PrivateHost]: 'That host is private/internal and cannot be fetched.',
  [FetchErrorCode.TooManyRedirects]: 'The URL redirected too many times.',
  [FetchErrorCode.UnsupportedContentType]:
    'The URL did not return a supported media type (image, video, audio, or PDF).',
  [FetchErrorCode.TooLarge]: 'The file exceeds the maximum fetch size.',
  [FetchErrorCode.UpstreamError]: 'The server returned an error.',
  [FetchErrorCode.FetchFailed]: 'The file could not be downloaded.',
};

// ── verify_c2pa_file ─────────────────────────────────────────────────────────
export async function verifyFileTool(args: { path: string; includeRaw?: boolean }): Promise<ToolResult> {
  const resolved = resolveLocalPath(args.path);
  if (!resolved.ok) return fail(`Cannot verify ${args.path}: ${resolved.reason}`);
  const path = resolved.path;

  let info;
  try {
    info = await stat(path);
  } catch {
    return fail(`File not found: ${path}`);
  }
  if (!info.isFile()) return fail(`Not a file: ${path}`);
  if (info.size > MAX_FILE_BYTES) {
    return fail(`File too large to verify: ${info.size} bytes (limit ${MAX_FILE_BYTES}).`);
  }

  const mimeType = mimeFromPath(path) ?? undefined;
  const digest = await verifyAsset({ path, mimeType }, args.includeRaw);
  const structured = digest as unknown as Record<string, unknown>;
  // Surface an engine failure at the protocol level, not just in the text.
  return digest.verdict === 'error'
    ? fail(renderSummary(digest, path), structured)
    : ok(renderSummary(digest, path), structured);
}

// ── verify_c2pa_url ──────────────────────────────────────────────────────────
export async function verifyUrlTool(args: { url: string; includeRaw?: boolean }): Promise<ToolResult> {
  const fetched = await fetchRemoteAsset(args.url);
  if (!fetched.ok) {
    const help = FETCH_ERROR_HELP[fetched.code] || 'The URL could not be fetched.';
    const detail = fetched.detail ? ` (${fetched.detail})` : '';
    return fail(`Could not fetch ${args.url}: ${help}${detail}`, { verdict: 'error', errorCode: fetched.code });
  }
  const digest = await verifyAsset({ buffer: fetched.buffer, mimeType: fetched.mimeType }, args.includeRaw);
  const structured = digest as unknown as Record<string, unknown>;
  return digest.verdict === 'error'
    ? fail(renderSummary(digest, fetched.finalUrl), structured)
    : ok(renderSummary(digest, fetched.finalUrl), structured);
}

// ── scan_c2pa_directory ──────────────────────────────────────────────────────
interface ScanEntry {
  path: string;
  verdict: Digest['verdict'];
  hasCredentials: boolean;
  signer: string | null;
  aiGenerated: boolean;
}

export async function scanDirectoryTool(args: { directory: string; maxFiles?: number }): Promise<ToolResult> {
  const resolved = resolveLocalPath(args.directory);
  if (!resolved.ok) return fail(`Cannot scan ${args.directory}: ${resolved.reason}`);
  const dir = resolved.path;
  const cap = Math.max(1, Math.min(args.maxFiles ?? 200, 1000));

  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return fail(`Directory not found or unreadable: ${dir}`);
  }

  const candidates = entries.filter((name) => {
    const ext = name.split('.').pop()?.toLowerCase() || '';
    return ext in EXTENSION_TO_MIME;
  });
  const dropped = Math.max(0, candidates.length - cap);
  const toScan = candidates.slice(0, cap);

  const results: ScanEntry[] = [];
  let tooLarge = 0;
  for (const name of toScan) {
    const path = join(dir, name);
    let info;
    try {
      info = await stat(path);
    } catch {
      continue;
    }
    if (!info.isFile()) continue;
    // Skip very large files: verifying hands the path to the native engine, and a
    // directory of huge videos would otherwise hang the whole scan.
    if (info.size > MAX_FILE_BYTES) {
      tooLarge++;
      continue;
    }
    const digest = await verifyAsset({ path, mimeType: mimeFromPath(path) ?? undefined });
    results.push({
      path,
      verdict: digest.verdict,
      // 'error' means the engine couldn't read the file, not that it has credentials.
      hasCredentials: digest.verdict !== 'no_credentials' && digest.verdict !== 'error',
      signer: digest.signer?.name ?? null,
      aiGenerated: digest.aiGenerated.isAI,
    });
  }

  const withCreds = results.filter((r) => r.hasCredentials).length;
  const aiCount = results.filter((r) => r.aiGenerated).length;
  const invalid = results.filter((r) => r.verdict === 'invalid').length;

  const tableLines = results.map(
    (r) =>
      `  ${r.verdict.padEnd(20)} ${r.aiGenerated ? 'AI ' : '   '} ${r.signer ? `[${r.signer}] ` : ''}${r.path}`,
  );
  const skipNotes = [
    dropped ? `${dropped} past the ${cap}-file cap` : '',
    tooLarge ? `${tooLarge} over the size limit` : '',
  ].filter(Boolean);
  const summary =
    `Scanned ${results.length} media file(s) in ${dir}` +
    (skipNotes.length ? ` (skipped: ${skipNotes.join(', ')})` : '') +
    `:\n  with Content Credentials: ${withCreds}\n  AI-declared: ${aiCount}\n  invalid: ${invalid}\n` +
    tableLines.join('\n');

  return ok(summary, {
    directory: dir,
    scanned: results.length,
    skipped: { pastCap: dropped, tooLarge },
    totals: { withCredentials: withCreds, aiDeclared: aiCount, invalid },
    files: results,
  });
}

// ── c2pa_info ────────────────────────────────────────────────────────────────
export async function infoTool(engineVersion: string, serverVersion: string): Promise<ToolResult> {
  const trust = trustListStatus();
  const info = {
    server: '@c2paviewer/c2pa-mcp',
    serverVersion,
    engine: '@contentauth/c2pa-node',
    engineVersion,
    supportedMimeTypes: SUPPORTED_MIME_TYPES,
    trustList: trust,
  };
  const text =
    `c2pa-mcp v${serverVersion} (engine @contentauth/c2pa-node v${engineVersion})\n` +
    `Supported types: ${SUPPORTED_MIME_TYPES.join(', ')}\n` +
    `Trust list: ${trust.urls.join(', ')} (TTL ${trust.ttlSeconds}s, ${trust.cached ? 'cached' : 'not yet fetched'})`;
  return ok(text, info);
}
