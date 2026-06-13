// The four MCP tool handlers. Each returns a human-readable text block (what the
// model reads) plus structuredContent (the machine-readable digest).

import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
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

/** Accept absolute/relative paths and file:// URIs. */
function resolveLocalPath(input: string): string {
  if (input.startsWith('file://')) return fileURLToPath(input);
  return input;
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
  const path = resolveLocalPath(args.path);
  let info;
  try {
    info = await stat(path);
  } catch {
    return fail(`File not found: ${path}`);
  }
  if (!info.isFile()) return fail(`Not a file: ${path}`);

  const mimeType = mimeFromPath(path) ?? undefined;
  const digest = await verifyAsset({ path, mimeType }, args.includeRaw);
  return ok(renderSummary(digest, path), digest as unknown as Record<string, unknown>);
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
  return ok(renderSummary(digest, fetched.finalUrl), digest as unknown as Record<string, unknown>);
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
  const dir = resolveLocalPath(args.directory);
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
  const maxBytes = Number(process.env.C2PA_MAX_SCAN_FILE_BYTES || 500 * 1024 * 1024);

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
    if (info.size > maxBytes) {
      tooLarge++;
      continue;
    }
    const digest = await verifyAsset({ path, mimeType: mimeFromPath(path) ?? undefined });
    results.push({
      path,
      verdict: digest.verdict,
      hasCredentials: digest.verdict !== 'no_credentials',
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
