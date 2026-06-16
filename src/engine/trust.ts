// Trust-list manager: fetch the C2PA trust anchors live, cache them with a TTL,
// and build the settings object that makes the engine report "Trusted" signers.
//
// Design choices (confirmed with the project owner):
//  - Fetched live so trust decisions track the canonical list without a release.
//  - Cached in memory for the process and on disk (TTL) so short-lived `npx`
//    invocations don't refetch on every call.
//  - DEGRADE LOUDLY: if the list can't be fetched and no in-TTL cache exists,
//    verification still runs but the digest reports trust was not evaluated.
//    We never silently fall back to a stale snapshot.

import { mkdir, open, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createTrustSettings, createVerifySettings, mergeSettings, settingsToJson } from '@contentauth/c2pa-node';
import type { TrustInfo } from '../types.js';
import { validateUrl, ssrfDispatcher } from '../net/safeFetch.js';

// Default trust anchors: the official C2PA Conformance Program list (going-forward
// signers) PLUS the legacy CAI Interim Trust List. The ITL was frozen in Jan 2026,
// but it is still the only list that recognizes pre-conformance signers — Adobe,
// Leica, Truepic, Canon, Samsung, and most real-world content in circulation today.
// Without it, mainstream signed content reads as valid-but-untrusted. Override or
// extend with the comma-separated C2PA_TRUST_LIST_URL env var.
const DEFAULT_TRUST_LIST_URLS = [
  'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem',
  'https://verify.contentauthenticity.org/trust/anchors.pem',
];

const TRUST_LIST_URLS: string[] = (process.env.C2PA_TRUST_LIST_URL || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const URLS = TRUST_LIST_URLS.length > 0 ? TRUST_LIST_URLS : DEFAULT_TRUST_LIST_URLS;

const TTL_SECONDS = Number(process.env.C2PA_TRUST_TTL_SECONDS || 24 * 60 * 60);
const FETCH_TIMEOUT_MS = Number(process.env.C2PA_TRUST_FETCH_TIMEOUT_MS || 15000);
const MAX_TRUST_FETCH_HOPS = 3;
// A PEM trust bundle is tens of KB; cap the body so a hostile/misconfigured URL
// can't stream an unbounded response into memory.
const MAX_TRUST_BYTES = Number(process.env.C2PA_MAX_TRUST_BYTES || 10 * 1024 * 1024);

// A per-USER cache dir, not shared /tmp. The trust list defines who is "trusted",
// so a world-writable cache an attacker could pre-seed would let them flip assets
// to `trusted`. Under the user's home, plus 0700 perms and an ownership check on
// read, the cache cannot be planted by another local user.
const CACHE_DIR = join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'c2pa-mcp');
const CACHE_FILE = join(CACHE_DIR, 'trust-anchors.pem');
const CACHE_META = join(CACHE_DIR, 'trust-anchors.meta.json');

export interface TrustSettings {
  /** A settings JSON string for Reader.fromAsset, or undefined to verify without trust. */
  settingsJson: string | undefined;
  info: TrustInfo;
}

// Process-lifetime memo so repeated verifications in one run don't re-read disk.
// `loaded` is the subset of URLS whose fetch actually succeeded, so trust info
// reports what was really applied rather than the full configured set.
let memo: { pem: string; fetchedAtMs: number; loaded: string[] } | null = null;

function nowMs(): number {
  return Date.now();
}

async function readDiskCache(): Promise<{ pem: string; fetchedAtMs: number; loaded: string[] } | null> {
  let fh: Awaited<ReturnType<typeof open>> | undefined;
  try {
    fh = await open(CACHE_FILE, 'r');
    // On POSIX, refuse a cache file we don't own or that others can write — it
    // could have been planted to inject a rogue trust anchor. fstat the OPEN fd
    // (not the path) and read from the same fd, so there's no TOCTOU window.
    if (process.platform !== 'win32' && typeof process.getuid === 'function') {
      const st = await fh.stat();
      if (st.uid !== process.getuid()) return null;
      if ((st.mode & 0o022) !== 0) return null; // group/other writable
    }
    const pem = await fh.readFile('utf8');
    const metaRaw = await readFile(CACHE_META, 'utf8');
    const meta = JSON.parse(metaRaw) as { fetchedAtMs?: number; urls?: string[]; loaded?: string[] };
    if (!pem.trim() || typeof meta.fetchedAtMs !== 'number') return null;
    // Bind the cache to the exact configured URL set: a cache built for a
    // different trust-list config must not be reused.
    if (!Array.isArray(meta.urls) || meta.urls.join('\n') !== URLS.join('\n')) return null;
    // `loaded` records which URLs actually contributed anchors. Older caches
    // without it fall back to the full configured set.
    const loaded = Array.isArray(meta.loaded) ? meta.loaded : URLS;
    return { pem, fetchedAtMs: meta.fetchedAtMs, loaded };
  } catch {
    return null;
  } finally {
    await fh?.close().catch(() => {});
  }
}

async function writeDiskCache(pem: string, fetchedAtMs: number, loaded: string[]): Promise<void> {
  try {
    await mkdir(CACHE_DIR, { recursive: true, mode: 0o700 });
    await writeFile(CACHE_FILE, pem, { encoding: 'utf8', mode: 0o600 });
    await writeFile(CACHE_META, JSON.stringify({ fetchedAtMs, urls: URLS, loaded }), {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch {
    // A non-writable cache dir is non-fatal; we just lose cross-process caching.
  }
}

function isFresh(fetchedAtMs: number): boolean {
  return nowMs() - fetchedAtMs < TTL_SECONDS * 1000;
}

async function fetchPem(rawUrl: string): Promise<string> {
  // The trust-list URL is operator-supplied (env var). Apply the same SSRF
  // discipline as the URL tool: https + public host only, and re-validate every
  // redirect hop, so a misconfigured or hostile URL can't be bounced to an
  // internal/metadata endpoint and have its response trusted as anchors.
  let v = validateUrl(rawUrl);
  if (!v.ok) throw new Error(`unsafe trust-list URL (${v.code})`);
  let url = v.url;

  for (let hop = 0; ; hop++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        redirect: 'manual',
        dispatcher: ssrfDispatcher,
      } as RequestInit & { dispatcher: unknown });
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {}); // release the connection before the next hop
        const location = res.headers.get('location');
        if (!location || hop >= MAX_TRUST_FETCH_HOPS) throw new Error('too many redirects');
        const next = validateUrl(new URL(location, url).toString());
        if (!next.ok) throw new Error(`unsafe redirect (${next.code})`);
        url = next.url;
        continue;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      if (Number(res.headers.get('content-length') || 0) > MAX_TRUST_BYTES) {
        await res.body?.cancel().catch(() => {});
        throw new Error('trust list too large');
      }
      const text = await res.text();
      if (text.length > MAX_TRUST_BYTES) throw new Error('trust list too large');
      if (!text.includes('BEGIN CERTIFICATE')) throw new Error('response is not PEM');
      return text;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Fetch all configured trust-list URLs and concatenate the successful ones.
 * Returns the combined PEM plus `loaded` — the URLs that actually contributed —
 * so the caller can report partial evaluation honestly. Throws if none load.
 */
async function fetchAllPems(): Promise<{ pem: string; loaded: string[] }> {
  const results = await Promise.allSettled(URLS.map(fetchPem));
  const pems: string[] = [];
  const loaded: string[] = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      pems.push(r.value);
      loaded.push(URLS[i]);
    }
  });
  if (pems.length === 0) throw new Error('all trust-list fetches failed');
  return { pem: pems.join('\n'), loaded };
}

/**
 * Build the trust info for a successful (possibly partial) evaluation. Pure and
 * exported so the partial-reporting logic is unit-testable without the network.
 * `listSource` reflects only the lists that loaded — never the full configured
 * set when some failed — and `partial` plus `reason` name what is missing.
 */
export function trustInfoFor(loaded: string[], configured: string[]): TrustInfo {
  const partial = loaded.length < configured.length;
  const info: TrustInfo = { evaluated: true, listSource: loaded.join(', '), partial };
  if (partial) {
    const missing = configured.filter((u) => !loaded.includes(u));
    info.reason = `Only ${loaded.length} of ${configured.length} configured trust lists loaded; missing: ${missing.join(', ')}.`;
  }
  return info;
}

function buildSettingsJson(pem: string): string {
  // settingsToJson converts the camelCase SettingsContext into the snake_case
  // JSON the underlying c2pa-rs engine expects.
  return settingsToJson(
    mergeSettings(
      createTrustSettings({ verifyTrustList: true, trustAnchors: pem }),
      createVerifySettings({ verifyTrust: true, verifyAfterReading: true, ocspFetch: false }),
    ),
  );
}

/**
 * Resolve trust settings for a verification. Uses the in-memory memo, then the
 * disk cache (if within TTL), then a live fetch. On total failure, degrades
 * loudly: returns no trust settings and an info object explaining why.
 */
export async function getTrustSettings(): Promise<TrustSettings> {
  // 1. Memory memo within TTL.
  if (memo && isFresh(memo.fetchedAtMs)) {
    return { settingsJson: buildSettingsJson(memo.pem), info: trustInfoFor(memo.loaded, URLS) };
  }

  // 2. Disk cache within TTL.
  const disk = await readDiskCache();
  if (disk && isFresh(disk.fetchedAtMs)) {
    memo = disk;
    return { settingsJson: buildSettingsJson(disk.pem), info: trustInfoFor(disk.loaded, URLS) };
  }

  // 3. Live fetch.
  try {
    const { pem, loaded } = await fetchAllPems();
    const fetchedAtMs = nowMs();
    memo = { pem, fetchedAtMs, loaded };
    await writeDiskCache(pem, fetchedAtMs, loaded);
    return { settingsJson: buildSettingsJson(pem), info: trustInfoFor(loaded, URLS) };
  } catch (err) {
    // Degrade loudly: verify without trust, and say so.
    const reason = `Trust list could not be fetched (${(err as Error).message}); signer trust was not evaluated.`;
    return { settingsJson: undefined, info: { evaluated: false, listSource: null, reason } };
  }
}

/** Lightweight status for the c2pa_info tool, without forcing a fetch. */
export function trustListStatus(): {
  urls: string[];
  ttlSeconds: number;
  cached: boolean;
  loaded: string[] | null;
} {
  const cached = !!(memo && isFresh(memo.fetchedAtMs));
  // `loaded` is only known once something has been fetched/cached this process;
  // null means "not yet evaluated", distinct from "evaluated, zero loaded".
  return { urls: URLS, ttlSeconds: TTL_SECONDS, cached, loaded: cached ? memo!.loaded : null };
}
