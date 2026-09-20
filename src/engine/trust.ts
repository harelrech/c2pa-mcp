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

import { mkdir, open, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { TrustInfo } from '../types.js';
import { validateUrl, ssrfDispatcher } from '../net/safeFetch.js';
import { requireEngine } from './engine.js';

// Trust inputs — the same five c2paviewer.com feeds its verifier
// (c2pa-viewer/app/utils/trustAnchors.ts), so the MCP and the site agree on who
// is "trusted". They come in two groups:
//
// Official C2PA Conformance Program (going-forward signers):
//   - C2PA-TRUST-LIST.pem      CA anchors for claim signers
//   - C2PA-TSA-TRUST-LIST.pem  CA anchors for Time-Stamp Authorities. c2pa-node
//                              has no separate TSA slot, so it is folded into the
//                              same anchors bundle — exactly as the site does.
//
// CAI Interim Trust List (frozen Jan 2026, officially temporary, but still the
// only thing that recognizes pre-conformance signers — Adobe, Leica, Truepic,
// Canon, Samsung, Fastly, and most real-world content in circulation today):
//   - anchors.pem              legacy CA anchors
//   - allowed.sha256.txt       allow-list of specific END-ENTITY cert hashes; a
//                              signer whose leaf is listed is trusted even when
//                              nothing chains to an anchor (this is what makes
//                              e.g. Fastly read Trusted)
//   - store.cfg                accepted Extended Key Usage OIDs
//
// Without the interim group, mainstream signed content reads valid-but-untrusted.
// When the interim list is retired, delete that group here and in README.md.
const DEFAULT_ANCHOR_URLS = [
  'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem',
  'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem',
  'https://verify.contentauthenticity.org/trust/anchors.pem',
];
const DEFAULT_ALLOWED_LIST_URL = 'https://verify.contentauthenticity.org/trust/allowed.sha256.txt';
const DEFAULT_TRUST_CONFIG_URL = 'https://verify.contentauthenticity.org/trust/store.cfg';

const envList = (name: string): string[] =>
  (process.env[name] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

// C2PA_TRUST_LIST_URL replaces the anchor set. C2PA_TRUST_ALLOWED_LIST_URL and
// C2PA_TRUST_CONFIG_URL replace their single default; set either to the empty
// string to disable that input (an unset var keeps the default).
const ANCHOR_URLS = envList('C2PA_TRUST_LIST_URL');
const URLS = ANCHOR_URLS.length > 0 ? ANCHOR_URLS : DEFAULT_ANCHOR_URLS;
const ALLOWED_LIST_URL =
  process.env.C2PA_TRUST_ALLOWED_LIST_URL === undefined
    ? DEFAULT_ALLOWED_LIST_URL
    : process.env.C2PA_TRUST_ALLOWED_LIST_URL.trim() || null;
const TRUST_CONFIG_URL =
  process.env.C2PA_TRUST_CONFIG_URL === undefined
    ? DEFAULT_TRUST_CONFIG_URL
    : process.env.C2PA_TRUST_CONFIG_URL.trim() || null;

/** Every configured input, in a stable order, for cache binding and reporting. */
const ALL_URLS: string[] = [...URLS, ...(ALLOWED_LIST_URL ? [ALLOWED_LIST_URL] : []), ...(TRUST_CONFIG_URL ? [TRUST_CONFIG_URL] : [])];

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
// One bundle file holds every input so they can never go out of step with each
// other (a fresh anchors file next to a stale allow-list would be a silent
// trust change). The v1 `trust-anchors.pem` cache is simply ignored.
const CACHE_FILE = join(CACHE_DIR, 'trust-bundle.json');

export interface TrustSettings {
  /** A settings JSON string for Reader.fromAsset, or undefined to verify without trust. */
  settingsJson: string | undefined;
  info: TrustInfo;
}

/** The fetched trust inputs. Empty string / null means "not loaded". */
interface TrustBundle {
  pem: string;
  allowedList: string | null;
  trustConfig: string | null;
  fetchedAtMs: number;
  /** The subset of ALL_URLS whose fetch actually succeeded. */
  loaded: string[];
}

// Process-lifetime memo so repeated verifications in one run don't re-read disk.
// `loaded` is the subset of ALL_URLS whose fetch actually succeeded, so trust info
// reports what was really applied rather than the full configured set.
let memo: TrustBundle | null = null;

function nowMs(): number {
  return Date.now();
}

async function readDiskCache(): Promise<TrustBundle | null> {
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
    const raw = JSON.parse(await fh.readFile('utf8')) as Partial<TrustBundle> & { urls?: string[] };
    if (typeof raw.pem !== 'string' || !raw.pem.trim() || typeof raw.fetchedAtMs !== 'number') return null;
    // Bind the cache to the exact configured input set: a cache built for a
    // different trust config must not be reused.
    if (!Array.isArray(raw.urls) || raw.urls.join('\n') !== ALL_URLS.join('\n')) return null;
    if (!Array.isArray(raw.loaded)) return null;
    return {
      pem: raw.pem,
      allowedList: typeof raw.allowedList === 'string' ? raw.allowedList : null,
      trustConfig: typeof raw.trustConfig === 'string' ? raw.trustConfig : null,
      fetchedAtMs: raw.fetchedAtMs,
      loaded: raw.loaded,
    };
  } catch {
    return null;
  } finally {
    await fh?.close().catch(() => {});
  }
}

async function writeDiskCache(bundle: TrustBundle): Promise<void> {
  try {
    await mkdir(CACHE_DIR, { recursive: true, mode: 0o700 });
    await writeFile(CACHE_FILE, JSON.stringify({ ...bundle, urls: ALL_URLS }), { encoding: 'utf8', mode: 0o600 });
  } catch {
    // A non-writable cache dir is non-fatal; we just lose cross-process caching.
  }
}

function isFresh(fetchedAtMs: number): boolean {
  return nowMs() - fetchedAtMs < TTL_SECONDS * 1000;
}

type TrustInputKind = 'anchors' | 'allowedList' | 'trustConfig';

// Each input gets a shape check so a wrong/hijacked URL can't be silently fed
// to the engine as trust material.
function validateTrustText(kind: TrustInputKind, text: string): void {
  if (kind === 'anchors' && !text.includes('BEGIN CERTIFICATE')) throw new Error('response is not PEM');
  if (kind === 'allowedList') {
    // One SHA-256 per line, base64 (44 chars, '=' padded) as CAI publishes it,
    // or hex (64 chars); '#' comments allowed. Must contain at least one hash.
    const ok = text
      .split('\n')
      .some((l) => /^(?:[A-Za-z0-9+/]{43}=|[0-9a-fA-F]{64})\s*$/.test(l.trim()));
    if (!ok) throw new Error('response is not a sha256 allow-list');
  }
  if (kind === 'trustConfig') {
    // Dotted OIDs per line; comments allowed.
    const ok = text.split('\n').some((l) => /^\d+(\.\d+)+\s*$/.test(l.trim()));
    if (!ok) throw new Error('response is not an EKU config');
  }
}

async function fetchTrustText(rawUrl: string, kind: TrustInputKind): Promise<string> {
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
      validateTrustText(kind, text);
      return text;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Fetch every configured input and keep the successful ones. Anchors are
 * concatenated; the allow-list and EKU config are single documents. `loaded`
 * records which URLs actually contributed so the caller can report partial
 * evaluation honestly. Throws only if NO anchors loaded — an allow-list or
 * config alone can't establish trust.
 */
async function fetchBundle(): Promise<TrustBundle> {
  const [anchorResults, allowedResult, configResult] = await Promise.all([
    Promise.allSettled(URLS.map((u) => fetchTrustText(u, 'anchors'))),
    ALLOWED_LIST_URL ? fetchTrustText(ALLOWED_LIST_URL, 'allowedList').then((v) => v, () => null) : Promise.resolve(null),
    TRUST_CONFIG_URL ? fetchTrustText(TRUST_CONFIG_URL, 'trustConfig').then((v) => v, () => null) : Promise.resolve(null),
  ]);
  const pems: string[] = [];
  const loaded: string[] = [];
  anchorResults.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      pems.push(r.value);
      loaded.push(URLS[i]);
    }
  });
  if (pems.length === 0) throw new Error('all trust-anchor fetches failed');
  if (ALLOWED_LIST_URL && allowedResult !== null) loaded.push(ALLOWED_LIST_URL);
  if (TRUST_CONFIG_URL && configResult !== null) loaded.push(TRUST_CONFIG_URL);
  return { pem: pems.join('\n'), allowedList: allowedResult, trustConfig: configResult, fetchedAtMs: nowMs(), loaded };
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
    info.reason = `Only ${loaded.length} of ${configured.length} configured trust inputs loaded; missing: ${missing.join(', ')}. Signers recognized only by a missing input will read as untrusted.`;
  }
  return info;
}

async function buildSettingsJson(bundle: TrustBundle): Promise<string> {
  // settingsToJson converts the camelCase SettingsContext into the snake_case
  // JSON the underlying c2pa-rs engine expects.
  const engine = await requireEngine();
  return engine.settingsToJson(
    engine.mergeSettings(
      engine.createTrustSettings({
        verifyTrustList: true,
        trustAnchors: bundle.pem,
        allowedList: bundle.allowedList || undefined,
        trustConfig: bundle.trustConfig || undefined,
      }),
      engine.createVerifySettings({ verifyTrust: true, verifyAfterReading: true, ocspFetch: false }),
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
    return { settingsJson: await buildSettingsJson(memo), info: trustInfoFor(memo.loaded, ALL_URLS) };
  }

  // 2. Disk cache within TTL.
  const disk = await readDiskCache();
  if (disk && isFresh(disk.fetchedAtMs)) {
    memo = disk;
    return { settingsJson: await buildSettingsJson(disk), info: trustInfoFor(disk.loaded, ALL_URLS) };
  }

  // 3. Live fetch.
  try {
    const bundle = await fetchBundle();
    memo = bundle;
    await writeDiskCache(bundle);
    return { settingsJson: await buildSettingsJson(bundle), info: trustInfoFor(bundle.loaded, ALL_URLS) };
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
  return { urls: ALL_URLS, ttlSeconds: TTL_SECONDS, cached, loaded: cached ? memo!.loaded : null };
}
