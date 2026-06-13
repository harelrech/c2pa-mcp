// SSRF-hardened remote fetch for the verify_c2pa_url tool.
//
// An LLM can be steered (by a malicious page or user) into asking this tool to
// fetch an internal address. These guards ensure the tool only ever retrieves a
// public https image/video/audio/pdf, never localhost, cloud metadata, or other
// private hosts. Ported from c2paviewer.com's URL-inspection proxy.

import { lookup as dnsLookup } from 'node:dns';
import { Agent } from 'undici';

const MAX_URL_FETCH_BYTES = Number(process.env.C2PA_MAX_FETCH_BYTES || 100 * 1024 * 1024); // 100 MB
const MAX_REDIRECT_HOPS = 3;
const FETCH_TIMEOUT_MS = Number(process.env.C2PA_FETCH_TIMEOUT_MS || 30000);

// The strongest anti-open-relay control: only relay bytes that claim to be a
// supported media type. Anything else (text/html, application/*, ...) is refused.
const ALLOWED_CONTENT_TYPE = /^(image|video|audio)\/|^application\/pdf\b/i;

export enum FetchErrorCode {
  MissingUrl = 'missing_url',
  InvalidUrl = 'invalid_url',
  MixedContent = 'mixed_content',
  PrivateHost = 'private_host',
  TooManyRedirects = 'too_many_redirects',
  UnsupportedContentType = 'unsupported_content_type',
  TooLarge = 'too_large',
  UpstreamError = 'upstream_error',
  FetchFailed = 'fetch_failed',
}

export type ValidateUrlResult = { ok: true; url: URL } | { ok: false; code: FetchErrorCode };

function parseIpv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  return octets as [number, number, number, number];
}

function isPrivateIpv4(host: string): boolean {
  const octets = parseIpv4(host);
  if (!octets) return false;
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10/8 private
  if (a === 127) return true; // 127/8 loopback
  if (a === 169 && b === 254) return true; // 169.254/16 link-local (incl. cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 private
  if (a === 192 && b === 168) return true; // 192.168/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 benchmark
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved
  return false;
}

/** Expand an IPv6 string into its 8 hextets (numbers), or null if it isn't valid. */
function expandIpv6(host: string): number[] | null {
  let h = host.toLowerCase().split('%')[0]; // strip any zone id
  if (!h.includes(':')) return null;
  // Fold a trailing embedded IPv4 (e.g. ::ffff:127.0.0.1) into two hextets.
  const m = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const o = [Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])];
    if (o.some((x) => x > 255)) return null;
    h = `${m[1]}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = h.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => (g === '' ? NaN : parseInt(g, 16)));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

function pairToIpv4(hi: number, lo: number): string {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * True if an IPv6 literal is private/reserved or embeds a private IPv4. Works on a
 * numeric expansion so it can't be evaded by compressed/expanded/zero-run forms or
 * by the position of an embedded v4 address.
 */
function isPrivateIpv6(host: string): boolean {
  const x = expandIpv6(host);
  if (!x) return false;
  const top5Zero = x[0] === 0 && x[1] === 0 && x[2] === 0 && x[3] === 0 && x[4] === 0;
  if (x.every((n) => n === 0)) return true; // :: unspecified
  if (top5Zero && x[5] === 0 && x[6] === 0 && x[7] === 1) return true; // ::1 loopback
  if (x[0] >= 0xfc00 && x[0] <= 0xfdff) return true; // ULA fc00::/7
  if (x[0] >= 0xfe80 && x[0] <= 0xfebf) return true; // link-local fe80::/10
  if (x[0] >= 0xfec0 && x[0] <= 0xfeff) return true; // site-local fec0::/10 (deprecated)
  if (x[0] >= 0xff00) return true; // multicast ff00::/8
  // IPv4-mapped ::ffff:a.b.c.d
  if (top5Zero && x[5] === 0xffff) return isPrivateIpv4(pairToIpv4(x[6], x[7]));
  // IPv4-compatible ::a.b.c.d (deprecated), excluding :: and ::1
  if (top5Zero && x[5] === 0 && (x[6] !== 0 || x[7] > 1)) return isPrivateIpv4(pairToIpv4(x[6], x[7]));
  // 6to4 2002::/16 embeds the v4 in hextets 1-2
  if (x[0] === 0x2002) return isPrivateIpv4(pairToIpv4(x[1], x[2]));
  // NAT64 64:ff9b::/96 embeds the v4 in the last two hextets
  if (x[0] === 0x0064 && x[1] === 0xff9b) return isPrivateIpv4(pairToIpv4(x[6], x[7]));
  return false;
}

/** True if the host must never be fetched (private/reserved/loopback/internal). */
export function isPrivateOrReservedHost(host: string): boolean {
  if (!host) return true;
  let h = host.toLowerCase().trim();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (isPrivateIpv4(h)) return true;
  if (h.includes(':') && isPrivateIpv6(h)) return true;
  return false;
}

/** Validate a raw URL string: https only, public host only. */
export function validateUrl(rawUrl: string | null | undefined): ValidateUrlResult {
  if (!rawUrl || !rawUrl.trim()) return { ok: false, code: FetchErrorCode.MissingUrl };
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    return { ok: false, code: FetchErrorCode.InvalidUrl };
  }
  // https only: rejects http:, data:, blob:, file:, ftp: in one move.
  if (url.protocol !== 'https:') return { ok: false, code: FetchErrorCode.MixedContent };
  if (isPrivateOrReservedHost(url.hostname)) return { ok: false, code: FetchErrorCode.PrivateHost };
  return { ok: true, url };
}

export function isAllowedContentType(contentType: string | null | undefined): boolean {
  if (!contentType) return false;
  return ALLOWED_CONTENT_TYPE.test(contentType.split(';')[0].trim());
}

// ── DNS-pinned dispatcher ───────────────────────────────────────────────────
// validateUrl only inspects the hostname STRING, but fetch() re-resolves DNS at
// connect time, so a public name that resolves to a private/metadata IP (e.g.
// 169.254.169.254.nip.io) would slip through. This connection-time lookup
// resolves the name ourselves, rejects if ANY resolved address is private, and
// pins the connection to the vetted result — which also closes DNS rebinding,
// since the same resolution is what the socket uses. Applied on every hop.
type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address?: string | { address: string; family: number }[],
  family?: number,
) => void;

function safeLookup(
  hostname: string,
  options: { all?: boolean } & Record<string, unknown>,
  callback: LookupCallback,
): void {
  dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err);
    for (const a of addresses) {
      // isPrivateIpv6 expands non-canonical forms itself, so raw resolver output
      // (e.g. a fully-expanded address) is matched correctly.
      const blocked = a.family === 6 ? isPrivateIpv6(a.address) : isPrivateIpv4(a.address);
      if (blocked) {
        const e: NodeJS.ErrnoException = new Error(`blocked private address ${a.address} for ${hostname}`);
        e.code = 'EAI_BLOCKED';
        return callback(e);
      }
    }
    if (options && options.all) callback(null, addresses);
    else callback(null, addresses[0].address, addresses[0].family);
  });
}

/** Shared dispatcher that validates and pins every outbound connection's DNS. */
export const ssrfDispatcher = new Agent({ connect: { lookup: safeLookup as never } });

export type FetchAssetResult =
  | { ok: true; buffer: Buffer; mimeType: string; finalUrl: string }
  | { ok: false; code: FetchErrorCode; detail?: string };

/** Read the body with a hard size cap, aborting as soon as the cap is exceeded. */
async function readCapped(res: Response): Promise<Buffer | null> {
  const lenHeader = Number(res.headers.get('content-length') || 0);
  if (lenHeader && lenHeader > MAX_URL_FETCH_BYTES) return null;
  if (!res.body) {
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.byteLength > MAX_URL_FETCH_BYTES ? null : buf;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > MAX_URL_FETCH_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks);
}

/**
 * Fetch a remote asset safely: validate every hop, never send cookies/auth,
 * enforce the content-type allowlist and size cap. Returns the bytes + MIME.
 */
export async function fetchRemoteAsset(rawUrl: string): Promise<FetchAssetResult> {
  let current = validateUrl(rawUrl);
  if (!current.ok) return { ok: false, code: current.code };

  let url = current.url;
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    const ctrl = new AbortController();
    // One timeout budget covers the whole hop INCLUDING the body read, so a slow-
    // drip server that trickles bytes is aborted rather than held open against the
    // size cap. The timer is cleared in `finally` once the hop fully resolves.
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      let res: Response;
      try {
        res = await fetch(url, {
          signal: ctrl.signal,
          redirect: 'manual', // we re-validate each hop ourselves
          dispatcher: ssrfDispatcher, // resolve-validate-pin DNS at connect time
          headers: { accept: 'image/*,video/*,audio/*,application/pdf', 'user-agent': 'c2pa-mcp' },
        } as RequestInit & { dispatcher: unknown });
      } catch (err) {
        return { ok: false, code: FetchErrorCode.FetchFailed, detail: (err as Error).message };
      }

      // Manual redirect: re-validate the Location before following.
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {}); // release the connection before the next hop
        const location = res.headers.get('location');
        if (!location) return { ok: false, code: FetchErrorCode.UpstreamError, detail: 'redirect without location' };
        if (hop === MAX_REDIRECT_HOPS) return { ok: false, code: FetchErrorCode.TooManyRedirects };
        const next = validateUrl(new URL(location, url).toString());
        if (!next.ok) return { ok: false, code: next.code };
        url = next.url;
        continue;
      }

      if (!res.ok) return { ok: false, code: FetchErrorCode.UpstreamError, detail: `HTTP ${res.status}` };

      const contentType = res.headers.get('content-type');
      if (!isAllowedContentType(contentType)) {
        return { ok: false, code: FetchErrorCode.UnsupportedContentType, detail: contentType || 'none' };
      }

      let buffer: Buffer | null;
      try {
        buffer = await readCapped(res);
      } catch (err) {
        // Abort (timeout) or stream error during the body read.
        return { ok: false, code: FetchErrorCode.FetchFailed, detail: `body read failed: ${(err as Error).message}` };
      }
      if (!buffer) return { ok: false, code: FetchErrorCode.TooLarge };

      return { ok: true, buffer, mimeType: (contentType as string).split(';')[0].trim(), finalUrl: url.toString() };
    } finally {
      clearTimeout(timer);
    }
  }

  return { ok: false, code: FetchErrorCode.TooManyRedirects };
}
