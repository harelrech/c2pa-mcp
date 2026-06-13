// SSRF guard unit tests. No network required (pure validation logic).
// Run after `npm run build`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateUrl,
  isPrivateOrReservedHost,
  isAllowedContentType,
  FetchErrorCode,
} from '../dist/net/safeFetch.js';

test('rejects non-https schemes', () => {
  assert.equal(validateUrl('http://example.com/a.jpg').code, FetchErrorCode.MixedContent);
  assert.equal(validateUrl('file:///etc/passwd').code, FetchErrorCode.MixedContent);
  assert.equal(validateUrl('data:image/png;base64,AAAA').code, FetchErrorCode.MixedContent);
});

test('rejects empty and malformed URLs', () => {
  assert.equal(validateUrl('').code, FetchErrorCode.MissingUrl);
  assert.equal(validateUrl('   ').code, FetchErrorCode.MissingUrl);
  assert.equal(validateUrl('not a url').code, FetchErrorCode.InvalidUrl);
});

test('rejects private, loopback, and metadata hosts', () => {
  for (const host of [
    'localhost',
    'foo.localhost',
    'service.internal',
    'printer.local',
    '127.0.0.1',
    '10.0.0.5',
    '192.168.1.1',
    '172.16.0.1',
    '169.254.169.254', // cloud metadata
    '[::1]',
    '[fc00::1]',
    '[fe80::1]',
    '[::ffff:127.0.0.1]', // IPv4-mapped, dotted form
    '[::ffff:7f00:1]', // IPv4-mapped, hex form (how the URL parser normalizes 127.0.0.1)
    '[::ffff:10.0.0.1]', // IPv4-mapped private
    '[::ffff:a9fe:a9fe]', // IPv4-mapped 169.254.169.254 metadata, hex form
    '[2002:7f00:1::]', // 6to4 embedding 127.0.0.1
    '[64:ff9b::7f00:1]', // NAT64 embedding 127.0.0.1
    '[fec0::1]', // deprecated site-local
    '[ff02::1]', // link-local multicast (all nodes)
    '[ff05::1]', // site-local multicast
    '[0:0:0:0:0:0:0:1]', // fully-expanded loopback
  ]) {
    const r = validateUrl(`https://${host}/file.jpg`);
    assert.equal(r.ok, false, `${host} should be rejected`);
    assert.equal(r.code, FetchErrorCode.PrivateHost, `${host} should be private_host`);
  }
});

test('isPrivateOrReservedHost flags reserved ranges directly', () => {
  assert.equal(isPrivateOrReservedHost('100.64.0.1'), true); // CGNAT
  assert.equal(isPrivateOrReservedHost('0.0.0.0'), true);
  assert.equal(isPrivateOrReservedHost('224.0.0.1'), true); // multicast
  assert.equal(isPrivateOrReservedHost('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedHost('example.com'), false);
});

test('accepts a normal public https media URL', () => {
  const r = validateUrl('https://example.com/photo.jpg');
  assert.equal(r.ok, true);
  assert.equal(r.url.hostname, 'example.com');
});

test('accepts a public IPv6 literal (no over-blocking)', () => {
  assert.equal(validateUrl('https://[2001:4860:4860::8888]/x.jpg').ok, true);
  assert.equal(isPrivateOrReservedHost('2606:2800:220:1:248:1893:25c8:1946'), false);
});

test('content-type allowlist', () => {
  assert.equal(isAllowedContentType('image/jpeg'), true);
  assert.equal(isAllowedContentType('video/mp4'), true);
  assert.equal(isAllowedContentType('audio/mpeg'), true);
  assert.equal(isAllowedContentType('application/pdf'), true);
  assert.equal(isAllowedContentType('image/png; charset=binary'), true);
  assert.equal(isAllowedContentType('text/html'), false);
  assert.equal(isAllowedContentType('application/json'), false);
  assert.equal(isAllowedContentType(null), false);
});
