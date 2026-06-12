// Supported asset formats for the c2pa engine, plus extension -> MIME mapping.
//
// The c2pa-node binding exposes no runtime "list supported types" call, so this
// is the maintained source of truth, derived from the c2pa-rs supported-formats
// list. It powers both the file tool (MIME inference) and the c2pa_info tool.

import { extname } from 'node:path';

/** extension (no dot, lowercase) -> MIME type the c2pa engine understands. */
export const EXTENSION_TO_MIME: Readonly<Record<string, string>> = Object.freeze({
  // images
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  tif: 'image/tiff',
  tiff: 'image/tiff',
  gif: 'image/gif',
  avif: 'image/avif',
  heic: 'image/heic',
  heif: 'image/heif',
  jxl: 'image/jxl',
  svg: 'image/svg+xml',
  dng: 'image/x-adobe-dng',
  // video
  mp4: 'video/mp4',
  m4v: 'video/mp4',
  mov: 'video/quicktime',
  avi: 'video/x-msvideo',
  // audio
  mp3: 'audio/mpeg',
  m4a: 'audio/mp4',
  wav: 'audio/wav',
  flac: 'audio/flac',
  aac: 'audio/aac',
  ogg: 'audio/ogg',
  // documents
  pdf: 'application/pdf',
});

export const SUPPORTED_MIME_TYPES: readonly string[] = Object.freeze([
  ...new Set(Object.values(EXTENSION_TO_MIME)),
]);

/** Infer a MIME type from a file path's extension, or null if unsupported. */
export function mimeFromPath(path: string): string | null {
  const ext = extname(path).slice(1).toLowerCase();
  return EXTENSION_TO_MIME[ext] ?? null;
}

/** True when the engine can read this MIME type. */
export function isSupportedMime(mime: string): boolean {
  const base = mime.split(';')[0].trim().toLowerCase();
  return SUPPORTED_MIME_TYPES.includes(base);
}
