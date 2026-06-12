// Extractors that pull human-meaningful facts out of a ManifestStore:
// AI-generation status, declared watermarks, and the edit/action history.
//
// Ported from c2paviewer.com and simplified to the canonical c2pa-types shape,
// where every manifest exposes `assertions: { label, data }[]`.

import type { Reader as ManifestStore, Manifest, ManifestAssertion } from '@contentauth/c2pa-types';
import type { AiInfo, EditEntry, WatermarkEntry } from '../types.js';

const AI_SOURCE_TYPES = [
  'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia',
  'http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia',
];

interface C2paAction {
  action?: string;
  name?: string;
  type?: string;
  softwareAgent?: string | { name?: string };
  digitalSourceType?: string;
  parameters?: { description?: string; name?: string };
  reason?: string;
  timestamp?: string;
  when?: string;
}

function manifestList(store: ManifestStore): Manifest[] {
  return Object.values((store.manifests || {}) as Record<string, Manifest>);
}

function actionsOf(manifest: Manifest): C2paAction[] {
  const out: C2paAction[] = [];
  const assertions = (manifest.assertions || []) as ManifestAssertion[];
  for (const a of assertions) {
    if (a?.label !== 'c2pa.actions' && a?.label !== 'c2pa.actions.v2') continue;
    const list = (a?.data as { actions?: C2paAction[] })?.actions;
    if (Array.isArray(list)) out.push(...list);
  }
  return out;
}

function agentName(agent: C2paAction['softwareAgent']): string {
  if (!agent) return '';
  return (typeof agent === 'string' ? agent : agent.name || '').trim();
}

/** Detect generative-AI provenance across every manifest in the store. */
export function extractAi(store: ManifestStore): AiInfo {
  const tools = new Set<string>();
  const sourceTypes = new Set<string>();
  let isAI = false;

  for (const manifest of manifestList(store)) {
    for (const action of actionsOf(manifest)) {
      const dst = action.digitalSourceType;
      if (dst && AI_SOURCE_TYPES.includes(dst)) {
        isAI = true;
        sourceTypes.add(dst);
        const name = agentName(action.softwareAgent) || manifest.claim_generator || '';
        if (name) tools.add(cleanName(name));
      }
    }
  }

  return { isAI, tools: [...tools], digitalSourceTypes: [...sourceTypes] };
}

/**
 * Detect DECLARED watermarks (e.g. SynthID, C2PA soft bindings). This reports
 * only what the manifest declares; it cannot verify a watermark signal in the
 * pixels (that needs the vendor's detector). The summary must stay honest.
 */
export function extractWatermarks(store: ManifestStore): WatermarkEntry[] {
  const out: WatermarkEntry[] = [];
  const seen = new Set<string>();

  for (const [label, manifest] of Object.entries((store.manifests || {}) as Record<string, Manifest>)) {
    const assertions = (manifest.assertions || []) as ManifestAssertion[];
    for (const a of assertions) {
      const aLabel = String(a?.label || '');
      if (!aLabel) continue;
      let payload = '';
      try {
        payload = JSON.stringify(a?.data ?? '');
      } catch {
        payload = String(a?.data ?? '');
      }
      const haystack = `${aLabel} ${payload}`.toLowerCase();
      const isSynthId = haystack.includes('synthid');
      const isSoftBinding = /soft[_-]binding/.test(haystack);
      const isWatermark = haystack.includes('watermark');
      if (!isSynthId && !isSoftBinding && !isWatermark) continue;

      const data = a?.data as { alg?: string; algorithm?: string } | undefined;
      const algorithm = String(data?.alg || data?.algorithm || '');
      const kind: WatermarkEntry['kind'] = isSynthId ? 'synthid' : isSoftBinding ? 'soft-binding' : 'watermark';
      const key = `${label}|${aLabel}|${kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ kind, assertionLabel: aLabel, algorithm });
    }
  }
  return out;
}

const ACTION_LABELS: Record<string, string> = {
  'c2pa.created': 'Created',
  'c2pa.opened': 'Opened',
  'c2pa.placed': 'Placed ingredient',
  'c2pa.edited': 'Edited',
  'c2pa.color_adjustments': 'Color adjustments',
  'c2pa.cropped': 'Cropped',
  'c2pa.drawing': 'Drawing',
  'c2pa.resized': 'Resized',
  'c2pa.converted': 'Converted',
  'c2pa.recorded': 'Recorded',
  'c2pa.captured': 'Captured',
  'c2pa.filtered': 'Filtered',
  'c2pa.transcoded': 'Transcoded',
  'c2pa.published': 'Published',
  'c2pa.printed': 'Printed',
  'c2pa.copied': 'Copied',
  'c2pa.removed': 'Removed',
  'c2pa.repackaged': 'Repackaged',
  'c2pa.unknown': 'Unknown action',
};

/** Edit/creation actions from the active manifest, in declaration order. */
export function extractEdits(store: ManifestStore): EditEntry[] {
  const activeLabel = store.active_manifest || undefined;
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const manifest = (activeLabel && manifests[activeLabel]) || undefined;
  if (!manifest) return [];

  const out: EditEntry[] = [];
  for (const act of actionsOf(manifest)) {
    const code = act.action || act.name || act.type || 'c2pa.unknown';
    const label = ACTION_LABELS[code] || humanize(code);
    const agent = agentName(act.softwareAgent);
    const ts = act.timestamp || act.when || '';
    let when = '';
    if (ts) {
      const d = new Date(ts);
      if (!isNaN(d.getTime())) {
        when =
          d.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            timeZone: 'UTC',
          }) + ' UTC';
      }
    }
    let detail = '';
    if (act.parameters?.description) detail = act.parameters.description;
    else if (act.parameters?.name) detail = `Applied: ${act.parameters.name}`;
    else if (act.reason) detail = act.reason;
    else if (act.digitalSourceType) {
      const t = act.digitalSourceType;
      if (t.includes('trainedAlgorithmicMedia')) detail = 'Generative AI';
      else if (t.includes('compositeWithTrainedAlgorithmicMedia')) detail = 'Composite with AI-generated content';
      else detail = t.split('/').pop() || '';
    }
    out.push({ label, agent, when, detail });
  }
  return out;
}

/** Best name for the software/hardware that produced the active claim. */
export function extractGenerator(store: ManifestStore): string | null {
  const activeLabel = store.active_manifest || undefined;
  const manifests = (store.manifests || {}) as Record<string, Manifest>;
  const manifest = (activeLabel && manifests[activeLabel]) || undefined;
  if (!manifest) return null;
  const info = manifest.claim_generator_info?.[0];
  if (info?.name) return cleanName(info.version ? `${info.name} ${info.version}` : info.name);
  if (manifest.claim_generator) return cleanName(manifest.claim_generator);
  return null;
}

function cleanName(s: string): string {
  return s.replace(/_/g, ' ').trim();
}

function humanize(code: string): string {
  return code
    .replace(/^c2pa\./, '')
    .replace(/^com\..*?\./, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
