// Render a digest as a compact, human-readable text block. This is what the
// model reads directly in the tool result; the structured digest rides alongside
// for programmatic clients.

import type { Digest } from './types.js';

const VERDICT_LABEL: Record<Digest['verdict'], string> = {
  trusted: 'TRUSTED',
  valid_untrusted: 'VALID (untrusted signer)',
  valid_trust_unknown: 'VALID (trust unverified)',
  invalid: 'INVALID',
  no_credentials: 'NO CONTENT CREDENTIALS',
  error: 'ERROR',
};

const SEVERITY_MARK: Record<string, string> = { error: '[x]', warning: '[!]', info: '[i]' };

export function renderSummary(digest: Digest, label?: string): string {
  const lines: string[] = [];
  const head = label ? `${label}\n` : '';

  lines.push(`VERDICT: ${VERDICT_LABEL[digest.verdict]}`);
  lines.push(digest.summary);

  if (digest.verdict === 'no_credentials' || digest.verdict === 'error') {
    if (!digest.trust.evaluated && digest.trust.reason) lines.push(`Trust: ${digest.trust.reason}`);
    return head + lines.join('\n');
  }

  if (digest.title || digest.format) {
    lines.push(`File: ${digest.title || 'untitled'}${digest.format ? ` (${digest.format})` : ''}`);
  }
  if (digest.generator) lines.push(`Produced with: ${digest.generator}`);

  if (digest.signer) {
    const trust = digest.signer.trusted ? 'on the C2PA trust list' : 'not on the trust list';
    lines.push(`Signer: ${digest.signer.name || 'undisclosed'} (${trust})`);
  }

  lines.push(
    digest.aiGenerated.isAI
      ? `AI-generated: yes${digest.aiGenerated.tools.length ? ` (${digest.aiGenerated.tools.join(', ')})` : ''}`
      : 'AI-generated: not declared',
  );

  if (digest.provenance.length > 1) {
    lines.push('Provenance:');
    for (const node of digest.provenance) {
      const indent = '  '.repeat(node.depth + 1);
      const signer = node.signer ? ` [${node.signer}]` : '';
      lines.push(`${indent}- ${node.relationship}: ${node.title} (${node.verdict})${signer}`);
    }
  }

  if (digest.edits.length) {
    const edits = digest.edits.map((e) => (e.agent ? `${e.label} (${e.agent})` : e.label)).slice(0, 12);
    lines.push(`Edits: ${edits.join('; ')}`);
  }

  if (digest.watermarks.length) {
    lines.push(`Declared watermarks: ${digest.watermarks.map((w) => w.kind).join(', ')} (declared, not pixel-verified)`);
  }

  if (digest.issues.length) {
    lines.push('Issues:');
    for (const issue of digest.issues) {
      lines.push(`  ${SEVERITY_MARK[issue.severity] || '-'} ${issue.code}: ${issue.explanation}`);
    }
  }

  if (digest.trust.evaluated) {
    const partial = digest.trust.partial ? ` (PARTIAL: ${digest.trust.reason || ''})`.trimEnd() : '';
    lines.push(`Trust: evaluated against ${digest.trust.listSource}${partial}`);
  } else {
    lines.push(`Trust: NOT evaluated. ${digest.trust.reason || ''}`.trim());
  }

  return head + lines.join('\n');
}
