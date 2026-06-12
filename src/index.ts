#!/usr/bin/env node
// Entry point: resolve versions, build the server, and serve over stdio.
// Distributed via `npx -y @c2paviewer/c2pa-mcp` and run by MCP clients (Claude
// Desktop, Claude Code, Cursor, ...) as a stdio subprocess.

import { createRequire } from 'node:module';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

const require = createRequire(import.meta.url);

function versionOf(spec: string, fallback: string): string {
  try {
    return (require(spec) as { version?: string }).version || fallback;
  } catch {
    return fallback;
  }
}

const serverVersion = versionOf('../package.json', '0.1.0');
const engineVersion = versionOf('@contentauth/c2pa-node/package.json', 'unknown');

const server = createServer({ serverVersion, engineVersion });
const transport = new StdioServerTransport();

await server.connect(transport);
