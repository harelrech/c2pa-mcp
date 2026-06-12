// Build the MCP server and register the four verification tools. Tool
// descriptions are written for the model: they say exactly when to reach for
// each one, since the model picks tools from these strings alone.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { infoTool, scanDirectoryTool, verifyFileTool, verifyUrlTool } from './tools.js';

export interface ServerVersions {
  serverVersion: string;
  engineVersion: string;
}

export function createServer({ serverVersion, engineVersion }: ServerVersions): McpServer {
  const server = new McpServer({ name: 'c2pa-mcp', version: serverVersion });

  server.registerTool(
    'verify_c2pa_file',
    {
      title: 'Verify C2PA content credentials in a local file',
      description:
        'Verify the C2PA Content Credentials (provenance) of a local image, video, audio, or PDF file. ' +
        'Returns a plain-language verdict (trusted / valid_untrusted / invalid / no_credentials), the signer, ' +
        'whether the content is AI-generated, its edit history, provenance lineage, and any validation issues. ' +
        'Use this when you have a file path on disk. The file is read locally and never uploaded.',
      inputSchema: {
        path: z.string().describe('Absolute or relative path (or file:// URI) to the media file to verify.'),
        includeRaw: z
          .boolean()
          .optional()
          .describe('If true, include the full raw C2PA manifest store in the structured result. Defaults to false.'),
      },
    },
    async (args) => verifyFileTool(args),
  );

  server.registerTool(
    'verify_c2pa_url',
    {
      title: 'Verify C2PA content credentials at a URL',
      description:
        'Download a remote image, video, audio, or PDF over https and verify its C2PA Content Credentials. ' +
        'Returns the same plain-language verdict, signer, AI-generation status, lineage, and issues as verify_c2pa_file. ' +
        'Use this for a web URL. Only public https URLs are allowed (private/internal hosts are refused).',
      inputSchema: {
        url: z.string().describe('Public https URL of the media file to verify.'),
        includeRaw: z
          .boolean()
          .optional()
          .describe('If true, include the full raw C2PA manifest store in the structured result. Defaults to false.'),
      },
    },
    async (args) => verifyUrlTool(args),
  );

  server.registerTool(
    'scan_c2pa_directory',
    {
      title: 'Scan a directory for C2PA content credentials',
      description:
        'Audit a folder of media files: report which ones carry C2PA Content Credentials, their verdict, signer, ' +
        'and whether each is AI-generated. Non-recursive. Use this to triage a directory of images/videos at once.',
      inputSchema: {
        directory: z.string().describe('Path (or file:// URI) to the directory to scan.'),
        maxFiles: z
          .number()
          .optional()
          .describe('Maximum number of media files to scan (default 200, max 1000).'),
      },
    },
    async (args) => scanDirectoryTool(args),
  );

  server.registerTool(
    'c2pa_info',
    {
      title: 'C2PA engine and trust-list info',
      description:
        'Report the verification engine version, the media types this server can verify, and the active trust-list ' +
        'configuration. Use this to check capabilities before verifying.',
      inputSchema: {},
    },
    async () => infoTool(engineVersion, serverVersion),
  );

  return server;
}
