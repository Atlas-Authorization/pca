import { McpServer } from './rpc';
import { createTools, type ToolOptions } from './tools';

export const VERSION = '0.5.0';

export function createServer(o: ToolOptions): McpServer {
  return new McpServer(createTools(o), { name: 'pca-dev-mcp', version: VERSION });
}
