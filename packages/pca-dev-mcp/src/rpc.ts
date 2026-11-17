/**
 * A minimal MCP server over stdio (newline-delimited JSON-RPC 2.0): initialize, ping, tools/list, tools/call.
 * Hand-rolled on purpose: the server needs nothing else and has no runtime dependency on an MCP SDK.
 * A tool that throws becomes an `isError` result the model can read; a malformed request becomes a JSON-RPC error.
 */

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** True for the tools that write files or run commands (they exist only when the server was started with --allow-write). */
  writes?: boolean;
  run(args: Record<string, unknown>): Promise<unknown> | unknown;
}

type Id = string | number | null;
interface Req { jsonrpc?: string; id?: Id; method?: string; params?: Record<string, unknown> }
export interface Rsp { jsonrpc: '2.0'; id: Id; result?: unknown; error?: { code: number; message: string } }

export const PROTOCOL_VERSION = '2025-06-18';
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const err = (id: Id, code: number, message: string): Rsp => ({ jsonrpc: '2.0', id, error: { code, message } });

export class McpServer {
  private readonly tools: Map<string, ToolDef>;
  constructor(tools: readonly ToolDef[], private readonly info: { name: string; version: string }) {
    this.tools = new Map(tools.map((t) => [t.name, t]));
  }

  /** Handle one message. Notifications (no id) return undefined. */
  async handle(msg: unknown): Promise<Rsp | undefined> {
    if (!isObj(msg) || typeof (msg as Req).method !== 'string') return err(null, -32600, 'invalid request');
    const { id, method, params } = msg as Req;
    if (id === undefined) return undefined; // notification (notifications/initialized, notifications/cancelled, ...)
    switch (method) {
      case 'initialize':
        return { jsonrpc: '2.0', id, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: this.info } };
      case 'ping':
        return { jsonrpc: '2.0', id, result: {} };
      case 'tools/list':
        return { jsonrpc: '2.0', id, result: { tools: [...this.tools.values()].map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) } };
      case 'tools/call': {
        const name = params?.name;
        const tool = typeof name === 'string' ? this.tools.get(name) : undefined;
        if (!tool) return err(id, -32602, `unknown tool '${String(name)}'`);
        const args = params?.arguments === undefined ? {} : params.arguments;
        if (!isObj(args)) return err(id, -32602, 'arguments must be an object');
        try {
          const out = await tool.run(args);
          return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out } };
        } catch (e) {
          return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: e instanceof Error ? e.message : String(e) }] } };
        }
      }
      default:
        return err(id, -32601, `method not found: ${String(method)}`);
    }
  }

  /** Serve newline-delimited JSON-RPC on a pair of streams until `input` ends. */
  async serve(input: AsyncIterable<string | Buffer>, write: (line: string) => void): Promise<void> {
    let buf = '';
    const pending: Promise<void>[] = [];
    const one = async (line: string): Promise<void> => {
      let msg: unknown;
      try { msg = JSON.parse(line); } catch { write(JSON.stringify(err(null, -32700, 'parse error'))); return; }
      const r = Array.isArray(msg) ? undefined : await this.handle(msg);
      if (Array.isArray(msg)) write(JSON.stringify(err(null, -32600, 'batches are not supported')));
      else if (r) write(JSON.stringify(r));
    };
    for await (const chunk of input) {
      buf += chunk.toString();
      let i: number;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) pending.push(one(line));
      }
    }
    if (buf.trim()) pending.push(one(buf.trim()));
    await Promise.all(pending);
  }
}
