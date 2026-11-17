// A client-side harness over McpProxy and the scripted upstream.
import { McpProxy, type RpcMsg } from '../mcp';
import { FakeUpstream, cfgFor, createIssue, deleteRepo, readIssue, rules, secretTool } from './fakes';

export const ALL_TOOLS = [readIssue, createIssue, deleteRepo, secretTool];

export function setup(over: Record<string, unknown> = {}, toolRules = rules(), tools = ALL_TOOLS, makeEngine?: ConstructorParameters<typeof McpProxy>[0]['makeEngine'], mcpExtra: Record<string, unknown> = {}, upstream?: FakeUpstream) {
  const up = upstream ?? new FakeUpstream([...tools]);
  const sent: RpcMsg[] = [];
  const cfg = cfgFor(over, toolRules, mcpExtra);
  const proxy = new McpProxy({ cfg, upstream: up, send: (m) => sent.push(m), log: () => undefined, ...(makeEngine ? { makeEngine } : {}) });
  let n = 0;
  const raw = async (line: string, id: number): Promise<RpcMsg> => {
    await proxy.fromClient(line);
    return sent.find((m) => m.id === id)!;
  };
  const rpc = async (method: string, params?: unknown): Promise<RpcMsg> => {
    const id = ++n;
    return raw(JSON.stringify({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) }), id);
  };
  const call = async (name: string, args: unknown = {}): Promise<RpcMsg> => rpc('tools/call', { name, arguments: args });
  const list = async (method = 'tools/list', field = 'tools'): Promise<string[]> => {
    const r = await rpc(method);
    return ((r.result as Record<string, Array<{ name?: string; uri?: string; uriTemplate?: string }>>)[field] ?? []).map((t) => (field === 'resources' ? t.uri : field === 'resourceTemplates' ? t.uriTemplate : t.name) ?? '');
  };
  const denied = (m: RpcMsg): string => {
    const r = m.result as { isError?: boolean; content?: Array<{ text: string }> } | undefined;
    return r?.isError === true ? (r.content?.[0]?.text ?? '') : (m.error?.message ?? '');
  };
  return { up, sent, proxy, call, rpc, list, raw, denied, cfg };
}
