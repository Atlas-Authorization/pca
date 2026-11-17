import { describe, expect, it } from 'vitest';
import { McpServer, PROTOCOL_VERSION, type ToolDef } from './rpc';

const echo: ToolDef = { name: 'echo', description: 'e', inputSchema: { type: 'object' }, run: (a) => ({ got: a }) };
const boom: ToolDef = { name: 'boom', description: 'b', inputSchema: { type: 'object' }, run: () => { throw new Error('bad input'); } };
const srv = new McpServer([echo, boom], { name: 't', version: '1' });

describe('McpServer', () => {
  it('initializes and lists tools without the run function', async () => {
    expect(await srv.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).toMatchObject({ id: 1, result: { protocolVersion: PROTOCOL_VERSION, serverInfo: { name: 't' } } });
    const l = (await srv.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' }))!.result as { tools: Array<Record<string, unknown>> };
    expect(l.tools.map((t) => t.name)).toEqual(['echo', 'boom']);
    expect(l.tools[0]).not.toHaveProperty('run');
  });
  it('answers notifications with nothing', async () => {
    expect(await srv.handle({ jsonrpc: '2.0', method: 'notifications/initialized' })).toBeUndefined();
  });
  it('calls a tool and returns text plus structured content', async () => {
    const r = await srv.handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { a: 1 } } });
    expect(r!.result).toMatchObject({ structuredContent: { got: { a: 1 } } });
    expect(JSON.parse((r!.result as { content: Array<{ text: string }> }).content[0]!.text)).toEqual({ got: { a: 1 } });
  });
  it('turns a throwing tool into an isError result the model can read', async () => {
    const r = await srv.handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'boom' } });
    expect(r!.result).toEqual({ isError: true, content: [{ type: 'text', text: 'bad input' }] });
  });
  it('rejects unknown tools, bad arguments, unknown methods and non-requests', async () => {
    expect((await srv.handle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'nope' } }))!.error!.code).toBe(-32602);
    expect((await srv.handle({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'echo', arguments: [1] } }))!.error!.code).toBe(-32602);
    expect((await srv.handle({ jsonrpc: '2.0', id: 7, method: 'resources/list' }))!.error!.code).toBe(-32601);
    expect((await srv.handle('hello'))!.error!.code).toBe(-32600);
    expect((await srv.handle({ id: 8 }))!.error!.code).toBe(-32600);
  });
  it('serves newline-delimited JSON over a stream, one reply per request, and survives garbage', async () => {
    const out: string[] = [];
    const input = (async function* () {
      yield '{"jsonrpc":"2.0","id":1,"method":"ping"}\nnot json\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0",';
      yield '"id":2,"method":"ping"}\n[]\n';
    })();
    await srv.serve(input, (l) => out.push(l));
    const msgs = out.map((l) => JSON.parse(l) as { id: unknown; error?: { code: number } });
    expect(msgs.filter((m) => m.error === undefined).map((m) => m.id).sort()).toEqual([1, 2]);
    expect(msgs.filter((m) => m.error).map((m) => m.error!.code).sort((a, b) => a - b)).toEqual([-32700, -32600]);
  });
});
