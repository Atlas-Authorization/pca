// A small MCP server (stdio) with three tools: one that reads, one that writes, one that is dangerous. The proxy sits in front of it.
import { createInterface } from 'node:readline';

const notes = [{ id: 1, text: 'buy milk' }];
const tools = [
  { name: 'search_notes', description: 'Search notes by text', inputSchema: { type: 'object', properties: { q: { type: 'string', maxLength: 100 } }, additionalProperties: false } },
  { name: 'create_note', description: 'Create a note', inputSchema: { type: 'object', properties: { text: { type: 'string', maxLength: 200 } }, required: ['text'], additionalProperties: false } },
  { name: 'delete_note', description: 'Delete a note permanently', inputSchema: { type: 'object', properties: { id: { type: 'integer', minimum: 1 } }, required: ['id'], additionalProperties: false } },
];
const text = (t) => ({ content: [{ type: 'text', text: t }] });

function call(name, a) {
  if (name === 'search_notes') return text(JSON.stringify(notes.filter((n) => n.text.includes(a.q ?? ''))));
  if (name === 'create_note') { const n = { id: notes.length + 1, text: a.text }; notes.push(n); return text(JSON.stringify(n)); }
  if (name === 'delete_note') { const i = notes.findIndex((n) => n.id === a.id); if (i >= 0) notes.splice(i, 1); return text(`deleted ${a.id}`); }
  return { isError: true, ...text(`unknown tool ${name}`) };
}

createInterface({ input: process.stdin }).on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  const out = (result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }) + '\n');
  if (m.method === 'initialize') return out({ protocolVersion: m.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'notes', version: '1' } });
  if (m.method === 'tools/list') return out({ tools });
  if (m.method === 'tools/call') return out(call(m.params?.name, m.params?.arguments ?? {}));
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'method not found' } }) + '\n');
});
