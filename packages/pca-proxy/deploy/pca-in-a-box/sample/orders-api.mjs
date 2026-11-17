// The sample API the proxy protects: a tiny in-memory orders service. It trusts one credential (the proxy's), so an agent that
// talks to it directly, without the proxy, is refused. Not part of PCA; it exists so the box has something to protect.
import { createServer } from 'node:http';

const TOKEN = process.env.UPSTREAM_TOKEN;
if (!TOKEN) throw new Error('UPSTREAM_TOKEN is required');
const orders = new Map([[1, { id: 1, sku: 'widget', qty: 2, refunded: false }], [2, { id: 2, sku: 'gadget', qty: 1, refunded: false }]]);
let next = 3;

const reply = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
const readJson = async (req) => { let s = ''; for await (const c of req) s += c; return s ? JSON.parse(s) : {}; };

createServer(async (req, res) => {
  try {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(res, 401, { error: 'unauthorized: this API only accepts calls through the proxy' });
    const url = new URL(req.url, 'http://x');
    const m = /^\/orders(?:\/(\d+))?(\/refund)?$/.exec(url.pathname);
    if (!m) return reply(res, 404, { error: 'not found' });
    const id = m[1] ? Number(m[1]) : undefined;
    if (id === undefined) {
      if (req.method === 'GET') return reply(res, 200, [...orders.values()]);
      if (req.method === 'POST') { const o = { id: next++, ...(await readJson(req)), refunded: false }; orders.set(o.id, o); return reply(res, 201, o); }
    } else {
      const o = orders.get(id);
      if (!o) return reply(res, 404, { error: 'no such order' });
      if (m[2] && req.method === 'POST') { o.refunded = true; return reply(res, 200, o); }
      if (!m[2] && req.method === 'GET') return reply(res, 200, o);
      if (!m[2] && req.method === 'DELETE') { orders.delete(id); return reply(res, 200, { deleted: id }); }
    }
    return reply(res, 405, { error: 'method not allowed' });
  } catch { return reply(res, 400, { error: 'bad request' }); }
}).listen(9000, '0.0.0.0', () => console.log('orders-api on :9000'));
