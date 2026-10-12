// Trivial recording upstream: answers 200 and keeps what it received. GET /_log returns the log.
import { createServer } from 'node:http';
import { Buffer } from 'node:buffer';
const log = [];
createServer((req, res) => {
  if (req.url === '/_log') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(log)); }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    log.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('upstream-ok');
  });
}).listen(8080, '0.0.0.0');
