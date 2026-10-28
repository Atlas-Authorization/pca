/**
 * A minimal Proof-Carrying Authority resource server.
 *
 * It exposes ONE protected route, POST /refund, and verifies a proof-carrying action on EVERY request
 * before doing any work. The proof arrives in the `PCA-Action` header and the plaintext params it committed
 * to in the JSON body (`{ charge, params }`); verification is OFFLINE. The root of trust is a grant loaded from THIS
 * server's own store by the action's signed `grant_ref`, and the decision is made by the full server verifier
 * (`requirePCA`, see `guard.ts`): the grant's scope and limits, the authorized plan, revocation, replay and budget. An
 * in-scope action is allowed; a tampered / expired / wrong-audience / unregistered / out-of-scope /
 * over-limit / replayed action is denied.
 *
 * Run it:  npm install && npm start      (then, in another terminal, `npm run client`)
 */

import express, { type Request, type Response } from 'express';
import { memoryPcaStore } from '@atlasauth/pca';
import { createGuard } from './guard.js';
import { fileGrantStore } from './store.js';

// This server's own audience id. A PCActn minted for a different audience will not verify here.
const AUDIENCE = 'ins_quickstart';
const PORT = 8787;

const grants = fileGrantStore();
// Per-holder replay counter + trust budget. In memory for the demo; Redis / your DB in production.
const state = memoryPcaStore();
// requirePCA (the full server verifier), built once: grant from our store, Ed25519 only, our clock, default-deny.
const guard = createGuard({ audience: AUDIENCE, grants, state });

const app = express();
app.use(express.json());

app.post('/refund', async (req: Request, res: Response) => {
  const actionHeader = req.header('PCA-Action');
  if (!actionHeader) {
    res.status(400).json({ error: 'missing PCA-Action header' });
    return;
  }
  const body = (req.body ?? {}) as { charge?: string; params?: Record<string, unknown> };
  // The operation THIS route executes, from the route and the body, never from the proof.
  const { status, body: out, wwwAuthenticate } = await guard(actionHeader, { verb: 'stripe.refund', resource: `charge:${body.charge}`, params: body.params ?? {} });
  if (wwwAuthenticate) res.setHeader('WWW-Authenticate', wwwAuthenticate);
  res.status(status).json(out);
});

app.listen(PORT, () => {
  console.log(`PCA resource server listening on http://localhost:${PORT}`);
  console.log('Protected route: POST /refund  (PCA-Action header + JSON { charge, params }; grants and plans come from the server store)');
  console.log('Try it: npm run client');
});
