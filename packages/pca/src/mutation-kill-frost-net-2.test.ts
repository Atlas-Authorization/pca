/** Mutation-kill tests (round 2) for frost-net.ts: PoP nonce retry, error-class shape, server address/close edge cases, deadline windows on slow transports. */
import http from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { frostTrustedDealerKeygen } from './frost';
import { generateKeyPair } from './keys';
import { utf8 } from './hash';
import {
  createSignerPoP, GuardianSignerService, inProcessTransport, issueAllowToken, NetworkCoordinator,
  startSignerHttpServer, verifySignerPoP, type SignerTransport,
} from './frost-net';

afterEach(() => vi.restoreAllMocks());

describe('createSignerPoP nonce retry', () => {
  it('a zero nonce draw is rejected and redrawn: R is never the identity and the proof verifies', () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const p = kg.participantShares[0]!;
    const real = ed25519.utils.randomPrivateKey;
    let calls = 0;
    vi.spyOn(ed25519.utils, 'randomPrivateKey').mockImplementation(() => (calls++ === 0 ? new Uint8Array(32) : real()));
    const pop = createSignerPoP(p.identifier, p.share, { groupPublicKey: kg.groupPublicKey });
    expect(calls).toBe(2);
    const identityB64 = Buffer.from(ed25519.ExtendedPoint.ZERO.toRawBytes()).toString('base64url');
    expect(pop.R).not.toBe(identityB64);
    expect(verifySignerPoP(pop, { groupPublicKey: kg.groupPublicKey })).toBe(true);
  });
});

describe('startSignerHttpServer edges', () => {
  const svc = () => {
    const kg = frostTrustedDealerKeygen(2, 3);
    const policy = generateKeyPair();
    const p = kg.participantShares[0]!;
    return new GuardianSignerService({
      identifier: p.identifier, share: p.share.slice(), groupPublicKey: kg.groupPublicKey, threshold: 2,
      policyAuthorityPublicKey: policy.publicKey,
    } as never);
  };
  const stubAddr = async (ret: unknown) => {
    const servers: http.Server[] = [];
    vi.spyOn(http.Server.prototype, 'address').mockImplementation(function (this: http.Server) {
      servers.push(this);
      return ret as never;
    });
    let err: unknown;
    try { await startSignerHttpServer(svc(), {}); } catch (e) { err = e; }
    vi.restoreAllMocks();
    await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
    return err;
  };
  it('a null address rejects with the exact message', async () => {
    const e = await stubAddr(null);
    expect(e).toBeInstanceOf(Error);
    expect((e as Error).message).toBe('could not determine server address');
  });
  it('a string (pipe) address rejects with the exact message', async () => {
    const e = await stubAddr('/tmp/sock');
    expect(e).toBeInstanceOf(Error);
    expect((e as Error).message).toBe('could not determine server address');
  });
  it('close() works when closeAllConnections is unavailable', async () => {
    const s = await startSignerHttpServer(svc(), {});
    const saved = http.Server.prototype.closeAllConnections;
    const own = Object.getOwnPropertyDescriptor(s.server, 'closeAllConnections');
    Object.defineProperty(s.server, 'closeAllConnections', { value: undefined, configurable: true, writable: true });
    try {
      await s.close();
    } finally {
      if (own) Object.defineProperty(s.server, 'closeAllConnections', own); else delete (s.server as unknown as Record<string, unknown>).closeAllConnections;
      http.Server.prototype.closeAllConnections = saved;
    }
    expect(s.server.listening).toBe(false);
  });
  it('a non-Error throw from the service maps to a 400 "bad request" refusal', async () => {
    const stub = { identifier: 7, round1() { throw 'not an error'; }, round2() { throw 'nope'; } };
    const s = await startSignerHttpServer(stub as never, {});
    try {
      const r = await fetch(s.url + '/round1', { method: 'POST', body: '{}' });
      expect(r.status).toBe(400);
      expect(await r.json()).toEqual({ ok: false, identifier: 7, refused: true, reason: 'bad request' });
    } finally {
      await s.close();
    }
  });
});

describe('NetworkCoordinator deadline windows with a slow transport', () => {
  const MSG = utf8('slow');
  const slow = (svc: GuardianSignerService): SignerTransport => {
    const base = inProcessTransport(svc);
    return {
      ...base,
      round1: async (r) => { await new Promise((res) => setTimeout(res, 30)); return base.round1(r); },
    };
  };
  for (const w of [0, -5, NaN, Infinity]) {
    it(`timeoutMs=${w} means no deadline (a 30ms-per-round run completes)`, async () => {
      const kg = frostTrustedDealerKeygen(2, 3);
      const policy = generateKeyPair();
      const svcs = kg.participantShares.map((p) => new GuardianSignerService({
        identifier: p.identifier, share: p.share.slice(), groupPublicKey: kg.groupPublicKey, threshold: 2,
        policyAuthorityPublicKey: policy.publicKey,
      } as never));
      const c = new NetworkCoordinator({
        groupPublicKey: kg.groupPublicKey, threshold: 2, signers: svcs.map(slow),
        verificationShares: kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey })),
      } as never);
      const allow = issueAllowToken(policy.secretKey, { message: MSG, groupPublicKey: kg.groupPublicKey });
      const res = await c.sign(MSG, allow, { timeoutMs: w });
      expect(res.signature.length).toBe(64);
    });
  }
});
