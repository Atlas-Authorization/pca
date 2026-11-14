#!/usr/bin/env node
/**
 * One MPC node (a party or the dealer) as its OWN OS process, talking to the others only over the TLS
 * mesh. Usage:  node party-main.js <config.json>      (or:  node party-main.js keygen <dir> <cn>)
 * Prints exactly one JSON line (the result or the attributable abort) on stdout.
 */

import { readFileSync } from 'node:fs';
import { generateIdentity, readPem } from './certs';
import { tamperFor, type FrameFault } from './faults';
import { Mesh, type NodeAddr } from './mesh';
import { type Behavior, runDealer, runParty } from './protocol';
import { NetAbort } from './wire';
import type { DecisionVector } from '../party';

export interface NodeConfig {
  role: 'party' | 'dealer' | 'ot-sender' | 'ot-receiver';
  /** For the ot-* roles: which base OT and how many transfers. */
  ot?: { kind: 'ec' | 'lwe'; count: number };
  id: number;
  n: number;
  Q?: number;
  sessionId: string;
  input?: DecisionVector;
  listenHost?: string;
  nodes: { id: number; host: string; port: number; certPath: string }[];
  keyPath: string;
  certPath: string;
  recvTimeoutMs?: number;
  connectTimeoutMs?: number;
  /** TEST ONLY: needs `unsafeTestHooks` AND env PCA_MPC_UNSAFE_TEST_HOOKS=1, else the node refuses to start. */
  behavior?: Behavior;
  /** TEST ONLY: same gating as `behavior`. */
  frameFault?: FrameFault;
  /** Explicit opt-in for the test hooks; never set by production configs. */
  unsafeTestHooks?: boolean;
  dealerSeed?: string;
  /** Which offline phase the parties run (default `no-dealer`, no dealer node). `trusted-dealer` also needs `insecureTrustedDealer: true`. */
  offline?: 'trusted-dealer' | 'no-dealer';
  /** Explicit opt-in to the trusted-dealer offline phase (the dealer sees every share and key). */
  insecureTrustedDealer?: boolean;
  /** TEST ONLY (dealer role): a lying dealer, `c = a*b + keepCDelta` (decimal string); same gating as `behavior`. */
  dealerFault?: { keepCDelta?: string; partnerCDelta?: Array<string | null>; macFaultAtInput?: number };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv[0] === 'keygen') {
    const id = generateIdentity(argv[1]!, argv[2] ?? 'mpc-node');
    process.stdout.write(JSON.stringify(id) + '\n');
    return;
  }
  const cfg = JSON.parse(readFileSync(argv[0]!, 'utf8')) as NodeConfig;
  const hooksRequested = cfg.behavior !== undefined || cfg.frameFault !== undefined || cfg.dealerFault !== undefined;
  if (hooksRequested && !(cfg.unsafeTestHooks === true && process.env.PCA_MPC_UNSAFE_TEST_HOOKS === '1')) {
    out({
      ok: false,
      role: cfg.role,
      id: cfg.id,
      error: { kind: 'local', blamed: null, reporter: cfg.id, message: 'refusing to start: test hooks (behavior/frameFault) are not enabled in this environment' },
    });
    process.exitCode = 3;
    return;
  }
  const nodes: NodeAddr[] = cfg.nodes.map((x) => ({ id: x.id, host: x.host, port: x.port, certPem: readPem(x.certPath) }));
  const linkTo = cfg.role === 'dealer' ? nodes.filter((x) => x.id < cfg.n).map((x) => x.id) : undefined;
  const mesh = new Mesh({
    selfId: cfg.id,
    nodes,
    linkTo,
    keyPem: readPem(cfg.keyPath),
    certPem: readPem(cfg.certPath),
    sessionId: cfg.sessionId,
    listenHost: cfg.listenHost,
    recvTimeoutMs: cfg.recvTimeoutMs,
    connectTimeoutMs: cfg.connectTimeoutMs,
    tamper: cfg.frameFault ? tamperFor(cfg.frameFault) : undefined,
    unsafeTestHooks: hooksRequested ? true : undefined,
  });
  const t0 = Date.now();
  try {
    await mesh.connect();
    const connectMs = Date.now() - t0;
    if (cfg.role === 'dealer') {
      const df = cfg.dealerFault;
      await runDealer({
        n: cfg.n,
        Q: cfg.Q,
        mesh,
        seed: cfg.dealerSeed ? BigInt(cfg.dealerSeed) : undefined,
        insecureTrustedDealer: cfg.insecureTrustedDealer,
        macFaultAtInput: df?.macFaultAtInput,
        fault: df
          ? {
              keepCDelta: df.keepCDelta !== undefined ? BigInt(df.keepCDelta) : undefined,
              partnerCDelta: df.partnerCDelta?.map((x) => (x === null ? undefined : BigInt(x))),
            }
          : undefined,
      });
      out({ ok: true, role: 'dealer', id: cfg.id, connectMs, links: mesh.stats(), events: mesh.events });
    } else if (cfg.role === 'ot-sender' || cfg.role === 'ot-receiver') {
      // lazy: pulls in the WASM-backed OT stack only for these roles
      const ot = await import('./ot-net');
      const k = cfg.ot ?? { kind: 'ec' as const, count: 128 };
      const peer = cfg.role === 'ot-sender' ? 1 : 0;
      const r = cfg.role === 'ot-sender' ? await ot.runOtSender(mesh, peer, k.kind, k.count) : await ot.runOtReceiver(mesh, peer, k.kind, k.count);
      out({ ok: true, role: cfg.role, connectMs, result: r, links: mesh.stats(), events: mesh.events });
    } else {
      const r = await runParty({
        id: cfg.id,
        n: cfg.n,
        Q: cfg.Q,
        input: cfg.input!,
        mesh,
        offline: cfg.offline,
        insecureTrustedDealer: cfg.insecureTrustedDealer,
        behavior: cfg.behavior,
        unsafeTestHooks: hooksRequested ? true : undefined,
        sessionId: cfg.sessionId,
      });
      out({ ok: true, role: 'party', connectMs, result: r, links: mesh.stats(), events: mesh.events });
    }
  } catch (e) {
    const ne = e instanceof NetAbort ? e : (mesh.failed ?? new NetAbort('local', null, cfg.id, (e as Error).message));
    out({
      ok: false,
      role: cfg.role,
      id: cfg.id,
      error: { kind: ne.kind, blamed: ne.blamed, reporter: ne.reporter, claimedKind: ne.claimedKind, claimedBlame: ne.claimedBlame, reason: ne.reason, evidence: ne.evidence, deadlineMs: ne.deadlineMs, message: ne.message },
      links: mesh.stats(),
      events: mesh.events,
    });
    process.exitCode = 3;
  }
  // give sockets a moment to flush abort frames, then exit regardless of lingering handles
  setTimeout(() => process.exit(process.exitCode ?? 0), 300).unref();
}

function out(o: unknown): void {
  // BigInt-safe
  process.stdout.write(JSON.stringify(o, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)) + '\n');
}

void main();
