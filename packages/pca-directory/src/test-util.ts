/** Shared fixtures for the tests: keys come from seed labels / fresh generation at load time, never from committed material. */
import { b64u, generateKeyPair, type KeyPair } from '@atlasauth/pca';
import { issuePassport, signPassport, type SignedPassport } from '@atlasauth/pca/ext/attestation';
import { DirectoryLog, type DirectoryLogOptions } from './log';
import { signPop, type EntryMode } from './entry';
import { memoryLogClient, type LogClient } from './client';
import { MemoryWitnessState, Witness } from './witness';
import type { TrustedLog } from './check';

export const T0 = 1_800_000_000_000;
export const HOUR = 3_600_000;

export const clock = (start = T0) => {
  const c = { t: start, now: () => c.t, advance: (ms: number) => (c.t += ms) };
  return c;
};

export function makeAgent(issuer: KeyPair, o: { now?: number; exp?: number; operator?: string; model?: string } = {}) {
  const kp = generateKeyPair();
  const now = o.now ?? T0;
  const passport = issuePassport({ model_id: o.model ?? 'model-x', operator: o.operator ?? 'acme', hardware_rooted: false, issued_at: now });
  const sp = signPassport(passport, { issuerSecret: issuer.secretKey, subject: b64u(kp.publicKey), exp: o.exp ?? now + 1000 * HOUR });
  return { kp, sp };
}

export const register = (log: DirectoryLog, agent: { kp: KeyPair; sp: SignedPassport }, mode: EntryMode = 'public', who = 'tester') =>
  log.submit({ passport: agent.sp, pop: signPop(agent.kp.secretKey, log.id, agent.sp), mode }, who);

export interface World {
  clock: ReturnType<typeof clock>;
  issuer: KeyPair;
  logs: DirectoryLog[];
  witnesses: Witness[];
  witnessStates: MemoryWitnessState[];
  witnessKeys: string[];
  witnessSecrets: Uint8Array[];
  trusted: (online?: boolean) => TrustedLog[];
  clients: LogClient[];
  /** Every witness cosigns every log's current head (with the proof from what it cosigned before). */
  round: (only?: number[]) => Promise<void>;
}

export function makeWorld(nLogs = 3, nWitnesses = 3, logOpts: Partial<DirectoryLogOptions> = {}): World {
  const c = clock();
  const issuer = generateKeyPair();
  const wkeys = Array.from({ length: nWitnesses }, () => generateKeyPair());
  const witnessKeys = wkeys.map((k) => b64u(k.publicKey));
  const logs = Array.from({ length: nLogs }, (_, i) => {
    const kp = generateKeyPair();
    return new DirectoryLog({ id: `log-${i}`, secret: kp.secretKey, now: c.now, witnessKeys, flood: false, ...logOpts });
  });
  const witnessStates = wkeys.map(() => new MemoryWitnessState());
  const witnesses = wkeys.map((k, i) => new Witness(k.secretKey, logs.map((l) => ({ guardian: l.publicKey })), witnessStates[i]));
  const clients = logs.map((l) => memoryLogClient(l, { minCosigs: 1 }));
  return {
    clock: c,
    issuer,
    logs,
    witnesses,
    witnessStates,
    witnessKeys,
    witnessSecrets: wkeys.map((k) => k.secretKey),
    clients,
    trusted: (online = false) => logs.map((l, i) => ({ id: l.id, guardian: l.publicKey, ...(online ? { client: clients[i]! } : {}) })),
    async round(only) {
      for (const l of logs) {
        for (const [wi, w] of witnesses.entries()) {
          if (only && !only.includes(wi)) continue;
          const sth = await l.sth();
          const prev = await witnessStates[wi]!.get(l.publicKey);
          const proof = prev && sth.size > prev.size && prev.size > 0 ? ((await l.consistency(prev.size, sth.size)) ?? undefined) : undefined;
          const r = await w.cosign(sth, proof);
          if (r.ok) await l.addCosignature(r.size, r.root, r.cosignature);
        }
      }
    },
  };
}
