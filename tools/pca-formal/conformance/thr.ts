/**
 * Threshold step-up conformance: reference model (pca_threshold.spthy) vs the REAL verifyThreshold.
 *   tsx thr.ts exh [shard i/n]      all (setShape x t x baseline) x all share lists of length <= 1, and <= 2 for the intact signer set
 *   tsx thr.ts rand <count> <seed> [shard i/n]
 */
import { b64u, shareMessage, signerSetHash, verifyThreshold, type Signer, type SignerRole, type ThresholdShare } from '../../../packages/pca/src/index';
import { sign } from '../../../packages/pca/src/keys';
import { thresholdModel, type Role, type ThresholdIn, type ShareS } from './model';
import { keyOf } from './real';
import { rng } from './spec';

type KeyName = 'A' | 'B' | 'C' | 'X' | 'Y' | 'Z';
const ROLES: Role[] = ['agent', 'guardian', 'principal'];
const BASE: Record<Role, KeyName> = { agent: 'A', guardian: 'B', principal: 'C' };
type Shape = 'ok' | 'dupRoleKey' | 'keyTwoRoles' | 'missingPrincipal' | 'missingGuardian' | 'missingAgent';
const SHAPES: Shape[] = ['ok', 'dupRoleKey', 'keyTwoRoles', 'missingPrincipal', 'missingGuardian', 'missingAgent'];
interface ShareSpec { role: Role; keyKind: 'registered' | 'other' | 'otherRoleKey'; msg: 'ok' | 'other'; set: 'ok' | 'other'; t: 'ok' | 'other'; roleCov: 'same' | 'other' }
interface TSpec { shape: Shape; t: number; baseline: 'none' | 'ok' | 'wrongMsg' | 'otherHolder'; shares: ShareSpec[] }

const regs = (shape: Shape): Array<{ role: Role; key: KeyName }> => {
  const r = ROLES.map((role) => ({ role, key: BASE[role] }));
  switch (shape) {
    case 'ok': return r;
    case 'dupRoleKey': return [...r, { role: 'agent', key: 'X' }];
    case 'keyTwoRoles': return r.map((x) => (x.role === 'guardian' ? { role: x.role, key: 'A' as KeyName } : x));
    case 'missingPrincipal': return r.filter((x) => x.role !== 'principal');
    case 'missingGuardian': return r.filter((x) => x.role !== 'guardian');
    case 'missingAgent': return r.filter((x) => x.role !== 'agent');
  }
};
const shareKey = (s: ShareSpec): KeyName => (s.keyKind === 'registered' ? BASE[s.role] : s.keyKind === 'other' ? 'X' : BASE[ROLES[(ROLES.indexOf(s.role) + 1) % 3]!]);
const otherRole = (r: Role): Role => ROLES[(ROLES.indexOf(r) + 1) % 3]!;
const otherT = (t: number) => (t % 3) + 1;

function toModel(sp: TSpec): ThresholdIn {
  return {
    signerSet: regs(sp.shape),
    setTag: 'set1', msg: 'm1', t: sp.t,
    shares: sp.shares.map((s): ShareS => ({
      role: s.role, key: shareKey(s),
      covers: { role: s.roleCov === 'same' ? s.role : otherRole(s.role), msg: s.msg === 'ok' ? 'm1' : 'm2', set: s.set === 'ok' ? 'set1' : 'set2', t: s.t === 'ok' ? sp.t : otherT(sp.t) },
    })),
    ...(sp.baseline === 'none' ? {} : { baseline: { holder: sp.baseline === 'otherHolder' ? 'X' : 'A', coversMsg: sp.baseline !== 'wrongMsg' } }),
  };
}
const M1 = new TextEncoder().encode('message-one');
const M2 = new TextEncoder().encode('message-two');
function toReal(sp: TSpec) {
  const set: Signer[] = regs(sp.shape).map((x) => ({ role: x.role as SignerRole, publicKey: keyOf(x.key).pk }));
  const set2: Signer[] = [...set, { role: 'agent' as SignerRole, publicKey: keyOf('Z').pk }]; // a different signer set (different hash)
  const tReal = sp.t;
  const shares: ThresholdShare[] = sp.shares.map((s) => {
    const k = keyOf(shareKey(s));
    const tt = s.t === 'ok' ? (tReal >= 1 && tReal <= 3 ? tReal : 1) : otherT(tReal >= 1 && tReal <= 3 ? tReal : 1);
    const msgBytes = shareMessage((s.roleCov === 'same' ? s.role : otherRole(s.role)) as SignerRole, s.msg === 'ok' ? M1 : M2, s.set === 'ok' ? set : set2, tt);
    return { role: s.role as SignerRole, publicKey: k.pk, sig: b64u(sign(k.sk, msgBytes)) };
  });
  const baseline = sp.baseline === 'none' ? undefined : {
    holder: keyOf(sp.baseline === 'otherHolder' ? 'X' : 'A').pk,
    sig: b64u(sign(keyOf(sp.baseline === 'otherHolder' ? 'X' : 'A').sk, sp.baseline === 'wrongMsg' ? M2 : M1)),
  };
  void signerSetHash;
  return verifyThreshold({ shares }, M1, set, tReal, baseline as never);
}

const shareDomain: ShareSpec[] = [];
for (const role of ROLES) for (const keyKind of ['registered', 'other', 'otherRoleKey'] as const) for (const msg of ['ok', 'other'] as const) for (const set of ['ok', 'other'] as const) for (const t of ['ok', 'other'] as const) for (const roleCov of ['same', 'other'] as const) shareDomain.push({ role, keyKind, msg, set, t, roleCov });

async function main() {
  const [mode, a1, a2, a3] = process.argv.slice(2);
  const shard = (x?: string) => { const [i, n] = (x ?? '0/1').split('/').map(Number); return { i: i!, n: n! }; };
  let n = 0, agree = 0, accepted = 0;
  const examples: unknown[] = [];
  const hist: Record<string, number> = {};
  const t0 = Date.now();
  const test = (sp: TSpec) => {
    const m = thresholdModel(toModel(sp));
    const r = toReal(sp);
    n++;
    if (m.ok) accepted++;
    const key = `t${sp.t}:${m.ok ? 'acc' : 'rej'}:${m.count}`;
    hist[key] = (hist[key] ?? 0) + 1;
    if (m.ok === r.ok && (m.count === r.count || (!m.ok && !r.ok && r.count === 0))) agree++;
    else if (examples.length < 20) examples.push({ sp, model: m, real: { ok: r.ok, count: r.count, reason: r.reason } });
  };
  if (mode === 'exh') {
    const { i, n: sn } = shard(a1);
    let idx = 0;
    const lists: ShareSpec[][] = [[]];
    for (const a of shareDomain) lists.push([a]);
    for (const a of shareDomain) for (const b of shareDomain) lists.push([a, b]);
    for (const shape of SHAPES) for (const t of [0, 1, 2, 3, 4]) for (const baseline of ['none', 'ok', 'wrongMsg', 'otherHolder'] as const) {
      for (const shares of lists) {
        if (shares.length === 2 && shape !== 'ok') continue;
        if (idx++ % sn === i) test({ shape, t, baseline, shares });
      }
    }
  } else if (mode === 'rand') {
    const count = Number(a1 ?? '1000'); const seed = Number(a2 ?? '1'); const { i, n: sn } = shard(a3);
    const r = rng(seed * 104729 + i);
    for (let c = 0; c < Math.ceil(count / sn); c++) {
      const shares = Array.from({ length: r.int(6) }, () => r.pick(shareDomain));
      // bias towards honest-looking shares so acceptance paths are exercised too
      if (r.bool(0.4)) for (const s of shares) if (r.bool(0.8)) { s.keyKind = 'registered'; s.msg = 'ok'; s.set = 'ok'; s.t = 'ok'; s.roleCov = 'same'; }
      test({ shape: r.bool(0.7) ? 'ok' : r.pick(SHAPES), t: r.pick([0, 1, 1, 2, 2, 3, 3, 4]), baseline: r.pick(['none', 'ok', 'wrongMsg', 'otherHolder'] as const), shares });
    }
  } else throw new Error('mode');
  console.log(JSON.stringify({ mode, args: [a1, a2, a3], seconds: (Date.now() - t0) / 1000, cases: n, agree, disagree: n - agree, modelAccepted: accepted, hist, examples }));
}
main().catch((e) => { console.error(e); process.exit(1); });
