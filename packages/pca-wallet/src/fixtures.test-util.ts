import { b64u, generateKeyPair, hashCanonical, sha256, sign, utf8, type KeyPair } from '@atlasauth/pca';
import { signIntentRequired, type SignedIntentRequired } from '@atlasauth/pca/ext/intent';
import { rng, type Omega } from '@atlasauth/pca-intent';
import {
  actionValuesOf,
  EMPTY_NOISE,
  pcaActionDigest,
  SlidingWindowCounter,
  TrustedChannel,
  type CellAt,
  type CellCoords,
  type ChannelOptions,
  type FrictionTier,
  type GrantView,
  type NoiseCounts,
  type PcaAction,
} from './index';

/** The §4 walkthrough's outcome space: add-ons, the trip total with cuts at the two readings, the add-on provenance. */
export const SKY: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    {
      verb: 'air.book',
      reversibility: 'irreversible',
      weight: 1,
      dims: [
        { kind: 'cat', path: 'action.params.add_ons', values: [{ kind: 'exact', value: 'none' }, { kind: 'exact', value: 'tripshield' }, { kind: 'other', value: '⊥' }] },
        { kind: 'num', path: 'action.params.total', lo: 0, hi: 500000, cuts: [40000, 80000], dist: 'uniform' },
        { kind: 'cat', path: 'env.prov.action.params.add_ons', values: [{ kind: 'exact', value: 'trusted|first_party' }, { kind: 'exact', value: 'tool|web|agent' }, { kind: 'other', value: '⊥' }] },
      ],
    },
  ],
};

export const USD = { 'action.params.total': { kind: 'money' as const, currency: 'USD', exponent: 2 } };

/** A shop: a reversible verb (tap questions) and an irreversible one. */
export const SHOP: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    { verb: 'cart.add', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.qty', lo: 0, hi: 100, cuts: [1, 5, 10, 50], dist: 'uniform' }] },
    { verb: 'cart.buy', reversibility: 'irreversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.amount', lo: 0, hi: 10000, cuts: [100, 1000], dist: 'uniform' }] },
  ],
};

export const D = (s: string): string => hashCanonical({ t: s });
export const SESSION = D('session');
export const KID = 'site-2026';

/** A fully controllable grant view: p per cell key `verb|i,j`, vetoes, ceiling, confirmed region. */
export function fakeView(init: { p?: Record<string, number>; defaultP?: number; vetoed?: string[]; outside?: string[]; confirmed?: CellAt[] } = {}): GrantView & { p_: Record<string, number> } {
  const p_ = { ...(init.p ?? {}) };
  const k = (v: string, idx: readonly number[]) => `${v}|${idx.join(',')}`;
  return {
    p_,
    p: (v, idx) => p_[k(v, idx)] ?? init.defaultP ?? 0.5,
    vetoed: (v, idx) => (init.vetoed ?? []).includes(k(v, idx)),
    outsideCeiling: (v, idx) => (init.outside ?? []).includes(k(v, idx)),
    confirmed: () => init.confirmed ?? [],
  };
}

export interface Harness {
  ch: TrustedChannel;
  site: KeyPair;
  ana: KeyPair;
  clock: { t: number };
  hourly: SlidingWindowCounter;
  noise: { n: NoiseCounts };
  map: { d: string };
  opts: ChannelOptions;
}

export function harness(over: Partial<ChannelOptions> & { seed?: number; shared?: Pick<Harness, 'hourly' | 'noise' | 'clock'> } = {}): Harness {
  const site = generateKeyPair();
  const ana = generateKeyPair();
  const clock = over.shared?.clock ?? { t: 1_000_000 };
  const hourly = over.shared?.hourly ?? new SlidingWindowCounter();
  const noise = over.shared?.noise ?? { n: EMPTY_NOISE };
  const map = { d: D('map-0') };
  const rand = rng(over.seed ?? 1);
  const opts: ChannelOptions = {
    omega: SKY,
    session: SESSION,
    mapDigest: () => map.d,
    principalSecret: ana.secretKey,
    site: { origin: 'https://skyair.example', name: 'SkyAir', keys: [{ kid: KID, alg: 'ed25519', pk: b64u(site.publicKey) }] },
    statementText: 'Book me and Sam a one-way flight SFO to JFK on Nov 20, under $400',
    units: USD,
    view: fakeView(),
    lift: (a) => {
      const v = actionValuesOf(a);
      return { verb: v.verb, values: { ...v.values, ...(a.verb === 'air.book' ? { 'env.prov.action.params.add_ons': 'trusted|first_party' } : {}) } };
    },
    hourly,
    noise: () => noise.n,
    onNoise: (n) => void (noise.n = n),
    rho: 0,
    rand,
    now: () => clock.t,
    ...over,
  };
  delete (opts as { seed?: number }).seed;
  delete (opts as { shared?: unknown }).shared;
  return { ch: new TrustedChannel(opts), site, ana, clock, hourly, noise, map, opts };
}

export function makeIR(h: Pick<Harness, 'site' | 'map' | 'clock'>, a: PcaAction, coords: CellCoords, over: Partial<{ question_id: string; friction: FrictionTier; session: string; expires_at: number; kid: string }> = {}): SignedIntentRequired {
  return signIntentRequired(
    {
      v: 1,
      kind: 'pca-intent-required',
      session: over.session ?? SESSION,
      map_digest: h.map.d,
      schema: D('schema'),
      pcactn_digest: D(`pcactn:${JSON.stringify(a)}`),
      action_digest: pcaActionDigest(a),
      cell: { verb: a.verb, coords },
      reason: 'uncertain',
      question_id: over.question_id ?? `q_${D(JSON.stringify(coords)).slice(0, 8).replace(/[^A-Za-z0-9_-]/g, 'x')}`,
      friction: over.friction ?? 'tap',
      delivered_to: 'wallet',
      expires_at: over.expires_at ?? h.clock.t + 900_000,
    },
    over.kid ?? KID,
    h.site.secretKey,
  );
}

/** An attempted action as the site sees it (the PCActn's `action`, with raw params). */
export const act = (verb: string, params: Record<string, unknown>, resource = 'site.example/r', reversibility_class = 'irreversible'): PcaAction => ({ verb, resource, params, reversibility_class });

/** A real EdDSA WebAuthn assertion over `challenge` (UP + UV set). */
export function assertion(cred: KeyPair, challengeB64u: string, rpId: string, origin: string, flags = 0x05) {
  const authData = new Uint8Array([...sha256(utf8(rpId)), flags, 0, 0, 0, 7]);
  const clientData = utf8(JSON.stringify({ type: 'webauthn.get', challenge: challengeB64u, origin }));
  const msg = new Uint8Array([...authData, ...sha256(clientData)]);
  return { authenticator_data: b64u(authData), client_data_json: b64u(clientData), signature: b64u(sign(cred.secretKey, msg)) };
}
