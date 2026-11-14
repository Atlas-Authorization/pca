import { describe, expect, it } from 'vitest';
import {
  type ActionContext,
  type Envelope,
  type PCActn,
  type PolicyDecision,
  type VerifyResult,
  DEFAULT_RISK_POLICY,
  PCACTN_MAX_LIFETIME_MS,
  PCACTN_MAX_SKEW_MS,
  PCACTN_VERSION,
  b64u,
  budgetAllocCaveat,
  delegate,
  generateKeyPair,
  mintGrant,
} from '@atlasauth/pca';
import { cleanText, explainDecision, explainVerification } from './index';

const base = {
  ver: 2,
  aud: 'ins_1',
  iat: 1000,
  exp: 2000,
  counter: 7,
  grant_ref: 'g',
  action: { verb: 'v', resource: 'r' },
  plan: { root: 'p', node_id: 'n' },
  cap_chain: [],
} as unknown as PCActn;

function verdictOf(over: object, checks: Record<string, string>, extra: object = {}, opts: { now?: number } = {}) {
  return explainVerification({ ...base, ...over } as PCActn, { allow: false, checks, ...extra } as unknown as VerifyResult, opts);
}
function failing(name: string, over: object = {}, opts: { now?: number } = {}, reason?: string) {
  const e = verdictOf(over, { [name]: 'fail' }, reason === undefined ? {} : { reason }, opts);
  if (!e.decisive) throw new Error('no decisive check');
  return e.decisive;
}
function passing(name: string, over: object = {}) {
  const e = explainVerification({ ...base, ...over } as PCActn, { allow: true, checks: { [name]: 'pass' } } as unknown as VerifyResult);
  const c = e.checks.find((x) => x.name === name);
  if (!c) throw new Error('missing check');
  return c.detail;
}

describe('cleanText redaction', () => {
  it('redacts a JWT, and only a full three-part one', () => {
    expect(cleanText('x eyJabcde.abcde.xyz y')).toBe('x [redacted] y');
    expect(cleanText('eyJabcde.abcde.')).toBe('[redacted]');
    expect(cleanText('eyJa.abcde.xyz')).toBe('eyJa.abcde.xyz');
    expect(cleanText('eyJabcde.a.xyz')).toBe('eyJabcde.a.xyz');
  });
  it('redacts bearer credentials', () => {
    expect(cleanText('Bearer abcdefgh')).toBe('Bearer [redacted]');
    expect(cleanText('Bearer  abcdefgh')).toBe('Bearer [redacted]');
    expect(cleanText('basic dXNlcjpwYXNz')).toBe('basic [redacted]');
    expect(cleanText('Bearer abc')).toBe('Bearer abc');
  });
  it('redacts URL userinfo only for a well-formed scheme', () => {
    expect(cleanText('https://user:pass@host/x')).toBe('https://[redacted]@host/x');
    expect(cleanText('x://u:p@h')).toBe('x://[redacted]@h');
    expect(cleanText('a!://u:p@h')).toBe('a!://u:p@h');
  });
  it('redacts key=value style secrets', () => {
    for (const n of ['token', 'secret', 'password', 'passwd', 'pwd', 'key', 'signature', 'sig', 'credential', 'authorization', 'auth']) {
      expect(cleanText(`${n}=abcdefg`), n).toBe(`${n}=[redacted]`);
    }
    expect(cleanText('api_key=abc')).toBe('api_key=[redacted]');
    expect(cleanText('api-key: abc')).toBe('api-key: [redacted]');
    expect(cleanText('apikey=abc')).toBe('apikey=[redacted]');
    expect(cleanText('token  =  abc')).toBe('token  =  [redacted]');
    expect(cleanText('token": "abc def"')).toBe('token": [redacted]');
    expect(cleanText('token="abc def" rest')).toBe('token=[redacted] rest');
    expect(cleanText("token='abc def' rest")).toBe('token=[redacted] rest');
    expect(cleanText('secret=abc&x=1')).toBe('secret=[redacted]&x=1');
    expect(cleanText('secret=abc;next')).toBe('secret=[redacted];next');
    expect(cleanText('secret=abc,next')).toBe('secret=[redacted],next');
  });
  it('cuts at exactly 400 characters', () => {
    const t400 = ' a'.repeat(200);
    expect(cleanText(t400)).toBe(t400);
    expect(cleanText(`${t400}b`)).toBe(`${t400}...`);
  });
});

describe('check presentation', () => {
  it('splits passed, failed and not-enforced checks', () => {
    const e = verdictOf({}, { wire: 'pass', version: 'not-enforced', audience: 'fail', validity: 'fail', cap_chain: 'pass', counter: 'not-enforced' });
    expect(e.passed).toEqual(['wire', 'cap_chain']);
    expect(e.failed).toEqual(['audience', 'validity']);
    expect(e.notEnforced).toEqual(['version', 'counter']);
  });
});

describe('failing check pinpoints', () => {
  const remedies: Record<string, string> = {
    wire: 'do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.',
    counter: 'use a strictly increasing per-holder counter; a repeated counter is a replay.',
    malformed: 'rebuild the action with the SDK; do not construct the wire object by hand.',
    replay: 'satisfy the replay requirement (supply the corresponding verifier hook / proof).',
  };
  it('names the check and the fix when the verifier gave no reason', () => {
    expect(failing('wire')).toMatchObject({ detail: 'wire structure / strict-canonical-form check failed', remedy: remedies.wire });
    expect(failing('malformed')).toMatchObject({ detail: 'the PCActn is structurally malformed', remedy: remedies.malformed });
    expect(failing('replay')).toMatchObject({ detail: 'replay check failed', remedy: remedies.replay });
    for (const n of ['counter', 'counter_format']) {
      expect(failing(n, { counter: 1.23456789 }), n).toMatchObject({ detail: 'counter 1.2346 is missing or not a non-negative safe integer', remedy: remedies.counter });
    }
    expect(failing('version', { ver: 3 })).toMatchObject({ detail: `unsupported ver 3 (verifier requires ${PCACTN_VERSION})`, remedy: `re-mint the action at wire version ${PCACTN_VERSION}.` });
    expect(failing('audience')).toMatchObject({ detail: 'aud "ins_1" does not match this resource server / instance' });
    expect(failing('grant_ref_bound', { grant_ref: 'g'.repeat(20) })).toMatchObject({
      detail: 'grant_ref gggggggggg… is not the id of the root capability in cap_chain',
      remedy: 'set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.',
    });
    expect(failing('plan_inclusion', { plan: { root: 'p'.repeat(20), node_id: 'n' } })).toMatchObject({
      detail: 'action (verb "v" on "r") is not node "n" of committed plan pppppppppp…',
      remedy: 'rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).',
    });
    expect(failing('plan_inclusion', { action: undefined, plan: undefined }).detail).toBe('action (verb undefined on undefined) is not node undefined of committed plan <none>');
  });
  it('prefers the verifier reason when it names the check', () => {
    for (const n of ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter', 'counter_format', 'malformed', 'replay']) {
      expect(failing(n, {}, {}, `${n}: because`).detail, n).toBe('because');
    }
    expect(failing('audience', {}, {}, 'other: because').detail).toBe('aud "ins_1" does not match this resource server / instance');
  });
  it('formats numbers compactly', () => {
    expect(failing('version', { ver: 9007199254740991 }).detail).toContain('unsupported ver 9007199254740991 (');
    expect(failing('version', { ver: 1.5 }).detail).toContain('ver 1.5 (');
    expect(failing('version', { ver: 1.23456789 }).detail).toContain('ver 1.2346 (');
    expect(failing('version', { ver: 'x' }).detail).toContain('ver x (');
    expect(failing('version', { ver: NaN }).detail).toContain('ver NaN (');
    expect(failing('version', { ver: Infinity }).detail).toContain('ver Infinity (');
    expect(failing('version', { ver: undefined }).detail).toContain('ver undefined (');
  });
  it('shortens keys to ten characters plus an ellipsis', () => {
    const d = (g: unknown) => failing('grant_ref_bound', { grant_ref: g }).detail;
    expect(d('a'.repeat(11))).toBe(`grant_ref ${'a'.repeat(11)} is not the id of the root capability in cap_chain`);
    expect(d('a'.repeat(12))).toBe(`grant_ref ${'a'.repeat(10)}… is not the id of the root capability in cap_chain`);
    expect(d('')).toBe('grant_ref <none> is not the id of the root capability in cap_chain');
    expect(d(5)).toBe('grant_ref <none> is not the id of the root capability in cap_chain');
    expect(d(undefined)).toBe('grant_ref <none> is not the id of the root capability in cap_chain');
  });
});

describe('validity pinpoint', () => {
  it('flags an empty window', () => {
    for (const exp of [1000, 999]) {
      expect(failing('validity', { iat: 1000, exp })).toEqual({
        name: 'validity',
        status: 'fail',
        title: 'freshness window',
        decisive: true,
        detail: `exp ${exp} ≤ iat 1000: empty validity window`,
        remedy: 'set exp strictly greater than iat.',
      });
    }
  });
  it('flags a too-long lifetime only above the maximum', () => {
    const over = failing('validity', { iat: 1000, exp: 1000 + PCACTN_MAX_LIFETIME_MS + 1 });
    expect(over.detail).toBe(`lifetime ${PCACTN_MAX_LIFETIME_MS + 1}ms exceeds the ${PCACTN_MAX_LIFETIME_MS}ms maximum`);
    expect(over.remedy).toBe(`shorten the window to ≤ ${PCACTN_MAX_LIFETIME_MS}ms (buildPCActn ttlMs).`);
    expect(failing('validity', { iat: 1000, exp: 1000 + PCACTN_MAX_LIFETIME_MS }).detail).toBe('validity window invalid');
  });
  it('without a clock the window is reported as invalid', () => {
    const d = failing('validity', { iat: 1000, exp: 2000 });
    expect(d.detail).toBe('validity window invalid');
    expect(d.remedy).toBe('build a fresh action with a valid iat/exp window.');
  });
  it('flags a future iat beyond the skew allowance', () => {
    const now = 5000;
    const future = failing('validity', { iat: now + PCACTN_MAX_SKEW_MS + 1, exp: now + PCACTN_MAX_SKEW_MS + 100 }, { now });
    expect(future.detail).toBe(`iat ${now + PCACTN_MAX_SKEW_MS + 1} is ${PCACTN_MAX_SKEW_MS + 1}ms in the future (> ${PCACTN_MAX_SKEW_MS}ms clock-skew allowance)`);
    expect(future.remedy).toBe('fix the signer clock; do not pre-date actions.');
    const edge = failing('validity', { iat: now + PCACTN_MAX_SKEW_MS, exp: now + PCACTN_MAX_SKEW_MS + 100 }, { now });
    expect(edge.detail).toBe('validity window invalid');
  });
  it('flags an expired action only once now is past exp', () => {
    const expired = failing('validity', { iat: 1000, exp: 2000 }, { now: 2500 });
    expect(expired.detail).toBe('expired 500ms ago (exp 2000, now 2500)');
    expect(expired.remedy).toBe('build a fresh action — a PCActn lifetime is short by design.');
    expect(failing('validity', { iat: 1000, exp: 2000 }, { now: 2000 }).detail).toBe('validity window invalid');
    expect(failing('validity', { iat: 1000, exp: 2000 }, { now: 1500 }).detail).toBe('validity window invalid');
  });
});

describe('capability chain and leaf signature pinpoints', () => {
  const DEFAULT_REMEDY = 'rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.';
  const mint = () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: b64u(principal.publicKey),
      holder: b64u(holder.publicKey),
      goal: 'g',
      envelope: { predicates: [{ verb: 'v' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } as Omit<Envelope, 'goal_commit'>,
    });
    return { grant, holder };
  };

  it('a chain that is not an array', () => {
    const d = failing('cap_chain', { cap_chain: 5 });
    expect(d.detail).toBe('cap_chain is not an array');
    expect(d.remedy).toBe(DEFAULT_REMEDY);
    expect(d).not.toHaveProperty('hop');
  });
  it('an empty chain', () => {
    const d = failing('cap_chain', { cap_chain: [] });
    expect(d.detail).toBe('empty chain');
    expect(d.remedy).toBe(DEFAULT_REMEDY);
    expect(d).not.toHaveProperty('hop');
  });
  it('a malformed hop names its index', () => {
    const d = failing('cap_chain', { cap_chain: [{}] });
    expect(d.detail).toBe('hop 0: malformed capability');
    expect(d.hop).toBe(0);
    expect(d.remedy).toBe(DEFAULT_REMEDY);
  });
  it('a caveat-limit failure points at append-only attenuation', () => {
    const d = failing('cap_chain', { cap_chain: [{ caveats: new Array(257).fill({ type: 'x' }) }] });
    expect(d.detail).toContain('caveat limit');
    expect(d.remedy).toBe('attenuation is append-only: never drop, reorder or edit a parent caveat.');
    expect(d).not.toHaveProperty('hop');
  });
  it('a valid chain at the wrong root points at the grant', () => {
    const { grant } = mint();
    const d = failing('cap_chain', { cap_chain: [grant] });
    expect(d.detail).toBe('chain root is not the grant this verifier expects');
    expect(d.remedy).toBe('root the chain at the principal key that minted the grant.');
    expect(d).not.toHaveProperty('hop');
  });
  it('a widening budget allocation', () => {
    const { grant, holder } = mint();
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    const c1 = delegate(grant, b64u(k1.publicKey), [budgetAllocCaveat(5)], holder.secretKey);
    const c2 = delegate(c1, b64u(k2.publicKey), [budgetAllocCaveat(10)], k1.secretKey);
    const d = failing('cap_chain', { cap_chain: [grant, c1, c2] });
    expect(d.detail).toContain('widens');
    expect(d.remedy).toBe('a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.');
    expect(d).not.toHaveProperty('hop');
  });
  it('a bad hop signature reports a multi-digit hop index', () => {
    const { grant, holder } = mint();
    const chain = [grant];
    let secret = holder.secretKey;
    for (let i = 1; i <= 11; i++) {
      const k = generateKeyPair();
      chain.push(delegate(chain[i - 1]!, b64u(k.publicKey), [], secret));
      secret = k.secretKey;
    }
    chain[11] = { ...chain[11]!, sig: b64u(new Uint8Array(64)) };
    const d = failing('cap_chain', { cap_chain: chain });
    expect(d.detail).toBe('hop 11: bad signature (not signed by expected key)');
    expect(d.hop).toBe(11);
    expect(d.remedy).toBe('re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).');
  });
  it('the leaf signature check names the leaf hop and suite', () => {
    const LEAF_REMEDY = 'sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.';
    const chain = [{ holder: 'A'.repeat(43) }, { holder: 'H'.repeat(43) }];
    const d = failing('leaf_signature', { cap_chain: chain });
    expect(d.detail).toBe('leaf hop #1 signature (holder HHHHHHHHHH…, suite ed25519) does not verify');
    expect(d.hop).toBe(1);
    expect(d.remedy).toBe(LEAF_REMEDY);
    const one = failing('leaf_signature', { cap_chain: [{ holder: 'H'.repeat(43) }], alg: 'ml-dsa-65' });
    expect(one.detail).toBe('leaf hop #0 signature (holder HHHHHHHHHH…, suite ml-dsa-65) does not verify');
    expect(one.hop).toBe(0);
  });
  it('no leaf capability to check against', () => {
    const none = 'no leaf capability to check the signature against (empty/invalid chain)';
    expect(failing('leaf_signature', { cap_chain: [] }).detail).toBe(none);
    expect(failing('leaf_signature', { cap_chain: [] })).not.toHaveProperty('hop');
    const odd = { '-1': { holder: 'AAAAAAAAAAAA' }, '1': { holder: 'BBBBBBBBBBBB' } };
    expect(failing('leaf_signature', { cap_chain: odd }).detail).toBe(none);
    expect(failing('leaf_signature', { cap_chain: Object.assign([], { '-1': { holder: 'AAAAAAAAAAAA' } }) }).detail).toBe(none);
  });
});

describe('passing check details', () => {
  it('says what held for each check', () => {
    expect(passing('wire')).toBe('wire structure + strict canonical form valid');
    expect(passing('version')).toBe('ver 2 supported');
    expect(passing('audience')).toBe('aud "ins_1" matches this resource server');
    expect(passing('validity', { iat: 1000, exp: 2500 })).toBe('fresh: iat/exp window valid (lifetime 1.5s)');
    expect(passing('grant_ref_bound', { grant_ref: 'g'.repeat(20) })).toBe('grant_ref gggggggggg… is the id of the chain root');
    expect(passing('plan_inclusion', { plan: { root: 'p'.repeat(20), node_id: 'n' } })).toBe('action is node "n" of committed plan pppppppppp…');
    expect(passing('plan_inclusion', { plan: undefined })).toBe('action is node undefined of committed plan <none>');
    expect(passing('counter')).toBe('counter 7 well-formed');
    expect(passing('counter_format')).toBe('counter 7 well-formed');
    expect(passing('replay')).toBe('ok');
  });
  it('counts hops and names the root issuer', () => {
    const cap = (i: string) => ({ issuer: i.repeat(43), holder: 'H'.repeat(43) });
    expect(passing('cap_chain', { cap_chain: [cap('I'), cap('J'), cap('K')] })).toBe('3-hop chain verifies; root issuer IIIIIIIIII…');
    expect(passing('cap_chain', { cap_chain: 'nope' })).toBe('0-hop chain verifies; root issuer <none>');
  });
  it('names the leaf holder and suite', () => {
    expect(passing('leaf_signature', { cap_chain: [{ holder: 'A'.repeat(43) }, { holder: 'H'.repeat(43) }] })).toBe('leaf holder HHHHHHHHHH… signature valid (suite ed25519)');
    expect(passing('leaf_signature', { cap_chain: [{ holder: 'H'.repeat(43) }], alg: 'ml-dsa-65' })).toBe('leaf holder HHHHHHHHHH… signature valid (suite ml-dsa-65)');
    expect(passing('leaf_signature', { cap_chain: [] })).toBe('leaf holder <none> signature valid (suite ed25519)');
    expect(passing('leaf_signature', { cap_chain: Object.assign([], { '-1': { holder: 'ZZZZZZZZZZZZ' } }) })).toBe('leaf holder <none> signature valid (suite ed25519)');
    expect(passing('leaf_signature', { cap_chain: { length: 2, 1: { holder: 'ZZZZZZZZZZZZ' } } })).toBe('leaf holder <none> signature valid (suite ed25519)');
  });
});

describe('caveat and where rendering in a decision', () => {
  const action = { action: { verb: 'v', resource: 'v', params: { amount: 5 } } } as unknown as ActionContext;
  const decision = {
    admit: true,
    needStepUp: false,
    releaseGuardianShare: true,
    r: 0.1,
    requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: true },
    budget: { B: 1, tau: 0, asOf: 0 },
    reasons: [],
  } as unknown as PolicyDecision;
  const envWith = (over: object): Envelope =>
    ({ predicates: [{ verb: 'v' }], caveats: [], agent_binding: {}, risk_policy: { theta1: 0.2, theta2: 0.6, kappa: 1 }, ...over }) as unknown as Envelope;
  const caveatDetails = (caveats: unknown[]) => explainDecision(base, decision, { envelope: envWith({ caveats }) }).caveats.map((c) => c.detail);
  const whereOf = (where: unknown) => {
    const e = explainDecision(base, decision, { envelope: envWith({ predicates: [{ verb: 'v', where }] }), context: { action } });
    return e.grant.where;
  };
  const A = { field: 'action.params.amount', op: 'eq', value: 5 };
  const B = { field: 'action.verb', op: 'eq', value: 'v' };
  const NOPE = { field: 'action.params.amount', op: 'eq', value: 99 };

  it('renders caveat values compactly', () => {
    expect(caveatDetails([{ type: 'rate', max: 3, per_secs: 60 }])).toEqual(['rate(max=3, per_secs=60) held']);
    expect(caveatDetails([{ type: 'x', a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7 }])).toEqual(['x(a=1, b=2, c=3, d=4, e=5, f=6) held']);
    expect(caveatDetails([{ type: 'y', o: { a: 1 }, s: 'str', n: null, f: 1.23456789, u: undefined }])).toEqual(['y(o={"a":1}, s=str, n=null, f=1.2346, u=undefined) held']);
    expect(caveatDetails([{ type: 'y', arr: [1, 'a'] }])).toEqual(['y(arr=[1,"a"]) held']);
  });
  it('a malformed caveat degrades to a placeholder type', () => {
    expect(caveatDetails([{ type: 5, x: 1 }])).toEqual(['<malformed>(x=1) held']);
    expect(caveatDetails([null])).toEqual(['<malformed> held']);
    expect(caveatDetails(['abc'])).toEqual(['<malformed> held']);
  });
  it('renders the where bound of the granting predicate', () => {
    expect(whereOf(undefined)).toBe('any (no where-bound)');
    expect(whereOf([])).toBe('any (no where-bound)');
    expect(whereOf([A])).toBe('action.params.amount eq 5');
    expect(whereOf([A, B])).toBe('action.params.amount eq 5 AND action.verb eq v');
    expect(whereOf([{ field: 'action.verb', op: 'exists' }])).toBe('action.verb exists');
    expect(whereOf([{ field: 'action.verb', op: 'eq', ref: 'action.resource' }])).toBe('action.verb eq →action.resource');
    expect(whereOf([{ all_of: [A, B] }])).toBe('(action.params.amount eq 5 AND action.verb eq v)');
    expect(whereOf([{ any_of: [NOPE, A] }])).toBe('(action.params.amount eq 99 OR action.params.amount eq 5)');
    expect(whereOf([{ not: NOPE }])).toBe('NOT action.params.amount eq 99');
    expect(whereOf([{ any_of: [{ all_of: 5 }, { any_of: 5 }, A] }])).toBe('(undefined undefined OR undefined undefined OR action.params.amount eq 5)');
    expect(whereOf([{ any_of: [null, 5, A] }])).toBe('(<malformed> OR <malformed> OR action.params.amount eq 5)');
  });
  it('stops rendering after seven levels of nesting', () => {
    const wrap = (key: 'all_of' | 'any_of', n: number): unknown => {
      let c: unknown = A;
      for (let i = 0; i < n; i++) c = { [key]: [c] };
      return c;
    };
    expect(whereOf([wrap('all_of', 7)])).toBe(`${'('.repeat(7)}…${')'.repeat(7)}`);
    expect(whereOf([wrap('any_of', 7)])).toBe(`${'('.repeat(7)}…${')'.repeat(7)}`);
    expect(whereOf([wrap('all_of', 6)])).toBe(`${'('.repeat(6)}action.params.amount eq 5${')'.repeat(6)}`);
    let n: unknown = NOPE;
    for (let i = 0; i < 7; i++) n = { not: n };
    expect(whereOf([n])).toBe(`${'NOT '.repeat(7)}…`);
  });
});
