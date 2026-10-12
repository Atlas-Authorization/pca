/**
 * Mutation-kill tests for attestation.ts (part 1): binding construction, the dev attestor, the registry, the nonce store and entropy floor,
 * requiresAttestation, and matchAgentBinding. Every boundary is pinned on both sides and every refusal reason is asserted verbatim.
 */
import { describe, expect, it } from 'vitest';
import {
  attestationBinding,
  attestationBindingB64u,
  attestationDigest,
  attestationRegistry,
  createDevAttestor,
  matchAgentBinding,
  memoryNonceStore,
  nonceBinds,
  nonceEntropyOk,
  requiresAttestation,
  type MeasuredIdentity,
} from './attestation';
import { b64u, hashCanonical } from './hash';
import { generateKeyPair } from './keys';

const EXP = { holderPub: 'holder-pub', grantRef: 'grant-1', epoch: 3, nonce: 'n-0123456789abcdef' };
const CLAIMS = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: 'nonce-1', issued_at: 10, expires_at: 20 };

describe('attestationBinding validation', () => {
  it('rejects each malformed field with its own message', () => {
    expect(() => attestationBinding(null as never)).toThrow('binding: holderPub required');
    expect(() => attestationBinding({ ...EXP, holderPub: '' })).toThrow('binding: holderPub required');
    expect(() => attestationBinding({ ...EXP, holderPub: 5 as never })).toThrow('binding: holderPub required');
    expect(() => attestationBinding({ ...EXP, grantRef: '' })).toThrow('binding: grantRef required');
    expect(() => attestationBinding({ ...EXP, grantRef: 5 as never })).toThrow('binding: grantRef required');
    expect(() => attestationBinding({ ...EXP, nonce: '' })).toThrow('binding: nonce required');
    expect(() => attestationBinding({ ...EXP, nonce: 5 as never })).toThrow('binding: nonce required');
    expect(() => attestationBinding({ ...EXP, epoch: -1 })).toThrow('binding: epoch must be a non-negative safe integer');
    expect(() => attestationBinding({ ...EXP, epoch: 1.5 })).toThrow('binding: epoch must be a non-negative safe integer');
    expect(() => attestationBinding({ ...EXP, epoch: Number.MAX_SAFE_INTEGER + 1 })).toThrow('binding: epoch must be a non-negative safe integer');
  });
  it('accepts epoch 0 and the largest safe integer; different fields give different bindings; b64u form matches', () => {
    expect(attestationBinding({ ...EXP, epoch: 0 }).length).toBe(64);
    expect(attestationBinding({ ...EXP, epoch: Number.MAX_SAFE_INTEGER }).length).toBe(64);
    const base = b64u(attestationBinding(EXP));
    expect(attestationBindingB64u(EXP)).toBe(base);
    for (const o of [{ holderPub: 'h2' }, { grantRef: 'g2' }, { epoch: 4 }, { nonce: 'n2' }]) expect(attestationBindingB64u({ ...EXP, ...o })).not.toBe(base);
  });
});

describe('createDevAttestor', () => {
  const kp = generateKeyPair();
  it('rejects an unknown signature alg by name', () => {
    expect(() => createDevAttestor(kp.secretKey, { alg: 'bogus' as never })).toThrow("createDevAttestor: unknown signature alg 'bogus'");
  });
  it('binds only when holder_pub, grant_ref and epoch are ALL supplied (epoch 0 counts)', () => {
    const a = createDevAttestor(kp.secretKey);
    const doc = (o: object) => a.attest({ ...CLAIMS, ...o });
    expect(doc({ holder_pub: 'h', grant_ref: 'g', epoch: 0 }).binding).toBe(attestationBindingB64u({ holderPub: 'h', grantRef: 'g', epoch: 0, nonce: 'nonce-1' }));
    for (const partial of [{ holder_pub: 'h' }, { grant_ref: 'g' }, { epoch: 1 }, { holder_pub: 'h', grant_ref: 'g' }, { holder_pub: 'h', epoch: 1 }, { grant_ref: 'g', epoch: 1 }, {}]) {
      expect(doc(partial).binding).toBeUndefined();
    }
  });
  it('carries the prompt / tool digests only when supplied, and the document digest is the canonical hash', () => {
    const a = createDevAttestor(kp.secretKey);
    const plain = a.attest(CLAIMS);
    expect('system_prompt_digest' in plain).toBe(false);
    expect('tool_manifest_digest' in plain).toBe(false);
    const full = a.attest({ ...CLAIMS, system_prompt_digest: 'sp', tool_manifest_digest: 'tm' });
    expect(full.system_prompt_digest).toBe('sp');
    expect(full.tool_manifest_digest).toBe('tm');
    expect(attestationDigest(full)).toBe(hashCanonical(full));
    expect(attestationDigest(full)).not.toBe(attestationDigest(plain));
  });
});

describe('attestationRegistry and nonceBinds', () => {
  const a = createDevAttestor(generateKeyPair().secretKey);
  const d1 = a.attest({ ...CLAIMS, nonce: 'k1' });
  const ctxFor = (q: unknown) => ({ pcactn: { attestation: { quote_digest: q } } }) as never;
  it('resolves by the PCActn quote_digest; later duplicates overwrite; junk entries are skipped', () => {
    const d2 = { ...d1, model_id: 'second' };
    const res = attestationRegistry([null as never, { nonce: 5 } as never, d1, d2]);
    expect(res(ctxFor('k1'))).toBe(d2);
    expect(res(ctxFor('nope'))).toBeUndefined();
    expect(res(ctxFor(5))).toBeUndefined();
  });
  it('never throws on a missing ctx / pcactn / attestation, and a non-array input resolves nothing', () => {
    const res = attestationRegistry([d1]);
    expect(res(undefined as never)).toBeUndefined();
    expect(res({} as never)).toBeUndefined();
    expect(res({ pcactn: {} } as never)).toBeUndefined();
    expect(attestationRegistry('x' as never)(ctxFor('k1'))).toBeUndefined();
  });
  it('nonceBinds is true only for an equal string nonce', () => {
    expect(nonceBinds(d1, ctxFor('k1'))).toBe(true);
    expect(nonceBinds(d1, ctxFor('k2'))).toBe(false);
    expect(nonceBinds({ ...d1, nonce: 5 as never }, ctxFor(5))).toBe(false);
    expect(nonceBinds(undefined as never, ctxFor('k1'))).toBe(false);
    expect(nonceBinds(d1, undefined as never)).toBe(false);
    expect(nonceBinds(d1, {} as never)).toBe(false);
    expect(nonceBinds(d1, { pcactn: {} } as never)).toBe(false);
    expect(nonceBinds({ ...d1, nonce: undefined as never }, { pcactn: { attestation: {} } } as never)).toBe(false);
  });
});

describe('memoryNonceStore', () => {
  it('consumes once; holds exactly `max` live entries then refuses (never evicts a retained nonce)', () => {
    const s = memoryNonceStore(2);
    expect(s.consume('a')).toBe(true);
    expect(s.consume('a')).toBe(false);
    expect(s.consume('b')).toBe(true);
    expect(s.consume('a')).toBe(false); // size == max
    expect(s.consume('b')).toBe(false);
    expect(s.consume('c')).toBe(false); // full of retained nonces: refused, fail closed
    expect(s.consume('a')).toBe(false); // and 'a' was NOT evicted: no replay window
    expect(s.consume('b')).toBe(false);
  });
  it('makes room only from nonces that aged out of retention', () => {
    let t = 0;
    const s = memoryNonceStore(2, { retentionMs: 100, now: () => t });
    expect(s.consume('a')).toBe(true);
    t = 50;
    expect(s.consume('b')).toBe(true);
    t = 99;
    expect(s.consume('c')).toBe(false); // nothing aged out yet
    t = 100; // 'a' (t=0) aged out exactly at retention; 'b' (t=50) still live
    expect(s.consume('c')).toBe(true);
    expect(s.consume('b')).toBe(false);
    expect(s.consume('c')).toBe(false);
  });
  it('defaults to a large bound', () => {
    const s = memoryNonceStore();
    for (let i = 0; i < 50; i++) expect(s.consume(`n${i}`)).toBe(true);
    expect(s.consume('n0')).toBe(false);
  });
});

describe('nonceEntropyOk', () => {
  const hex = (n: number) => Array.from({ length: n }, (_, i) => '0123456789abcdef'[i % 16]).join('');
  const b64 = (n: number) => Array.from({ length: n }, (_, i) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'[i % 32]).join('');
  it('non-strings fail', () => {
    for (const v of [undefined, null, 5, {}, ['a']]) expect(nonceEntropyOk(v)).toBe(false);
  });
  it('hex needs >= 32 digits (16 bytes)', () => {
    expect(nonceEntropyOk(hex(32))).toBe(true);
    expect(nonceEntropyOk(hex(31))).toBe(false);
    expect(nonceEntropyOk(hex(30))).toBe(false);
    expect(nonceEntropyOk(hex(64))).toBe(true);
    expect(nonceEntropyOk(hex(31) + 'F')).toBe(true); // upper-case hex
  });
  it('base64url needs >= 22 characters (floor(3n/4) >= 16)', () => {
    expect(nonceEntropyOk(b64(22))).toBe(true);
    expect(nonceEntropyOk(b64(21))).toBe(false);
    expect(nonceEntropyOk('ghijklmnopqrstuvwxyzGHIJ')).toBe(true); // not hex: the base64url branch applies (24 chars -> 18 bytes)
    expect(nonceEntropyOk('ghijklmnopqrstuvwxyzGHI-_')).toBe(true);
  });
  it('anchored: a valid run with junk before or after is refused', () => {
    expect(nonceEntropyOk(hex(32) + '!')).toBe(false);
    expect(nonceEntropyOk('!' + hex(32))).toBe(false);
    expect(nonceEntropyOk(hex(32) + ' ')).toBe(false);
    expect(nonceEntropyOk('abcdefgh!ijklmnop!qrstuv!wxyz')).toBe(false); // plenty long and varied, but not in either alphabet
    expect(nonceEntropyOk(b64(30) + '+')).toBe(false);
    expect(nonceEntropyOk('+' + b64(30))).toBe(false);
  });
  it('needs at least 8 distinct characters', () => {
    expect(nonceEntropyOk('abcdefgh'.repeat(4))).toBe(true); // exactly 8 distinct
    expect(nonceEntropyOk('abcdefg'.repeat(5))).toBe(false); // 7 distinct (35 chars)
    expect(nonceEntropyOk('a'.repeat(40))).toBe(false);
  });
  it('minBytes raises the bar but can never lower it below 16', () => {
    expect(nonceEntropyOk(hex(32), 20)).toBe(false);
    expect(nonceEntropyOk(hex(40), 20)).toBe(true);
    expect(nonceEntropyOk(hex(32), 4)).toBe(true);
    expect(nonceEntropyOk(hex(30), 4)).toBe(false);
  });
});

describe('requiresAttestation', () => {
  it('is false for no / empty / inert bindings', () => {
    for (const b of [undefined, {}, { model_allowlist: [] }, { weights_allowlist: [] }, { system_prompt_allowlist: [] }, { tool_manifest_allowlist: [] }, { operator: '' }, { min_measurement: '' }, { min_measurement: { svn: NaN } }, { min_measurement: {} }, { min_measurement: { svn: '3' } }, { require_hardware: false }, { require_measured_weights: false }, { model_allowlist: 'x' }, { operator: 5 }] as never[]) {
      expect(requiresAttestation(b)).toBe(false);
    }
  });
  it('each single constraint makes it true', () => {
    for (const b of [{ model_allowlist: ['m'] }, { weights_allowlist: ['w'] }, { system_prompt_allowlist: ['s'] }, { tool_manifest_allowlist: ['t'] }, { operator: 'o' }, { min_measurement: 'x' }, { min_measurement: { svn: 0 } }, { min_measurement: { svn: 7 } }, { require_hardware: true }, { require_measured_weights: true }] as never[]) {
      expect(requiresAttestation(b)).toBe(true);
    }
  });
});

describe('matchAgentBinding', () => {
  const id: MeasuredIdentity = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r1', operator: 'o' };
  it('an absent / empty binding matches anything', () => {
    expect(matchAgentBinding(id, undefined)).toBeNull();
    expect(matchAgentBinding(id, {})).toBeNull();
    expect(matchAgentBinding(id, { model_allowlist: [], weights_allowlist: [], system_prompt_allowlist: [], tool_manifest_allowlist: [], operator: '', min_measurement: '' })).toBeNull();
  });
  it('model_allowlist', () => {
    expect(matchAgentBinding(id, { model_allowlist: ['m', 'x'] })).toBeNull();
    expect(matchAgentBinding(id, { model_allowlist: ['x'] })).toBe('model_id m not in model_allowlist');
  });
  it('operator', () => {
    expect(matchAgentBinding(id, { operator: 'o' })).toBeNull();
    expect(matchAgentBinding(id, { operator: 'p' })).toBe('operator o is not the bound operator');
  });
  it('min_measurement as an equality pin', () => {
    expect(matchAgentBinding(id, { min_measurement: 'r1' })).toBeNull();
    expect(matchAgentBinding(id, { min_measurement: 'r2' })).toBe('runtime_measurement does not match required min_measurement');
  });
  it('min_measurement as an svn lower bound', () => {
    const at = (rm: string, svn: number) => matchAgentBinding({ ...id, runtime_measurement: rm }, { min_measurement: { svn } });
    expect(at('5', 5)).toBeNull();
    expect(at('6', 5)).toBeNull();
    expect(at('4', 5)).toBe('runtime_measurement svn 4 is below required min svn 5');
    expect(at('0', 0)).toBeNull();
    expect(at('abc', 5)).toBe('runtime_measurement abc is not an integer SVN (required min svn 5)');
    expect(at('4.5', 5)).toBe('runtime_measurement 4.5 is not an integer SVN (required min svn 5)');
    expect(at('', 0)).toBe('runtime_measurement  is not an integer SVN (required min svn 0)');
    expect(at('  ', 0)).toBe('runtime_measurement    is not an integer SVN (required min svn 0)');
    expect(at('5', Number.NaN)).toBeNull(); // malformed lower bound: nothing to enforce
    expect(at('abc', Number.POSITIVE_INFINITY)).toBeNull();
    expect(matchAgentBinding(id, { min_measurement: { svn: '5' } as never })).toBeNull(); // non-numeric svn: ignored
    expect(matchAgentBinding(id, { min_measurement: null as never })).toBeNull();
  });
  it('weights_allowlist and require_measured_weights', () => {
    expect(matchAgentBinding(id, { weights_allowlist: ['w'] })).toBeNull();
    expect(matchAgentBinding(id, { weights_allowlist: ['x'] })).toBe('weights_digest not in weights_allowlist (model swap / fine-tune?)');
    const msg = 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)';
    expect(matchAgentBinding(id, { require_measured_weights: true })).toBe(msg);
    expect(matchAgentBinding({ ...id, weights_measured: false }, { require_measured_weights: true })).toBe(msg);
    expect(matchAgentBinding({ ...id, weights_measured: true }, { require_measured_weights: true })).toBeNull();
    expect(matchAgentBinding(id, { require_measured_weights: false })).toBeNull();
  });
  it('system prompt and tool manifest pins fail closed when the identity carries no digest', () => {
    const sp = 'system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)';
    expect(matchAgentBinding(id, { system_prompt_allowlist: ['s'] })).toBe(sp);
    expect(matchAgentBinding({ ...id, system_prompt_digest: 'x' }, { system_prompt_allowlist: ['s'] })).toBe(sp);
    expect(matchAgentBinding({ ...id, system_prompt_digest: 's' }, { system_prompt_allowlist: ['s'] })).toBeNull();
    const tm = 'tool_manifest_digest not in tool_manifest_allowlist (tools changed?)';
    expect(matchAgentBinding(id, { tool_manifest_allowlist: ['t'] })).toBe(tm);
    expect(matchAgentBinding({ ...id, tool_manifest_digest: 'x' }, { tool_manifest_allowlist: ['t'] })).toBe(tm);
    expect(matchAgentBinding({ ...id, tool_manifest_digest: 't' }, { tool_manifest_allowlist: ['t'] })).toBeNull();
    expect(matchAgentBinding(id, { system_prompt_allowlist: 's' as never, tool_manifest_allowlist: 't' as never })).toBeNull(); // non-array pins are not constraints
  });
});
