/**
 * Mutation-kill tests for validateWireV2 (wire.ts): every refusal is asserted by its EXACT reason. Many wire branches
 * are layered (a missing field would also fail a later type check), so a test that only checks "invalid" cannot see a
 * dropped guard; the exact reason can. Each case starts from a valid, signed PCActn (structurally cloned) and breaks one
 * thing; boundary values on the accepting side are checked too.
 */
import { describe, expect, it } from 'vitest';
import { decodeB64uStrict } from './hash';
import { validateSignatureWire } from './pq';
import { setup } from './server/fixture.test-util';
import { MAX_AUD_LEN, MAX_NONCE_LEN, validateWireV2 } from './wire';

type P = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const s = setup();
const BASE: P = JSON.parse(JSON.stringify(s.mk(s.plan[1]!)));
const B32 = BASE.grant_ref as string; // a valid canonical 32-byte b64u value
const SIG64 = (BASE.cap_chain[0] as P).sig as string;
const mk = (f: (p: P) => void): P => {
  const p: P = JSON.parse(JSON.stringify(BASE));
  f(p);
  return p;
};
const check = (f: (p: P) => void, want: string | null) => expect(validateWireV2(mk(f))).toBe(want);

describe('validateWireV2: base and top level', () => {
  it('the base PCActn is well-formed', () => {
    expect(validateWireV2(BASE)).toBeNull();
    expect(BASE.cap_chain).toHaveLength(2);
    expect(BASE.plan.inclusion_proof.path.length).toBeGreaterThan(0);
  });
  it('non-objects (incl. null / undefined / arrays / class instances)', () => {
    for (const v of [null, undefined, [], 5, 'x', new Date(0), () => 1]) expect(validateWireV2(v)).toBe('PCActn is not an object');
  });
  it('unknown and missing fields', () => {
    check((p) => (p.zzz = 1), "unknown field 'zzz'");
    check((p) => delete p.sig, "missing field 'sig'");
    check((p) => delete p.risk_claim, "missing field 'risk_claim'");
  });
  it('integers', () => {
    check((p) => (p.ver = '2'), "'ver' must be a safe integer");
    check((p) => (p.counter = '1'), "'counter' must be a safe integer");
    check((p) => (p.iat = '1'), "'iat' must be a safe integer");
    check((p) => (p.exp = '1'), "'exp' must be a safe integer");
  });
  it('aud: non-empty, <= 256 UTF-8 bytes (inclusive)', () => {
    const AUD_ERR = "'aud' must be a non-empty string (<= 256 UTF-8 bytes)";
    check((p) => (p.aud = ''), AUD_ERR);
    check((p) => (p.aud = 5), AUD_ERR);
    check((p) => (p.aud = 'a'.repeat(MAX_AUD_LEN + 1)), AUD_ERR);
    check((p) => (p.aud = 'é'.repeat(MAX_AUD_LEN / 2 + 1)), AUD_ERR); // 258 UTF-8 bytes, 129 UTF-16 units
    expect(validateWireV2(mk((p) => (p.aud = 'a'.repeat(MAX_AUD_LEN))))).not.toBe(AUD_ERR);
  });
  it('nonce: optional; when present non-empty, <= 128 UTF-8 bytes (inclusive)', () => {
    const N_ERR = "'nonce' must be a non-empty string (<= 128 UTF-8 bytes)";
    check((p) => (p.nonce = ''), N_ERR);
    check((p) => (p.nonce = 5), N_ERR);
    check((p) => (p.nonce = 'n'.repeat(MAX_NONCE_LEN + 1)), N_ERR);
    expect(validateWireV2(mk((p) => (p.nonce = 'n'.repeat(MAX_NONCE_LEN))))).not.toBe(N_ERR);
  });
  it('grant_ref', () => {
    check((p) => (p.grant_ref = 'x'), "'grant_ref' is not canonical base64url (32 bytes)");
  });
  it('a throwing accessor is reported as malformed', () => {
    const p = mk(() => {});
    Object.defineProperty(p, 'ver', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    expect(validateWireV2(p)).toBe('malformed: boom');
  });
});

describe('validateWireV2: action and plan', () => {
  it('action', () => {
    check((p) => (p.action = []), "'action' must be an object");
    check((p) => (p.action.x = 1), "unknown field 'action.x'");
    for (const k of ['verb', 'resource', 'reversibility_class']) check((p) => (p.action[k] = 5), 'action.verb/resource/reversibility_class must be strings');
    check((p) => (p.action.params_digest = 'x'), "'action.params_digest' is not canonical base64url (32 bytes)");
  });
  it('plan', () => {
    check((p) => (p.plan = 'x'), "'plan' must be an object");
    check((p) => (p.plan.x = 1), "unknown field 'plan.x'");
    check((p) => (p.plan.root = 'x'), "'plan.root' is not canonical base64url (32 bytes)");
    check((p) => (p.plan.node_id = 5), "'plan.node_id' must be a string");
    check((p) => (p.plan.conditions_digest = 'x'), "'plan.conditions_digest' must be a canonical base64url string (32 bytes)");
    check((p) => delete p.plan.conditions_digest, null);
  });
  it('inclusion proof', () => {
    check((p) => (p.plan.inclusion_proof = []), "'plan.inclusion_proof' must be an object");
    check((p) => (p.plan.inclusion_proof.x = 1), "unknown field 'plan.inclusion_proof.x'");
    check((p) => (p.plan.inclusion_proof.index = '0'), "'plan.inclusion_proof.index' must be a safe integer");
    check((p) => (p.plan.inclusion_proof.size = '2'), "'plan.inclusion_proof.size' must be a safe integer");
    check((p) => (p.plan.inclusion_proof.path = {}), "'plan.inclusion_proof.path' must be an array");
    check((p) => (p.plan.inclusion_proof.path = ['x']), 'proof step 0 must be an object');
    check((p) => (p.plan.inclusion_proof.path[0].z = 1), "unknown field 'path[0].z'");
    check((p) => (p.plan.inclusion_proof.path[0].side = 'X'), "proof step 0: side must be 'L' or 'R'");
    check((p) => (p.plan.inclusion_proof.path[0].side = 'R'), null);
    check((p) => (p.plan.inclusion_proof.path[0].side = 'L'), null);
    check((p) => (p.plan.inclusion_proof.path[0].hash = 'x'), 'proof step 0: hash is not canonical base64url (32 bytes)');
  });
});

describe('validateWireV2: capability chain', () => {
  it('container and hop shape', () => {
    check((p) => (p.cap_chain = {}), "'cap_chain' must be an array");
    check((p) => (p.cap_chain = [5]), 'cap_chain[0] must be an object');
    check((p) => (p.cap_chain[1].zz = 1), "unknown field 'cap_chain[1].zz'");
    for (const k of ['id', 'issuer', 'holder', 'body_digest']) check((p) => (p.cap_chain[0][k] = 'x'), `cap_chain[0].${k} is not canonical base64url (32 bytes)`);
  });
  it('hop signature wire carries the suite validator reason', () => {
    const p = mk((q) => (q.cap_chain[1].sig = 'x'));
    expect(validateWireV2(p)).toBe(`cap_chain[1]: ${validateSignatureWire(p.cap_chain[1], decodeB64uStrict)}`);
    expect(validateSignatureWire(p.cap_chain[1], decodeB64uStrict)).toBeTypeOf('string');
  });
  it('parent / holder_pq / caveats', () => {
    check((p) => (p.cap_chain[1].parent = 'x'), 'cap_chain[1].parent is not canonical base64url (32 bytes)');
    check((p) => (p.cap_chain[0].holder_pq = 'x'), 'cap_chain[0].holder_pq is not canonical base64url (32 bytes)');
    check((p) => (p.cap_chain[0].holder_pq = B32), null);
    const CV = 'cap_chain[0].caveats must be an array of {type,...} objects';
    check((p) => (p.cap_chain[0].caveats = {}), CV);
    check((p) => (p.cap_chain[0].caveats = [5]), CV);
    check((p) => (p.cap_chain[0].caveats = [{}]), CV);
    check((p) => (p.cap_chain[0].caveats = [{ type: 5 }]), CV);
  });
});

describe('validateWireV2: attestation / provenance / freshness / risk_claim', () => {
  it('attestation', () => {
    const E = "'attestation' must be an object with an integer 'epoch'";
    check((p) => (p.attestation = []), E);
    check((p) => (p.attestation.epoch = '0'), E);
    for (const k of ['quote_digest', 'model_id', 'measurement', 'operator']) check((p) => (p.attestation[k] = 5), 'attestation string fields must be strings');
  });
  it('provenance', () => {
    const E = "'provenance' is malformed";
    check((p) => (p.provenance = []), E);
    check((p) => (p.provenance.causal_hash = 5), E);
    check((p) => (p.provenance.taint_level = '0'), E);
    check((p) => (p.provenance.trusted_refs = 'x'), E);
    check((p) => (p.provenance.trusted_refs = [5]), E);
    check((p) => (p.provenance.trusted_refs = ['ok']), null);
  });
  it('freshness', () => {
    const E = "'freshness' is malformed";
    check((p) => (p.freshness = []), E);
    check((p) => (p.freshness.epoch = '0'), E);
    check((p) => (p.freshness.beacon_ref = 5), E);
    check((p) => (p.freshness.accumulator_witness = 5), E);
  });
  it('risk_claim', () => {
    const E = "'risk_claim' is malformed";
    check((p) => (p.risk_claim = []), E);
    check((p) => (p.risk_claim.r = '0'), E);
    check((p) => (p.risk_claim.inputs = 'x'), E);
  });
});

describe('validateWireV2: optional slots', () => {
  it('caution in [0,1] inclusive', () => {
    const E = "'caution' must be a number in [0,1]";
    check((p) => (p.caution = -0.5), E);
    check((p) => (p.caution = 1.5), E);
    check((p) => (p.caution = '0.5'), E);
    check((p) => (p.caution = 0), null);
    check((p) => (p.caution = 1), null);
  });
  it('rationale_commitment / tool_binding / progress_step / prohibition_evidence', () => {
    check((p) => (p.rationale_commitment = 'x'), "'rationale_commitment' is not canonical base64url (32 bytes)");
    check((p) => (p.rationale_commitment = B32), null);
    check((p) => (p.tool_binding = 'x'), "'tool_binding' is not canonical base64url (32 bytes)");
    check((p) => (p.tool_binding = B32), null);
    check((p) => (p.progress_step = 5), "'progress_step' must be an object");
    check((p) => (p.progress_step = {}), null);
    check((p) => (p.prohibition_evidence = 5), "'prohibition_evidence' must be an object or array");
    check((p) => (p.prohibition_evidence = []), null);
    check((p) => (p.prohibition_evidence = {}), null);
  });
  it('threshold shares', () => {
    check((p) => (p.threshold = 5), "'threshold' must be {shares:[...]}");
    check((p) => (p.threshold = { shares: 'x' }), "'threshold' must be {shares:[...]}");
    check((p) => (p.threshold = { shares: [5] }), 'threshold.shares[0] is malformed');
    check((p) => (p.threshold = { shares: [{ role: 5 }] }), 'threshold.shares[0] is malformed');
    check((p) => (p.threshold = { shares: [{ role: 'agent', publicKey: 'x', sig: SIG64 }] }), 'threshold.shares[0].publicKey is not canonical base64url (32 bytes)');
    // 0.4.1: share signature fields are validated per suite (validateShareSignatureWire), prefixed with the share index
    check((p) => (p.threshold = { shares: [{ role: 'agent', publicKey: B32, sig: 'x' }] }), "threshold.shares[0]: 'sig' is not canonical base64url (64 bytes) for alg 'ed25519'");
    check((p) => (p.threshold = { shares: [{ role: 'agent', publicKey: B32, sig: SIG64 }] }), null);
  });
});
