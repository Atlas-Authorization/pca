import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  canonicalizeStrict,
  decodeB64uStrict,
  decodePCActn,
  merkleRoot,
  strictParse,
  verifyInclusion,
  verifyPCActnCore,
  type Capability,
  type PCActn,
} from './index';
import { type IntentPolicy } from './ext/intent';
import { verifyWithSuite } from './pq-test-support';
import { type Signer, type ThresholdShare, verifyThreshold } from './threshold';

/** The TS reference must satisfy EVERY golden vector (the same file the 8 language verifiers consume). */
const file = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'vectors.json'), 'utf8')) as {
  format: number;
  primitives: {
    canonical: { value: unknown; expect: string }[];
    json_parse: { input: string; accept: boolean; canonical?: string }[];
    b64u: { input: string; valid: boolean; len?: number }[];
    merkle: { leaves: unknown[]; root: string; proofs: never[] }[];
    threshold_share: {
      name?: string;
      role: string;
      t: number;
      signer_set: unknown[];
      threshold_message: string;
      valid?: boolean;
      share_message: string;
      share: { role: string; publicKey: string; sig: string; alg?: string; pq_sig?: string; pq_pk?: string };
    }[];
    pq_artifact?: {
      artifact: string;
      alg: string;
      valid: boolean;
      ed_pub: string;
      pq_pk?: string;
      message: string;
      sig: string;
      pq_sig?: string;
    }[];
  };
  agent_leaf_binding?: string;
  vectors: {
    name: string;
    grant: Capability;
    context: { now: number; aud: string; allowed_suites?: string[]; intent_policy?: IntentPolicy; intent_policy_json?: string; intent_v2?: unknown };
    pcactn?: PCActn;
    pcactn_json?: string;
    expect: { allow: boolean; checks: Record<string, boolean>; reason_contains?: string };
  }[];
};

const KEY: Record<string, string> = { chain: 'cap_chain' };

describe('conformance vectors (wire v2)', () => {
  it('is format 2', () => expect(file.format).toBe(2));
  for (const v of file.vectors) {
    it(v.name, async () => {
      let p: PCActn | undefined;
      let parseFailed = false;
      if (v.pcactn_json !== undefined) {
        try {
          p = decodePCActn(v.pcactn_json);
        } catch {
          parseFailed = true;
        }
      } else p = v.pcactn;
      if (parseFailed) {
        expect(v.expect).toEqual({ allow: false, checks: { wire: false } });
        return;
      }
      // Intent Layer v2 (rules 13-15, 19): `context.intent_v2` is the VERIFIER state (schemas, session root, accumulators,
      // map disclosure), passed as-is, exactly as the generator (scripts/gen-conformance-intent-v2.mjs) and every native
      // driver do. Without it every v2 check reports "no ... configured".
      const r = await verifyPCActnCore(p!, { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud, ...(v.context.allowed_suites !== undefined ? { allowedSuites: v.context.allowed_suites as never } : {}), ...(v.context.intent_policy_json !== undefined ? { intent: JSON.parse(v.context.intent_policy_json) as IntentPolicy } : v.context.intent_policy !== undefined ? { intent: v.context.intent_policy } : {}), ...(v.context.intent_v2 !== undefined ? { intentV2: v.context.intent_v2 as never } : {}) });
      expect(r.allow).toBe(v.expect.allow);
      if (v.expect.reason_contains !== undefined) expect(String(r.reason ?? '')).toContain(v.expect.reason_contains);
      const got: Record<string, boolean> = {};
      for (const k of Object.keys(v.expect.checks)) got[k] = r.checks[KEY[k] ?? k] === 'pass';
      expect(got).toEqual(v.expect.checks);
      // Intent Layer M2: the `intent` check is reported iff the vector expects it (absent == pre-M2 verdict).
      expect('intent' in r.checks).toBe('intent' in v.expect.checks);
      if (v.expect.checks.wire === false) expect(Object.keys(r.checks)).toEqual(['wire']);
    });
  }
  it('primitives: canonical, strict JSON, strict base64url, merkle', () => {
    for (const c of file.primitives.canonical) expect(canonicalizeStrict(c.value)).toBe(c.expect);
    for (const j of file.primitives.json_parse) {
      if (j.accept) expect(canonicalizeStrict(strictParse(j.input))).toBe(j.canonical);
      else expect(() => strictParse(j.input), j.input).toThrow();
    }
    for (const b of file.primitives.b64u) expect(decodeB64uStrict(b.input, b.len) !== null, b.input).toBe(b.valid);
    for (const m of file.primitives.merkle) {
      expect(merkleRoot(m.leaves)).toBe(m.root);
      m.leaves.forEach((_l, i) => expect(verifyInclusion(m.root, m.proofs[i]!, m.leaves[i])).toBe(true));
    }
  });

  it('primitives: threshold shares verify over their role/set/t-bound share_message (incl. v2.1 agent binding)', () => {
    for (const e of file.primitives.threshold_share) {
      const msg = decodeB64uStrict(e.share_message);
      expect(msg, `share_message not canonical b64u for ${e.role}/t${e.t}`).not.toBeNull();
      // Truth is the signer-set-aware reference (R5-A1 pinning, R6-02 PQ-required), not a self-vouched suite check.
      const th = decodeB64uStrict(e.threshold_message)!;
      const v = verifyThreshold({ shares: [e.share as ThresholdShare] }, th, e.signer_set as Signer[], e.t);
      // the share counted for its role (a lone guardian share at t=2 is valid but does not meet t by itself)
      const got = v.roles.includes(e.role as Signer['role']);
      expect(got, `${e.name ?? e.role}/t${e.t}`).toBe(e.valid ?? true);
    }
  });

  it('primitives: PQ artifact signatures verify over their message under every suite (shared agility seam)', () => {
    for (const e of file.primitives.pq_artifact ?? []) {
      const msg = decodeB64uStrict(e.message);
      expect(msg, `message not canonical b64u for ${e.artifact}/${e.alg}`).not.toBeNull();
      const got = verifyWithSuite(
        e.alg,
        { edPub: e.ed_pub, mlDsaPub: e.pq_pk, slhDsaPub: e.pq_pk, mlDsa87Pub: e.pq_pk, slhDsa256sPub: e.pq_pk },
        msg!,
        { sig: e.sig, pq_sig: e.pq_sig },
      );
      expect(got, `${e.artifact}/${e.alg}`).toBe(e.valid);
    }
  });
});
