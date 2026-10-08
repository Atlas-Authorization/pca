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
  verifyWithSuite,
  type Capability,
  type PCActn,
} from './index';

/** The TS reference must satisfy EVERY golden vector (the same file the 8 language verifiers consume). */
const file = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'vectors.json'), 'utf8')) as {
  format: number;
  primitives: {
    canonical: { value: unknown; expect: string }[];
    json_parse: { input: string; accept: boolean; canonical?: string }[];
    b64u: { input: string; valid: boolean; len?: number }[];
    merkle: { leaves: unknown[]; root: string; proofs: never[] }[];
    threshold_share: {
      role: string;
      t: number;
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
    context: { now: number; aud: string };
    pcactn?: PCActn;
    pcactn_json?: string;
    expect: { allow: boolean; checks: Record<string, boolean> };
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
      const r = await verifyPCActnCore(p!, { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud });
      expect(r.allow).toBe(v.expect.allow);
      const got: Record<string, boolean> = {};
      for (const k of Object.keys(v.expect.checks)) got[k] = r.checks[KEY[k] ?? k] === 'pass';
      expect(got).toEqual(v.expect.checks);
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
      const got = verifyWithSuite(
        e.share.alg,
        { edPub: e.share.publicKey, mlDsaPub: e.share.pq_pk },
        msg!,
        { sig: e.share.sig, pq_sig: e.share.pq_sig },
      );
      expect(got, `${e.role}/t${e.t}`).toBe(e.valid ?? true);
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
