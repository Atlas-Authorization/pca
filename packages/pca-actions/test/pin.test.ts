// The pin is T6 made operational (spec section 7.2): a grant that pinned a definition follows a change only when it provably
// narrowed, or when the principal approved it. Property tests over random definitions and mutations, with real signatures.
import { generateKeyPair } from '@atlasauth/pca';
import { decidePin, registryKeyOf, signEvolutionRecord, signReapproval } from '@atlasauth/pca/ext/intent';
import { describe, expect, it } from 'vitest';
import { defDigest, diffDefs, evolutionRecords, validateDef } from '../src';
import { mutate } from './mutate';
import { genDef, rng } from './vectors-gen';
import { runs } from './runs';

const reg = generateKeyPair();
const principal = generateKeyPair();
const KEYS = [registryKeyOf('reg-1', reg.secretKey)];
const grant = { id: 'G'.repeat(43), issuer: Buffer.from(principal.publicKey).toString('base64url') };
const ROOT = 'R'.repeat(43);

describe('pin follows a change only when the registry signed equal/narrow or the principal approved', () => {
  it('for random definitions and mutations (property, signed records, 3x10^4 cases in CI)', () => {
    const r = rng(0x71a001);
    const n = runs(30_000); // each case signs and verifies real Ed25519 records; the 10^5 oracle is the diff test
    let free = 0;
    let blocked = 0;
    for (let i = 0; i < n; i++) {
      const base = genDef(r, i);
      if (validateDef(base) !== null) continue;
      const m = mutate(base, r);
      if (m === null) continue;
      const from = defDigest(base);
      const to = defDigest(m);
      if (from === to) continue;
      const unsigned = evolutionRecords('t', [base], [m])[0]!;
      const rec = signEvolutionRecord(unsigned, 'reg-1', reg.secretKey);
      const pin = { pack: { ns: 't', root: ROOT }, defs: { [base.verb]: from }, on_new_action: 'deny' as const };
      const input = { pin, doc: { pack: { ns: 't', root: ROOT }, verbs: [{ verb: base.verb, def: to }] }, verb: base.verb, records: [rec], keys: KEYS, grant };
      const cls = diffDefs(base, m).class;
      const plain = decidePin({ ...input, reapprovals: [] });
      if (cls === 'equal' || cls === 'narrow') {
        free++;
        expect(plain, cls).toEqual({ ok: true, via: 'chain' });
      } else {
        blocked++;
        expect(plain.ok, cls).toBe(false);
        const approved = decidePin({ ...input, reapprovals: [signReapproval({ grantId: grant.id, record: rec, principalSecret: principal.secretKey })] });
        expect(approved, cls).toEqual({ ok: true, via: 'chain' });
        // approval by anyone but the grant's principal, or for another grant, changes nothing (sampled: each is a signature check)
        if (blocked % 16 === 1) {
          expect(decidePin({ ...input, reapprovals: [signReapproval({ grantId: grant.id, record: rec, principalSecret: reg.secretKey })] }).ok).toBe(false);
          expect(decidePin({ ...input, reapprovals: [signReapproval({ grantId: 'H'.repeat(43), record: rec, principalSecret: principal.secretKey })] }).ok).toBe(false);
        }
      }
    }
    expect(free).toBeGreaterThan(0);
    expect(blocked).toBeGreaterThan(0);
  }, 1_800_000);

  it('registry growth never grants: any verb a pack gains is new_action to every pinned grant', () => {
    const r = rng(0x71a002);
    for (let i = 0; i < runs(2000); i++) {
      const pinned = genDef(r, i);
      const added = genDef(r, i + 100_000);
      if (validateDef(pinned) !== null || validateDef(added) !== null || pinned.verb === added.verb) continue;
      const pin = { pack: { ns: 't', root: ROOT }, defs: { [pinned.verb]: defDigest(pinned) }, on_new_action: 'deny' as const };
      const rec = signEvolutionRecord(evolutionRecords('t', [pinned], [pinned, added])[0]!, 'reg-1', reg.secretKey);
      const d = decidePin({ pin, doc: { pack: { ns: 't', root: 'S'.repeat(43) }, verbs: [{ verb: pinned.verb, def: defDigest(pinned) }, { verb: added.verb, def: defDigest(added) }] }, verb: added.verb, records: [rec], keys: KEYS, grant });
      expect(d).toMatchObject({ ok: false, code: 'new_action', escalate: false });
    }
  });
});
