/**
 * Natives -> reference: every native SDK's producer tests write conformance/producer-native/<lang>.json in their own CI run
 * (PCA_PRODUCER_OUT set). The reference verifier must accept every artifact a native signed, and must refuse it once a byte of
 * its signature changes (the post-quantum half when there is one, so that half is really checked, not skipped).
 *
 * File shape: `{lang, aud, now, cases: [{kind, alg, grant?, pcactn?, artifact?, pins?}]}`. `kind` defaults to `pcactn`. Each
 * language contributes one PCActn per suite it signs, a PCActn from a delegated sub-agent, one facade `act` with params, and one
 * of each artifact kind below. `pins` is the verifier-side configuration for the signer: `{pk, pq_pk?}`, plus `kid` (and `alg`)
 * for the site-signed kinds and `site` for labels.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyPCActnCore } from './pcactn-full';
import { verifyEscalationAnswer } from './escalation';
import { checkRevocationEpoch } from './revocation';
import { verifySessionRoot } from './intent-session';
import { verifyActionSchema } from './action-schema';
import { verifyIntentRequired } from './intent-required';
import { verifyLabels } from './label-receipts';
import { FACT_DOMAIN, validateFactWire } from './oracle-facts';
import { verifyArtifactSig } from './intent-artifacts';
import { verifyCaution } from './agent-native';
import { pqPinFor } from './pq';
import type { Capability } from './capability';
import type { PCActn } from './pcactn';

type Any = any; // eslint-disable-line @typescript-eslint/no-explicit-any
type Case = { kind?: string; alg: string; grant?: Capability; pcactn?: PCActn & { alg?: string; pq_sig?: string }; artifact?: Any; pins?: Any };
type Doc = { lang: string; aud: string; now: number; cases: Case[] };

const DIR = join(__dirname, '..', 'conformance', 'producer-native');
const docs: Doc[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')) as Doc);

const LANGS = ['dotnet', 'go', 'java', 'kotlin', 'php', 'python', 'ruby', 'rust', 'swift'];
const flip = (s: string): string => (s[10] === 'A' ? s.slice(0, 10) + 'B' + s.slice(11) : s.slice(0, 10) + 'A' + s.slice(11));
const pinOf = (p: Any) => ({ pk: p.pk, ...(p.pq_pk !== undefined ? { pq_pk: p.pq_pk } : {}) });
const pqPins = (p: Any): Record<string, string> => (p?.pq_pk !== undefined ? { [p.pk]: p.pq_pk } : {});
const schemaKey = (p: Any) => ({ kid: p.kid, alg: p.alg ?? 'ed25519', pk: p.pk, ...(p.pq_pk !== undefined ? { pq_pk: p.pq_pk } : {}) });

/** Accept-check per kind (true = the reference accepts it). */
const VERIFY: Record<string, (c: Case, d: Doc, a: Any) => boolean | Promise<boolean>> = {
  pcactn: async (c, d, p) => (await verifyPCActnCore(p, { grant: c.grant!, nowEpoch: d.now, audience: d.aud, insecureSkipPlanRootCheck: true })).allow,
  escalation_answer: (c, d, a) => verifyEscalationAnswer(a, [pinOf(c.pins)], { policy_digest: a.policy_digest, action_digest: a.action_digest, history_head: a.history_head, ...(a.render_digest !== undefined ? { render_digest: a.render_digest } : {}) }, d.now).ok,
  revocation_epoch: (c, d, a) => checkRevocationEpoch(a, { guardianPublic: c.pins.pk, now: d.now, pqPins: pqPins(c.pins) }).ok,
  session_root: (c, _d, a) => verifySessionRoot(a, { pqPins: pqPins(c.pins) }).ok,
  action_schema: (c, _d, a) => verifyActionSchema(a, [schemaKey(c.pins)]).ok,
  intent_required: (c, d, a) => verifyIntentRequired(a, [schemaKey(c.pins)], d.now).ok,
  labels: (c, _d, a) => verifyLabels(a, [{ site: c.pins.site, kid: c.pins.kid, ...pinOf(c.pins) }]) === null,
  fact: (c, _d, a) => validateFactWire(a) === null && verifyArtifactSig(FACT_DOMAIN, a, pinOf(c.pins)),
  caution: (c, _d, a) => verifyCaution(a, undefined, c.pins.pk),
  pq_binding: (_c, d, a) => pqPinFor(a, d.aud) !== null,
};

/** The same artifact with one signature byte changed: the PQ half when present, else the classical one. */
function tamper(kind: string, x: Any): Any {
  if (kind === 'action_schema' || kind === 'intent_required') {
    const field = x.sig.pq_value !== undefined ? 'pq_value' : 'value';
    return { ...x, sig: { ...x.sig, [field]: flip(x.sig[field]) } };
  }
  const field = x.pq_sig !== undefined ? 'pq_sig' : 'sig';
  return { ...x, [field]: flip(x[field]) };
}

describe('native producers: every signed artifact verifies under the reference', () => {
  it('every native SDK contributed its file', () => {
    expect(docs.map((d) => d.lang).sort()).toEqual(LANGS);
    for (const d of docs) expect(d.cases.length, d.lang).toBeGreaterThan(0);
  });

  for (const d of docs) {
    for (const [i, c] of d.cases.entries()) {
      const kind = c.kind ?? 'pcactn';
      it(`${d.lang}: #${i} ${kind} ${c.alg}`, async () => {
        const verify = VERIFY[kind];
        expect(verify, `no reference verifier for kind '${kind}'`).toBeDefined();
        const subject = kind === 'pcactn' ? c.pcactn : c.artifact;
        expect(subject, `${kind} case without its artifact`).toBeDefined();
        expect(await verify!(c, d, subject), 'the reference refused a native artifact').toBe(true);
        expect(await verify!(c, d, tamper(kind, subject)), 'a changed signature byte was accepted').toBe(false);
      });
    }
  }
});
