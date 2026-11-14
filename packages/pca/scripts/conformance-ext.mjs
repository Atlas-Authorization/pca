// Extension-member wire vectors (conformance/LAYERS.md, layer `extension`): the optimistic path and the transparency ledger.
//
//   conformance/optimistic-vectors.json   claim, claim window, fraud proof (wire level), settlement record
//   conformance/ledger-vectors.json       Merkle inclusion, RFC 9162 consistency, signed tree heads, witness cosignatures,
//                                         head-to-head consistency, checkpoint chains, legacy witnessed heads and equivocation
//
// Every vector carries `expect`, computed by the TypeScript reference and pinned to the INTENDED outcome written next to the
// case (`want`): a reference change that moves a verdict makes the generator throw instead of silently re-blessing it. The
// natives (Go, Python, Rust) re-derive the same verdicts from the same inputs; the corpus is the only thing they share.
//
// One library for three callers: gen-conformance-ext.mjs (writes the files, reads the reference from ../dist), the TypeScript
// conformance test (reads it from ../src) and the native runners' documentation of the expectations.
//
// Deterministic: fixed key seeds, Ed25519 (RFC 8032, deterministic signatures), no clock, no randomness.
import { createHash } from 'node:crypto';

export const NOW = 1_800_000_000_000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/ext/${l}`).digest());
const seed48 = (l) => new Uint8Array([...seed(`${l}/a`), ...seed(`${l}/b`).slice(0, 16)]); // SLH-DSA-SHA2-128f keygen takes 3 x 16 bytes

/** The window policy the claim vectors verify under (the library default, spelled out so the natives can read it). */
export const WINDOW_POLICY = { minWindowMs: 1000, maxWindowMs: 86_400_000, defaultWindowMs: 300_000, maxSkewMs: 5000 };
const PERMISSIVE = { minWindowMs: -1e18, maxWindowMs: 1e18, defaultWindowMs: 60_000, maxSkewMs: 1e18 };

const mkKey = (core, l) => {
  const sk = seed(l);
  return { sk, pub: core.b64u(core.publicKeyOf(sk)) };
};
const sha = (s) => new Uint8Array(createHash('sha256').update(s).digest());
const flip = (b64) => (b64[0] === 'A' ? 'B' : 'A') + b64.slice(1); // changes the first sextet: a different, still well-formed value
const clone = (x) => JSON.parse(JSON.stringify(x));

const mismatches = [];
function want(table, name, got, intended) {
  if (JSON.stringify(got) !== JSON.stringify(intended)) {
    mismatches.push(`${table}/${name}: the reference says ${JSON.stringify(got)}, the case intends ${JSON.stringify(intended)}`);
  }
}
/** Throws when any case disagreed with its intended outcome (all of them are listed, not just the first). */
function settled(doc) {
  if (mismatches.length) throw new Error(`${mismatches.length} case(s) disagree with the reference:\n  ${mismatches.splice(0).join('\n  ')}`);
  return doc;
}

// =============================================================================================================
// optimistic
// =============================================================================================================

export function buildOptimistic({ opt, core }) {
  const agent = mkKey(core, 'agent');
  const other = mkKey(core, 'other-agent');
  const guardian = mkKey(core, 'guardian');
  const otherGuardian = mkKey(core, 'other-guardian');
  const fakeActn = (n, rc = 'reversible') => ({ v: 2, id: `ext-${n}`, action: { verb: 'pay', resource: `invoice:${n}`, reversibility_class: rc } });
  const digestOf = (p) => core.pcactnDigest(p);

  // ---- claims --------------------------------------------------------------------------------------------
  const claims = [];
  const claimCase = (name, o, intended) => {
    const p = fakeActn(o.n ?? name, o.rc ?? 'reversible');
    let claim = opt.openOptimistic(p, { bondRef: o.bondRef ?? `bond-${name}`, claimedR: o.claimedR ?? 0.25, challengeWindowMs: o.window ?? 60_000, issuedAt: o.issuedAt ?? NOW, serverNow: o.signNow ?? NOW, windowPolicy: PERMISSIVE }, (o.signer ?? agent).sk);
    if (o.mutate) claim = o.mutate(clone(claim));
    const v = {
      name,
      claim,
      pcactn_digest: o.digest ?? digestOf(p),
      signer_public: o.verifyKey ?? agent.pub,
      server_now: o.serverNow ?? NOW,
    };
    const r = opt.claimCheck(claim, v.pcactn_digest, v.signer_public, { serverNow: v.server_now, windowPolicy: WINDOW_POLICY });
    v.expect = { ok: r.check === 'ok', check: r.check };
    want('optimistic_claim', name, v.expect, { ok: intended === 'ok', check: intended });
    claims.push(v);
  };
  claimCase('ok-basic', {}, 'ok');
  claimCase('ok-claimed-r-zero', { claimedR: 0 }, 'ok');
  claimCase('ok-claimed-r-one', { claimedR: 1 }, 'ok');
  claimCase('ok-claimed-r-fraction', { claimedR: 0.125 }, 'ok');
  claimCase('ok-claimed-r-negative', { claimedR: -0.5 }, 'ok');
  claimCase('ok-claimed-r-tiny', { claimedR: 0.000001 }, 'ok');
  claimCase('ok-min-window', { window: 1000 }, 'ok');
  claimCase('ok-max-window', { window: 86_400_000 }, 'ok');
  claimCase('ok-skew-future-edge', { issuedAt: NOW + 5000 }, 'ok');
  claimCase('ok-skew-past-edge', { issuedAt: NOW - 5000 }, 'ok');
  claimCase('ok-class-unknown', { rc: 'unknown' }, 'ok');
  claimCase('ok-class-compensable', { rc: 'compensable' }, 'ok');
  claimCase('ok-bond-ref-escapes', { bondRef: 'b"ond\\1/é \u{1F512}\u0001' }, 'ok');
  claimCase('ok-bond-ref-empty', { bondRef: '' }, 'ok'); // an empty handle is well-formed at the wire level
  claimCase('window-future-skew', { issuedAt: NOW + 5001 }, 'window');
  claimCase('window-past-skew', { issuedAt: NOW - 5001 }, 'window');
  claimCase('window-below-min', { window: 999 }, 'window');
  claimCase('window-zero', { window: 0 }, 'window');
  claimCase('window-negative', { window: -1 }, 'window');
  claimCase('window-above-max', { window: 86_400_001 }, 'window');
  claimCase('window-string', { mutate: (c) => ((c.challenge_window_ms = '60000'), c) }, 'window');
  claimCase('window-null', { mutate: (c) => ((c.challenge_window_ms = null), c) }, 'window');
  claimCase('window-missing', { mutate: (c) => (delete c.challenge_window_ms, c) }, 'window');
  claimCase('issued-at-missing', { mutate: (c) => (delete c.issued_at, c) }, 'window');
  claimCase('issued-at-string', { mutate: (c) => ((c.issued_at = String(NOW)), c) }, 'window');
  claimCase('claimed-r-string', { mutate: (c) => ((c.claimed_r = '0.25'), c) }, 'claimed_r');
  claimCase('claimed-r-null', { mutate: (c) => ((c.claimed_r = null), c) }, 'claimed_r');
  claimCase('claimed-r-missing', { mutate: (c) => (delete c.claimed_r, c) }, 'claimed_r');
  claimCase('claimed-r-bool', { mutate: (c) => ((c.claimed_r = true), c) }, 'claimed_r');
  claimCase('irreversible-class', { mutate: (c) => ((c.reversibility_class = 'irreversible'), c) }, 'irreversible');
  claimCase('irreversible-wins-over-digest', { digest: 'not-the-digest', mutate: (c) => ((c.reversibility_class = 'irreversible'), c) }, 'irreversible');
  claimCase('digest-differs', { digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, 'digest');
  claimCase('digest-wins-over-window', { digest: 'x', issuedAt: NOW + 99_999 }, 'digest');
  claimCase('class-missing', { mutate: (c) => (delete c.reversibility_class, c) }, 'signature');
  claimCase('sig-wrong-signer-key', { verifyKey: other.pub }, 'signature');
  claimCase('sig-signed-by-other', { signer: other }, 'signature');
  claimCase('sig-tamper-claimed-r', { mutate: (c) => ((c.claimed_r = 0.3), c) }, 'signature');
  claimCase('sig-tamper-bond-ref', { mutate: (c) => ((c.bond_ref = 'bond-other'), c) }, 'signature');
  claimCase('sig-tamper-window', { mutate: (c) => ((c.challenge_window_ms = 60_001), c) }, 'signature');
  claimCase('sig-tamper-issued-at', { mutate: (c) => ((c.issued_at = NOW + 1), c) }, 'signature');
  claimCase('sig-tamper-class', { mutate: (c) => ((c.reversibility_class = 'compensable'), c) }, 'signature');
  claimCase('sig-extra-field', { mutate: (c) => ((c.extra = 1), c) }, 'signature');
  claimCase('sig-missing', { mutate: (c) => (delete c.sig, c) }, 'signature');
  claimCase('sig-null', { mutate: (c) => ((c.sig = null), c) }, 'signature');
  claimCase('sig-empty', { mutate: (c) => ((c.sig = ''), c) }, 'signature');
  claimCase('sig-bit-flip', { mutate: (c) => ((c.sig = flip(c.sig)), c) }, 'signature');
  claimCase('sig-truncated', { mutate: (c) => ((c.sig = c.sig.slice(0, 80)), c) }, 'signature');
  claimCase('sig-padded', { mutate: (c) => ((c.sig = `${c.sig}=`), c) }, 'signature');
  claimCase('sig-standard-base64', { mutate: (c) => ((c.sig = c.sig.replace(/-/g, '+').replace(/_/g, '/') + '=='), c) }, 'signature');
  // a claim that is not an object
  for (const [name, bad] of [['null', null], ['string', 'claim'], ['number', 7]]) {
    const v = { name: `not-an-object-${name}`, claim: bad, pcactn_digest: 'x', signer_public: agent.pub, server_now: NOW };
    const r = opt.claimCheck(bad, v.pcactn_digest, v.signer_public, { serverNow: NOW, windowPolicy: WINDOW_POLICY });
    v.expect = { ok: false, check: r.check };
    want('optimistic_claim', v.name, r.check, 'malformed');
    claims.push(v);
  }

  // ---- the challenge window ----------------------------------------------------------------------------
  const windows = [];
  for (const [name, issued, win] of [['basic', NOW, 60_000], ['min', NOW, 1000], ['max', NOW, 86_400_000], ['past', NOW - 4000, 30_000], ['zero-origin', 0, 1000]]) {
    const { claim } = { claim: { issued_at: issued, challenge_window_ms: win } };
    const end = issued + win;
    for (const [tag, now] of [['before', end - 1], ['at-end', end], ['after', end + 1], ['far-before', issued], ['far-after', end + 86_400_000]]) {
      const within = opt.withinChallengeWindow(claim, now);
      const phase = opt.claimStatus(claim, now);
      const v = { name: `window-${name}-${tag}`, issued_at: issued, challenge_window_ms: win, now, expect: { end: opt.challengeWindowEnd(claim), within, phase } };
      want('optimistic_window', v.name, v.expect.within, now <= end);
      windows.push(v);
    }
  }

  // ---- fraud proofs (wire level) -------------------------------------------------------------------------
  const frauds = [];
  const base = claimsFor('fraud');
  function claimsFor(n, o = {}) {
    const p = fakeActn(n, o.rc ?? 'reversible');
    const claim = opt.openOptimistic(p, { bondRef: o.bondRef ?? `bond-${n}`, claimedR: o.claimedR ?? 0.25, challengeWindowMs: 60_000, issuedAt: NOW, serverNow: NOW, windowPolicy: PERMISSIVE }, agent.sk);
    return { claim, p };
  }
  const proofFor = (claim, kind, decision, o = {}) => ({
    pcactn_digest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    claimed_r: claim.claimed_r,
    kind,
    decision,
    evidence: { action: { action: { verb: 'pay', resource: 'invoice:fraud', params: {}, reversibility_class: o.evClass ?? 'reversible' } }, now: NOW },
    r_margin: o.margin ?? 1e-9,
    reason: o.reason ?? `kind ${kind}`,
  });
  const fraudCase = (name, claim, proof, intended) => {
    const v = { name, claim, proof };
    v.expect = { check: opt.fraudProofWireCheck(claim, proof) };
    v.expect.ok = v.expect.check === 'ok';
    want('optimistic_fraud_proof', name, v.expect.check, intended);
    frauds.push(v);
  };
  const c = base.claim;
  const D = (releaseGuardianShare, r, optimisticAllowed) => ({ releaseGuardianShare, r, optimisticAllowed });
  fraudCase('ok-policy-denied', c, proofFor(c, 'policy-denied', D(false, 0.9, false)), 'ok');
  fraudCase('ok-policy-denied-r-irrelevant', c, proofFor(c, 'policy-denied', D(false, 0, true)), 'ok');
  fraudCase('ok-not-allowed', c, proofFor(c, 'optimistic-not-allowed', D(true, 0.6, false)), 'ok');
  fraudCase('ok-understated', c, proofFor(c, 'risk-understated', D(true, 0.5, true)), 'ok');
  fraudCase('ok-understated-just-above-default-margin', c, proofFor(c, 'risk-understated', D(true, 0.25 + 2e-9, true)), 'ok');
  fraudCase('ok-understated-custom-margin', c, proofFor(c, 'risk-understated', D(true, 0.4, true), { margin: 0.1 }), 'ok');
  fraudCase('ok-understated-negative-margin-is-zero', c, proofFor(c, 'risk-understated', D(true, 0.2500001, true), { margin: -5 }), 'ok');
  const cIrr = claimsFor('irr').claim;
  fraudCase('ok-irreversible-on-snapshot', c, proofFor(c, 'irreversible', D(true, 0.1, true), { evClass: 'irreversible' }), 'ok');
  const cIrr2 = { ...clone(cIrr), reversibility_class: 'irreversible' };
  fraudCase('ok-irreversible-on-claim', cIrr2, proofFor(cIrr2, 'irreversible', D(true, 0.1, true)), 'ok');
  fraudCase('consistency-irreversible-nowhere', c, proofFor(c, 'irreversible', D(true, 0.1, true)), 'consistency');
  fraudCase('consistency-policy-denied-but-released', c, proofFor(c, 'policy-denied', D(true, 0.9, false)), 'consistency');
  fraudCase('consistency-not-allowed-but-allowed', c, proofFor(c, 'optimistic-not-allowed', D(true, 0.6, true)), 'consistency');
  fraudCase('consistency-not-allowed-but-denied', c, proofFor(c, 'optimistic-not-allowed', D(false, 0.6, false)), 'consistency');
  fraudCase('consistency-understated-equal-r', c, proofFor(c, 'risk-understated', D(true, 0.25, true)), 'consistency');
  fraudCase('consistency-understated-within-margin', c, proofFor(c, 'risk-understated', D(true, 0.25 + 1e-10, true)), 'consistency');
  fraudCase('consistency-understated-below-claim', c, proofFor(c, 'risk-understated', D(true, 0.1, true)), 'consistency');
  fraudCase('consistency-understated-but-fast-path-refused', c, proofFor(c, 'risk-understated', D(true, 0.9, false)), 'consistency');
  fraudCase('consistency-understated-margin-swallows', c, proofFor(c, 'risk-understated', D(true, 0.5, true), { margin: 0.3 }), 'consistency');
  fraudCase('digest-differs', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), pcactn_digest: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, 'digest');
  fraudCase('bond-differs', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), bond_ref: 'bond-other' }, 'bond');
  fraudCase('claimed-r-differs', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), claimed_r: 0.26 }, 'claimed_r');
  fraudCase('claimed-r-string', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), claimed_r: '0.25' }, 'claimed_r');
  fraudCase('kind-unknown', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), kind: 'because' }, 'kind');
  fraudCase('kind-missing', c, ((p) => (delete p.kind, p))(proofFor(c, 'policy-denied', D(false, 1, false))), 'kind');
  fraudCase('kind-case', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), kind: 'Policy-Denied' }, 'kind');
  fraudCase('malformed-decision-missing', c, ((p) => (delete p.decision, p))(proofFor(c, 'policy-denied', D(false, 1, false))), 'malformed');
  fraudCase('malformed-decision-r-string', c, proofFor(c, 'policy-denied', { releaseGuardianShare: false, r: '1', optimisticAllowed: false }), 'malformed');
  fraudCase('malformed-decision-flag-number', c, proofFor(c, 'policy-denied', { releaseGuardianShare: 0, r: 1, optimisticAllowed: false }), 'malformed');
  fraudCase('malformed-decision-r-missing', c, proofFor(c, 'policy-denied', { releaseGuardianShare: false, optimisticAllowed: false }), 'malformed');
  fraudCase('malformed-reason-missing', c, ((p) => (delete p.reason, p))(proofFor(c, 'policy-denied', D(false, 1, false))), 'malformed');
  fraudCase('malformed-digest-number', c, { ...proofFor(c, 'policy-denied', D(false, 1, false)), pcactn_digest: 7 }, 'malformed');
  fraudCase('malformed-proof-null', c, null, 'malformed');
  fraudCase('malformed-proof-string', c, 'proof', 'malformed');
  fraudCase('malformed-claim-null', null, proofFor(c, 'policy-denied', D(false, 1, false)), 'malformed');
  fraudCase('wire-evidence-ignored-when-absent', c, ((p) => (delete p.evidence, p))(proofFor(c, 'policy-denied', D(false, 1, false))), 'ok');
  fraudCase('wire-r-margin-missing-uses-default', c, ((p) => (delete p.r_margin, p))(proofFor(c, 'risk-understated', D(true, 0.25 + 2e-9, true))), 'ok');
  fraudCase('wire-r-margin-string-uses-default', c, { ...proofFor(c, 'risk-understated', D(true, 0.25 + 2e-9, true)), r_margin: '5' }, 'ok');

  // ---- settlement records -----------------------------------------------------------------------------------
  const settlements = [];
  const accounts = (extra = {}) => new opt.InMemoryBondAccount({ alice: 1_000_000, ...extra });
  const mkLedger = (o = {}) => new opt.BondLedger({ guardianSecret: guardian.sk, accounts: accounts(), ...o });
  const settle = (name, record, intended, key = guardian.pub, pins, requiresSuite) => {
    const v = { name, record, guardian_public: key, ...(pins ? { pins } : {}), ...(requiresSuite ? { requires_suite: requiresSuite } : {}) };
    v.expect = { check: opt.settlementWireCheck(record, key, pins ? { pqPins: pins } : undefined) };
    v.expect.ok = v.expect.check === 'ok';
    want('optimistic_settlement', name, v.expect.check, intended);
    settlements.push(v);
    return v;
  };
  const L = mkLedger();
  const open100 = L.openBond({ claimId: 'bond-s1', amount: 100, depositor: 'alice', at: NOW });
  const release100 = L.releaseBond({ claimId: 'bond-s1', at: NOW + 70_000 });
  const claimS = claimsFor('s2', { bondRef: 'bond-s2' }).claim;
  const L2 = mkLedger();
  L2.openBond({ claimId: 'bond-s2', amount: 250, depositor: 'alice', at: NOW });
  const slashAnon = L2.slashBondOnRevocation({ claimId: 'bond-s2', claim: claimS, revokedCapId: 'cap:leaf', treasury: 'treasury', at: NOW + 10 });
  const L3 = mkLedger();
  const claimT = claimsFor('s3', { bondRef: 'bond-s3' }).claim;
  L3.openBond({ claimId: 'bond-s3', amount: 250, depositor: 'alice', at: NOW });
  const slashChal = L3.slashBondOnRevocation({ claimId: 'bond-s3', claim: claimT, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'watchtower', compensationAccount: 'pool:g1', at: NOW + 10 });
  const L4 = mkLedger();
  const claimU = claimsFor('s4', { bondRef: 'bond-s4' }).claim;
  L4.openBond({ claimId: 'bond-s4', amount: 12.345678, depositor: 'alice', at: NOW });
  const slashMicro = L4.slashBondOnRevocation({ claimId: 'bond-s4', claim: claimU, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'wt', at: NOW + 10 });
  const L5 = mkLedger({ guardianEpoch: 3 });
  const open5 = L5.openBond({ claimId: 'bond-s5', amount: 7, depositor: 'alice', at: NOW });
  const L6 = mkLedger();
  const claimV = claimsFor('s6', { bondRef: 'bond-s6' }).claim;
  L6.openBond({ claimId: 'bond-s6', amount: 101, depositor: 'alice', at: NOW });
  const slashOdd = L6.slashBondOnRevocation({ claimId: 'bond-s6', claim: claimV, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'wt', at: NOW + 10 });

  const planner = L.planner; // generator only: re-sign a deliberately malformed body so the check under test is the first to fail
  const resign = (rec, mut) => {
    const { sig, pq_sig, alg, pq_pk, ...body } = clone(rec);
    void sig; void pq_sig; void alg; void pq_pk;
    const b = mut(body);
    return planner.signRecord(b);
  };

  settle('ok-open', open100, 'ok');
  settle('ok-release', release100, 'ok');
  settle('ok-slash-anonymous', slashAnon, 'ok');
  settle('ok-slash-challenger-split', slashChal, 'ok');
  settle('ok-slash-micro-amount', slashMicro, 'ok');
  settle('ok-slash-odd-integer-dust', slashOdd, 'ok');
  settle('ok-open-with-epoch', open5, 'ok');
  settle('signature-wrong-guardian', open100, 'signature', otherGuardian.pub);
  for (const [name, mut] of [
    ['amount', (r) => ({ ...r, amount: r.amount + 1 })],
    ['to', (r) => ({ ...r, to: 'mallory' })],
    ['from', (r) => ({ ...r, from: 'mallory' })],
    ['claim-id', (r) => ({ ...r, claimId: 'bond-x' })],
    ['at', (r) => ({ ...r, at: r.at + 1 })],
  ]) settle(`signature-tamper-${name}`, mut(open100), 'signature');
  settle('signature-tamper-evidence', { ...slashAnon, evidenceDigest: flip(slashAnon.evidenceDigest) }, 'signature');
  settle('signature-tamper-split-account', { ...slashChal, split: { ...slashChal.split, challengerAccount: 'mallory' } }, 'signature');
  settle('signature-tamper-split-victim-account', { ...slashChal, split: { ...slashChal.split, victimAccount: 'mallory' } }, 'signature');
  settle('signature-tamper-epoch', { ...open5, guardian_epoch: 4 }, 'signature');
  settle('signature-drop-epoch', ((r) => (delete r.guardian_epoch, r))(clone(open5)), 'signature');
  settle('signature-bit-flip', { ...open100, sig: flip(open100.sig) }, 'signature');
  settle('signature-truncated', { ...open100, sig: open100.sig.slice(0, 80) }, 'signature');
  settle('signature-empty', { ...open100, sig: '' }, 'signature');
  settle('signature-extra-field', { ...open100, memo: 'x' }, 'signature');
  settle('split-tamper-reward', { ...slashChal, split: { ...slashChal.split, challengerReward: slashChal.split.challengerReward + 1 } }, 'split');
  settle('split-tamper-treasury-remainder', { ...slashChal, split: { ...slashChal.split, treasuryRemainder: slashChal.split.treasuryRemainder - 1 } }, 'split');
  settle('split-treasury-account-not-destination', resign(slashChal, (r) => ({ ...r, split: { ...r.split, treasuryAccount: 'elsewhere' } })), 'split');
  settle('split-amount-differs', resign(slashChal, (r) => ({ ...r, split: { ...r.split, amount: r.amount + 1 } })), 'split');
  settle('split-sum-short', resign(slashChal, (r) => ({ ...r, split: { ...r.split, treasuryRemainder: r.split.treasuryRemainder - 1 } })), 'split');
  settle('split-sum-over', resign(slashChal, (r) => ({ ...r, split: { ...r.split, victimCompensation: r.split.victimCompensation + 1 } })), 'split');
  settle('split-negative-share', resign(slashChal, (r) => ({ ...r, split: { ...r.split, challengerReward: -1, treasuryRemainder: r.split.treasuryRemainder + r.split.challengerReward + 1 } })), 'split');
  settle('split-anonymous-pays-challenger', resign(slashAnon, (r) => ({ ...r, split: { ...r.split, challengerReward: 1, treasuryRemainder: r.amount - 1 } })), 'split');
  settle('split-anonymous-victim-share', resign(slashAnon, (r) => ({ ...r, split: { ...r.split, victimCompensation: 1, treasuryRemainder: r.amount - 1 } })), 'split');
  settle('split-named-challenger-empty-name', resign(slashChal, (r) => ({ ...r, split: { ...r.split, challengerAccount: '' } })), 'split');
  settle('split-victim-account-empty', resign(slashChal, (r) => ({ ...r, split: { ...r.split, victimAccount: '' } })), 'split');
  settle('split-share-string', resign(slashChal, (r) => ({ ...r, split: { ...r.split, challengerReward: String(r.split.challengerReward) } })), 'split');
  settle('shape-slash-without-split', resign(slashAnon, (r) => (delete r.split, r)), 'shape');
  settle('shape-slash-split-null', resign(slashAnon, (r) => ({ ...r, split: null })), 'shape');
  settle('shape-slash-without-evidence', resign(slashAnon, (r) => ({ ...r, evidenceDigest: '' })), 'shape');
  settle('shape-open-with-evidence', resign(open100, (r) => ({ ...r, evidenceDigest: 'x' })), 'shape');
  settle('shape-release-with-split', resign(release100, (r) => ({ ...r, split: slashAnon.split })), 'shape');
  settle('shape-open-with-split', resign(open100, (r) => ({ ...r, split: slashAnon.split })), 'shape');
  settle('shape-action-unknown', resign(open100, (r) => ({ ...r, action: 'burn' })), 'shape');
  settle('shape-action-missing', resign(open100, (r) => (delete r.action, r)), 'shape');
  settle('shape-amount-zero', resign(open100, (r) => ({ ...r, amount: 0 })), 'shape');
  settle('shape-amount-negative', resign(open100, (r) => ({ ...r, amount: -5 })), 'shape');
  settle('shape-amount-string', resign(open100, (r) => ({ ...r, amount: '100' })), 'shape');
  settle('shape-amount-missing', resign(open100, (r) => (delete r.amount, r)), 'shape');
  settle('shape-claim-id-empty', resign(open100, (r) => ({ ...r, claimId: '' })), 'shape');
  settle('shape-from-empty', resign(open100, (r) => ({ ...r, from: '' })), 'shape');
  settle('shape-to-number', resign(open100, (r) => ({ ...r, to: 5 })), 'shape');
  settle('shape-at-string', resign(open100, (r) => ({ ...r, at: 'now' })), 'shape');
  settle('shape-at-missing', resign(open100, (r) => (delete r.at, r)), 'shape');
  settle('shape-evidence-missing', resign(open100, (r) => (delete r.evidenceDigest, r)), 'shape');
  settle('shape-epoch-negative', resign(open100, (r) => ({ ...r, guardian_epoch: -1 })), 'shape');
  settle('shape-epoch-fraction', resign(open100, (r) => ({ ...r, guardian_epoch: 1.5 })), 'shape');
  settle('shape-epoch-string', resign(open100, (r) => ({ ...r, guardian_epoch: '3' })), 'shape');
  settle('shape-sig-missing', ((r) => (delete r.sig, r))(clone(open100)), 'shape');
  settle('ok-resigned-epoch-zero', resign(open100, (r) => ({ ...r, guardian_epoch: 0 })), 'ok');
  settle('suite-unknown', { ...open100, alg: 'bogus-suite' }, 'suite');
  settle('suite-null', { ...open100, alg: null }, 'suite');
  settle('malformed-null', null, 'malformed');
  settle('malformed-string', 'record', 'malformed');
  settle('malformed-array', [open100], 'malformed');

  // post-quantum guardian suites: `pins` = { <ed25519 identity>: <ML-DSA-65 public key> }; absent = no pin (refused as `signature`)
  {
    const mlOf = (l) => { const k = core.mlDsa65Keygen(seed(`optimistic/${l}`)); return { ...k, pub: core.b64u(k.publicKey) }; };
    const gML = mlOf('guardian-ml');
    const oML = mlOf('other-ml');
    const pin = { [guardian.pub]: gML.pub };
    for (const [tag, alg] of [['ml', 'ml-dsa-65'], ['hybrid', 'hybrid-ed25519-ml-dsa-65']]) {
      const suite = { alg, mlDsa: gML };
      const Lp = mkLedger({ suite });
      const op = Lp.openBond({ claimId: 'bond-pq1', amount: 100, depositor: 'alice', at: NOW });
      const rel = Lp.releaseBond({ claimId: 'bond-pq1', at: NOW + 70_000 });
      const Lq = mkLedger({ suite });
      const claimQ = claimsFor('pq2', { bondRef: 'bond-pq2' }).claim;
      Lq.openBond({ claimId: 'bond-pq2', amount: 250, depositor: 'alice', at: NOW });
      const slash = Lq.slashBondOnRevocation({ claimId: 'bond-pq2', claim: claimQ, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'watchtower', compensationAccount: 'pool:g1', at: NOW + 10 });
      settle(`pq-${tag}-ok-open-pinned`, op, 'ok', guardian.pub, pin);
      settle(`pq-${tag}-ok-release-pinned`, rel, 'ok', guardian.pub, pin);
      settle(`pq-${tag}-ok-slash-pinned`, slash, 'ok', guardian.pub, pin);
      settle(`pq-${tag}-no-pin`, op, 'signature');
      settle(`pq-${tag}-wrong-pin`, op, 'signature', guardian.pub, { [guardian.pub]: oML.pub });
      settle(`pq-${tag}-pin-for-other-identity`, op, 'signature', guardian.pub, { [otherGuardian.pub]: gML.pub });
      settle(`pq-${tag}-wrong-guardian`, op, 'signature', otherGuardian.pub, pin);
      settle(`pq-${tag}-tamper-amount`, { ...op, amount: op.amount + 1 }, 'signature', guardian.pub, pin);
      settle(`pq-${tag}-tamper-split-account`, { ...slash, split: { ...slash.split, challengerAccount: 'mallory' } }, 'signature', guardian.pub, pin);
      settle(`pq-${tag}-sig-bit-flip`, { ...op, sig: flip(op.sig) }, 'signature', guardian.pub, pin);
      settle(`pq-${tag}-alg-stripped`, ((r) => (delete r.alg, r))(clone(op)), 'signature', guardian.pub, pin);
      settle(`pq-${tag}-alg-unknown`, { ...op, alg: 'bogus-suite' }, 'suite', guardian.pub, pin);
      settle(`pq-${tag}-pq-pk-swapped`, { ...op, pq_pk: oML.pub }, 'signature', guardian.pub, pin);
      settle(`pq-${tag}-shape-amount-missing`, ((r) => (delete r.amount, r))(clone(op)), 'shape', guardian.pub, pin);
      settle(`pq-${tag}-split-tamper-reward`, { ...slash, split: { ...slash.split, challengerReward: slash.split.challengerReward + 1 } }, 'split', guardian.pub, pin);
    }
    const hy = mkLedger({ suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: gML } }).openBond({ claimId: 'bond-pq3', amount: 100, depositor: 'alice', at: NOW });
    settle('pq-hybrid-pq-sig-stripped', ((r) => (delete r.pq_sig, r))(clone(hy)), 'signature', guardian.pub, pin);
    settle('pq-hybrid-pq-sig-bit-flip', { ...hy, pq_sig: flip(hy.pq_sig) }, 'signature', guardian.pub, pin);
    settle('pq-hybrid-downgraded-to-ed25519', ((r) => (delete r.alg, delete r.pq_pk, delete r.pq_sig, r))(clone(hy)), 'signature', guardian.pub, pin);
    // `pins: {}` is an explicit EMPTY pin set (no pins), not an absent one
    settle('pq-ml-empty-pins', mkLedger({ suite: { alg: 'ml-dsa-65', mlDsa: gML } }).openBond({ claimId: 'bond-pq4', amount: 100, depositor: 'alice', at: NOW }), 'signature', guardian.pub, {});

    // registered suites beyond ML-DSA: TS verifies them (backends permitting), so the reference outcome is `ok` under a pin. A verifier
    // WITHOUT the suite must refuse (never accept); `requires_suite` names the suite, a verifier lacking it answers `suite`
    // (`unsupported_suite`) instead of expect.check. An absent pin is `signature` for every SDK.
    const slhK = core.slhDsa128fKeygen(seed48('optimistic/guardian-slh'));
    const fnK = core.fnDsa512Keygen(seed('optimistic/guardian-fn'));
    for (const [name, alg, keys, pk] of [
      ['slh-dsa-sha2-128f', 'slh-dsa-sha2-128f', { slhDsa: slhK }, core.encodeSlhDsaPublicKey(slhK.publicKey)],
      ['hybrid-ed25519-slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', { slhDsa: slhK }, core.encodeSlhDsaPublicKey(slhK.publicKey)],
      ['fn-dsa-512', 'fn-dsa-512', { fnDsa512: { ...fnK, signSeed: seed('fn-sign') } }, core.encodeFnDsaPublicKey(fnK.verifyingKey)],
    ]) {
      const r = mkLedger({ suite: { alg, ...keys } }).openBond({ claimId: `bond-${name}`, amount: 100, depositor: 'alice', at: NOW });
      settle(`suite-${name}-ok-pinned`, r, 'ok', guardian.pub, { [guardian.pub]: pk }, alg);
      settle(`suite-${name}-no-pin`, r, 'signature', guardian.pub, undefined, alg);
    }
  }

  return settled({
    format: 1,
    layer: 'extension',
    description: 'Optimistic-path wire vectors (conformance/LAYERS.md, layer extension). Generated by packages/pca/scripts/gen-conformance-ext.mjs from the TypeScript reference; do not edit. expect.check names the FIRST failing check in the documented order; "ok" when none fails. optimistic_settlement vectors named pq-* are signed with ml-dsa-65 / hybrid-ed25519-ml-dsa-65: with `pins` ({ <ed25519 identity b64u>: <ML-DSA-65 public key b64u> }) they verify under that pin set, without `pins` there is no pin and the record is refused as `signature`. Vectors named suite-* use slh-dsa / fn-dsa and carry `requires_suite`: a verifier that implements the suite must return expect.check, one that lacks it answers `suite` (unsupported_suite) instead. `pins: {}` is an explicit empty pin set.',
    keys: { agent: agent.pub, other_agent: other.pub, guardian: guardian.pub, other_guardian: otherGuardian.pub },
    window_policy: WINDOW_POLICY,
    check_order: {
      optimistic_claim: 'malformed,irreversible,digest,claimed_r,window,signature',
      optimistic_fraud_proof: 'malformed,digest,bond,claimed_r,kind,consistency',
      optimistic_settlement: 'malformed,suite,shape,split,signature',
    },
    counts: { optimistic_claim: claims.length, optimistic_window: windows.length, optimistic_fraud_proof: frauds.length, optimistic_settlement: settlements.length },
    optimistic_claim: claims,
    optimistic_window: windows,
    optimistic_fraud_proof: frauds,
    optimistic_settlement: settlements,
  });
}

/** Re-derive the verdict of one optimistic vector with the reference `opt`; the shape of `expect`. */
export function evaluateOptimistic({ opt }, table, v) {
  const windowPolicy = WINDOW_POLICY;
  if (table === 'optimistic_claim') {
    const r = opt.claimCheck(v.claim, v.pcactn_digest, v.signer_public, { serverNow: v.server_now, windowPolicy });
    return { ok: r.check === 'ok', check: r.check };
  }
  if (table === 'optimistic_window') {
    const claim = { issued_at: v.issued_at, challenge_window_ms: v.challenge_window_ms };
    return { end: opt.challengeWindowEnd(claim), within: opt.withinChallengeWindow(claim, v.now), phase: opt.claimStatus(claim, v.now) };
  }
  if (table === 'optimistic_fraud_proof') {
    const check = opt.fraudProofWireCheck(v.claim, v.proof);
    return { check, ok: check === 'ok' };
  }
  const check = opt.settlementWireCheck(v.record, v.guardian_public, v.pins ? { pqPins: v.pins } : undefined);
  return { check, ok: check === 'ok' };
}

// =============================================================================================================
// ledger
// =============================================================================================================

export function buildLedger({ led, core }) {
  const guardian = mkKey(core, 'ledger/guardian');
  const other = mkKey(core, 'ledger/other');
  const w1 = mkKey(core, 'ledger/witness-1');
  const w2 = mkKey(core, 'ledger/witness-2');
  const w3 = mkKey(core, 'ledger/witness-3');
  const stranger = mkKey(core, 'ledger/stranger');
  // post-quantum identities: the ML-DSA-65 key is derived from its own fixed seed and pinned by Ed25519 identity (`pins`)
  const mlOf = (l) => { const k = core.mlDsa65Keygen(seed(`ledger/${l}`)); return { ...k, pub: core.b64u(k.publicKey) }; };
  const gML = mlOf('guardian-ml');
  const oML = mlOf('other-ml');
  const w1ML = mlOf('witness-1-ml');
  const w2ML = mlOf('witness-2-ml');
  const ML = 'ml-dsa-65';
  const HY = 'hybrid-ed25519-ml-dsa-65';
  const suiteOf = (alg, m) => ({ alg, mlDsa: m });
  const commit = (i) => core.b64u(sha(`leaf/${i}`));
  const leaves = Array.from({ length: 70 }, (_, i) => commit(i));
  const mkLog = (n, principal = 'grant-1') => {
    const l = new led.TransparencyLedger(principal);
    for (let i = 0; i < n; i++) l.appendCommitment(leaves[i]);
    return l;
  };
  const LOG = mkLog(70);
  const rootAt = (n) => LOG.rootAt(n);
  const EMPTY = led.EMPTY_TREE_ROOT;

  // ---- inclusion -------------------------------------------------------------------------------------------
  const inclusion = [];
  const incl = (name, root, proof, leaf, intended) => {
    const v = { name, root, proof, leaf };
    v.expect = { ok: led.verifyLedgerInclusion(root, proof, leaf) };
    want('ledger_inclusion', name, v.expect.ok, intended);
    inclusion.push(v);
  };
  const SIZES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33, 64, 70];
  for (const n of SIZES) {
    const l = mkLog(n);
    const idxs = n <= 9 ? [...Array(n).keys()] : [0, 1, Math.floor(n / 2), n - 2, n - 1];
    for (const i of idxs) incl(`ok-size-${n}-index-${i}`, l.head().root, l.inclusionProof(i), leaves[i], true);
  }
  {
    const l = mkLog(9);
    const root = l.head().root;
    const p = l.inclusionProof(4);
    incl('wrong-leaf', root, p, leaves[5], false);
    incl('ok-control', root, p, leaves[4], true);
    incl('root-of-other-size', rootAt(8), p, leaves[4], false);
    incl('root-bit-flip', flip(root), p, leaves[4], false);
    incl('path-hash-bit-flip', root, { ...p, path: p.path.map((s, i) => (i === 1 ? { ...s, hash: flip(s.hash) } : s)) }, leaves[4], false);
    incl('path-side-swapped', root, { ...p, path: p.path.map((s, i) => (i === 0 ? { ...s, side: s.side === 'L' ? 'R' : 'L' } : s)) }, leaves[4], false);
    incl('path-truncated', root, { ...p, path: p.path.slice(1) }, leaves[4], false);
    incl('path-extra-step', root, { ...p, path: [...p.path, p.path[0]] }, leaves[4], false);
    incl('path-empty', root, { ...p, path: [] }, leaves[4], false);
    incl('index-out-of-range', root, { ...p, index: 9 }, leaves[4], false);
    incl('index-negative', root, { ...p, index: -1 }, leaves[4], false);
    incl('index-wrong', root, { ...p, index: 3 }, leaves[4], false);
    incl('size-zero', root, { ...p, size: 0 }, leaves[4], false);
    incl('size-larger-same-path-shape', root, { ...p, size: 10 }, leaves[4], true); // the shape (not the size) is what the proof fixes: index 4 of 9 and of 10 climb the same left subtree
    incl('size-changes-path-shape', root, { ...p, size: 17 }, leaves[4], false);
    incl('index-fraction', root, { ...p, index: 4.5 }, leaves[4], false);
    incl('index-string', root, { ...p, index: '4' }, leaves[4], false);
    incl('proof-null', root, null, leaves[4], false);
    incl('leaf-is-number', root, p, 4, false);
    incl('leaf-empty-string', root, p, '', false);
    // a single-leaf tree: the root is the leaf hash itself
    const one = mkLog(1);
    incl('single-leaf-empty-path-extra', one.head().root, { ...one.inclusionProof(0), path: [{ side: 'L', hash: one.head().root }] }, leaves[0], false);
  }

  // ---- consistency -------------------------------------------------------------------------------------------
  const consistency = [];
  const cons = (name, oldRoot, newRoot, proof, intended) => {
    const v = { name, old_root: oldRoot, new_root: newRoot, proof };
    v.expect = { ok: led.verifyLedgerConsistency(oldRoot, newRoot, proof) };
    want('ledger_consistency', name, v.expect.ok, intended);
    consistency.push(v);
  };
  for (let n = 0; n <= 13; n++) for (let m = 0; m <= n; m++) cons(`ok-${m}-to-${n}`, rootAt(m), rootAt(n), LOG.consistencyProof(m, n), true);
  for (const [m, n] of [[1, 64], [8, 16], [15, 16], [16, 17], [31, 33], [32, 33], [33, 64], [48, 64], [63, 64], [1, 70], [35, 70], [64, 70], [69, 70], [7, 70]]) {
    cons(`ok-${m}-to-${n}`, rootAt(m), rootAt(n), LOG.consistencyProof(m, n), true);
  }
  {
    const m = 5;
    const n = 12;
    const p = LOG.consistencyProof(m, n);
    cons('old-root-wrong', rootAt(6), rootAt(n), p, false);
    cons('new-root-wrong', rootAt(m), rootAt(n + 1), p, false);
    cons('roots-swapped', rootAt(n), rootAt(m), p, false);
    cons('old-root-bit-flip', flip(rootAt(m)), rootAt(n), p, false);
    cons('new-root-bit-flip', rootAt(m), flip(rootAt(n)), p, false);
    cons('path-element-bit-flip', rootAt(m), rootAt(n), { ...p, path: p.path.map((h, i) => (i === 1 ? flip(h) : h)) }, false);
    cons('path-truncated', rootAt(m), rootAt(n), { ...p, path: p.path.slice(0, -1) }, false);
    cons('path-extra', rootAt(m), rootAt(n), { ...p, path: [...p.path, p.path[0]] }, false);
    cons('path-empty', rootAt(m), rootAt(n), { ...p, path: [] }, false);
    cons('path-reversed', rootAt(m), rootAt(n), { ...p, path: [...p.path].reverse() }, false);
    cons('old-size-wrong', rootAt(m), rootAt(n), { ...p, oldSize: m + 1 }, false);
    cons('new-size-off-by-one-same-walk', rootAt(m), rootAt(n), { ...p, newSize: n + 1 }, true); // the walk (not the size) is what the roots pin; verifyHeadConsistency also requires newSize to equal the signed size
    cons('new-size-changes-walk', rootAt(m), rootAt(n), { ...p, newSize: 20 }, false);
    cons('old-greater-than-new', rootAt(n), rootAt(m), { oldSize: n, newSize: m, path: p.path }, false);
    cons('old-size-negative', rootAt(m), rootAt(n), { ...p, oldSize: -1 }, false);
    cons('old-size-fraction', rootAt(m), rootAt(n), { ...p, oldSize: 5.5 }, false);
    cons('new-size-string', rootAt(m), rootAt(n), { ...p, newSize: '12' }, false);
    cons('path-not-array', rootAt(m), rootAt(n), { ...p, path: 'x' }, false);
    cons('path-element-not-string', rootAt(m), rootAt(n), { ...p, path: p.path.map((h, i) => (i === 0 ? 7 : h)) }, false);
    cons('path-element-not-base64url', rootAt(m), rootAt(n), { ...p, path: p.path.map((h, i) => (i === 0 ? '!!!' : h)) }, false);
    cons('path-too-long', rootAt(m), rootAt(n), { ...p, path: Array.from({ length: 200 }, () => p.path[0]) }, false);
    cons('equal-size-different-roots', rootAt(m), rootAt(m + 1), { oldSize: m, newSize: m, path: [] }, false);
    cons('equal-size-nonempty-path', rootAt(m), rootAt(m), { oldSize: m, newSize: m, path: [p.path[0]] }, false);
    cons('empty-old-nonempty-path', EMPTY, rootAt(n), { oldSize: 0, newSize: n, path: [p.path[0]] }, false);
    cons('empty-old-wrong-root', rootAt(1), rootAt(n), { oldSize: 0, newSize: n, path: [] }, false);
    cons('empty-to-empty-wrong-new', EMPTY, rootAt(1), { oldSize: 0, newSize: 0, path: [] }, false);
    cons('empty-old-garbage-new-root', EMPTY, 'not-a-root', { oldSize: 0, newSize: n, path: [] }, true); // RFC 9162 2.1.4.1: an empty tree is consistent with any tree
    // 32-bit truncation of the sizes must not collapse onto the small ones
    cons('size-wraps-32-bit', rootAt(3), rootAt(7), { oldSize: 3 + 2 ** 32, newSize: 7 + 2 ** 32, path: LOG.consistencyProof(3, 7).path }, false);
    cons('size-unsafe-integer', rootAt(3), rootAt(7), { oldSize: 3, newSize: 2 ** 53, path: LOG.consistencyProof(3, 7).path }, false);
    cons('size-beyond-safe-integer', rootAt(3), rootAt(7), { oldSize: 2 ** 53, newSize: 2 ** 53 + 2, path: [] }, false);
  }

  // ---- signed tree heads ----------------------------------------------------------------------------------------
  const INSTANCE = 'inst-1';
  const PRINCIPAL = 'grant-1';
  const sthAt = (size, prevSize, o = {}) =>
    led.signTreeHead(
      (o.signer ?? guardian).sk,
      { instance_id: o.instance ?? INSTANCE, principal: o.principal ?? PRINCIPAL, size, root: o.root ?? rootAt(size), prev_root: o.prevRoot ?? (prevSize === undefined ? '' : rootAt(prevSize)), timestamp: o.timestamp ?? NOW + (size < 1e6 ? size : 0) },
      o.suite,
    );
  const heads = [];
  const head = (name, sth, key, intended, pins, requiresSuite) => {
    const v = { name, sth, guardian_public: key, ...(pins ? { pins } : {}), ...(requiresSuite ? { requires_suite: requiresSuite } : {}) };
    v.expect = { ok: led.verifyTreeHead(sth, key, undefined, pins ? { pqPins: pins } : undefined) };
    want('ledger_tree_head', name, v.expect.ok, intended);
    heads.push(v);
  };
  const h8 = sthAt(8, 7);
  head('ok-basic', h8, guardian.pub, true);
  head('ok-first-head-empty-prev-root', sthAt(1), guardian.pub, true);
  head('ok-empty-log', sthAt(0, undefined, { root: EMPTY }), guardian.pub, true);
  head('ok-empty-principal-and-instance', sthAt(8, 7, { principal: '', instance: '' }), guardian.pub, true);
  head('ok-unicode-fields', sthAt(8, 7, { principal: 'gränt-\u{1F512}- ', instance: 'i"n\\st' }), guardian.pub, true);
  head('ok-large-size', sthAt(2 ** 40, undefined, { root: rootAt(8) }), guardian.pub, true);
  head('ok-max-safe-size', sthAt(2 ** 53 - 1, undefined, { root: rootAt(8) }), guardian.pub, true);
  head('ok-epoch-annotation-unsigned', { ...h8, guardian_epoch: 9 }, guardian.pub, true);
  head('ok-witnesses-unsigned', { ...h8, witnesses: [led.cosignTreeHead(h8, w1.sk)] }, guardian.pub, true);
  head('ok-witnesses-garbage-unsigned', { ...h8, witnesses: 'x' }, guardian.pub, true);
  head('wrong-guardian-key', h8, other.pub, false);
  head('guardian-field-differs', { ...h8, guardian: other.pub }, guardian.pub, false);
  head('signed-by-other', sthAt(8, 7, { signer: other }), guardian.pub, false);
  for (const [name, mut] of [
    ['instance', (h) => ({ ...h, instance_id: 'inst-2' })],
    ['principal', (h) => ({ ...h, principal: 'grant-2' })],
    ['size', (h) => ({ ...h, size: h.size + 1 })],
    ['root', (h) => ({ ...h, root: flip(h.root) })],
    ['prev-root', (h) => ({ ...h, prev_root: flip(h.prev_root) })],
    ['timestamp', (h) => ({ ...h, timestamp: h.timestamp + 1 })],
  ]) head(`tamper-${name}`, mut(h8), guardian.pub, false);
  head('sig-bit-flip', { ...h8, sig: flip(h8.sig) }, guardian.pub, false);
  head('sig-truncated', { ...h8, sig: h8.sig.slice(0, 60) }, guardian.pub, false);
  head('sig-missing', ((h) => (delete h.sig, h))(clone(h8)), guardian.pub, false);
  head('sig-empty', { ...h8, sig: '' }, guardian.pub, false);
  head('extra-field-is-ignored-if-unsigned', { ...h8, memo: 'x' }, guardian.pub, true);
  head('alg-unknown', { ...h8, alg: 'bogus-suite' }, guardian.pub, false);
  head('size-negative-signed', sthAt(-1, undefined, { root: rootAt(1) }), guardian.pub, false);
  head('size-fraction-signed', sthAt(1.5, undefined, { root: rootAt(1) }), guardian.pub, false);
  head('size-string-signed', sthAt('8', undefined, { root: rootAt(1) }), guardian.pub, false);
  head('domain-confusion-witnessed-head', ((l) => {
    const wh = l.witnessHead(guardian.sk);
    return { instance_id: INSTANCE, principal: PRINCIPAL, size: wh.size, root: wh.root, prev_root: '', timestamp: NOW, guardian: wh.witness, sig: wh.sig };
  })(mkLog(8)), guardian.pub, false);
  head('malformed-null', null, guardian.pub, false);
  head('malformed-string', 'sth', guardian.pub, false);
  // post-quantum suites: `pins` = { <ed25519 identity>: <ML-DSA-65 public key> }; absent = no pin (a PQ head is then refused)
  {
    const pin = { [guardian.pub]: gML.pub };
    const wrongPin = { [guardian.pub]: oML.pub };
    for (const [tag, alg] of [['ml', ML], ['hybrid', HY]]) {
      const sth = sthAt(8, 7, { suite: suiteOf(alg, gML) });
      head(`pq-${tag}-ok-pinned`, sth, guardian.pub, true, pin);
      head(`pq-${tag}-no-pin`, sth, guardian.pub, false);
      head(`pq-${tag}-wrong-pin`, sth, guardian.pub, false, wrongPin);
      head(`pq-${tag}-pin-for-other-identity`, sth, guardian.pub, false, { [other.pub]: gML.pub });
      head(`pq-${tag}-tamper-root`, { ...sth, root: flip(sth.root) }, guardian.pub, false, pin);
      head(`pq-${tag}-tamper-size`, { ...sth, size: sth.size + 1 }, guardian.pub, false, pin);
      head(`pq-${tag}-sig-bit-flip`, { ...sth, sig: flip(sth.sig) }, guardian.pub, false, pin);
      head(`pq-${tag}-alg-stripped`, ((h) => (delete h.alg, h))(clone(sth)), guardian.pub, false, pin);
      head(`pq-${tag}-alg-unknown`, { ...sth, alg: 'bogus-suite' }, guardian.pub, false, pin);
      head(`pq-${tag}-pq-pk-swapped`, { ...sth, pq_pk: oML.pub }, guardian.pub, false, pin);
    }
    const hy = sthAt(8, 7, { suite: suiteOf(HY, gML) });
    head('pq-hybrid-pq-sig-stripped', ((h) => (delete h.pq_sig, h))(clone(hy)), guardian.pub, false, pin);
    head('pq-hybrid-pq-sig-bit-flip', { ...hy, pq_sig: flip(hy.pq_sig) }, guardian.pub, false, pin);
    head('pq-hybrid-ed-sig-bit-flip', { ...hy, sig: flip(hy.sig) }, guardian.pub, false, pin);
    head('pq-hybrid-downgraded-to-ed25519', ((h) => (delete h.alg, delete h.pq_pk, delete h.pq_sig, h))(clone(hy)), guardian.pub, false, pin);
    head('pq-ml-allow-nothing-signed-by-other-identity', sthAt(8, 7, { suite: suiteOf(ML, oML), signer: other }), guardian.pub, false, pin);
    // `pins: {}` is an explicit EMPTY pin set (no pins), not an absent one
    head('pq-ml-empty-pins', sthAt(8, 7, { suite: suiteOf(ML, gML) }), guardian.pub, false, {});
    // registered suites beyond ML-DSA: TS verifies them (backends permitting), reference outcome `ok` under a pin. A verifier WITHOUT
    // the suite must refuse (false, never accept); `requires_suite` names it. An absent pin is refused by every SDK.
    const slhK = core.slhDsa128fKeygen(seed48('ledger/guardian-slh'));
    const fnK = core.fnDsa512Keygen(seed('ledger/guardian-fn'));
    const lessK = core.lessCat1Keygen(seed('ledger/guardian-less'));
    for (const [alg, keys, pk] of [
      ['slh-dsa-sha2-128f', { slhDsa: slhK }, core.encodeSlhDsaPublicKey(slhK.publicKey)],
      ['hybrid-ed25519-slh-dsa-sha2-128f', { slhDsa: slhK }, core.encodeSlhDsaPublicKey(slhK.publicKey)],
      ['fn-dsa-512', { fnDsa512: { ...fnK, signSeed: seed('fn-sign') } }, core.encodeFnDsaPublicKey(fnK.verifyingKey)],
      ['less-cat1', { lessCat1: { ...lessK, signSeed: seed('less-sign') } }, core.encodeLessPublicKey(lessK.publicKey)],
    ]) {
      const sth = sthAt(8, 7, { suite: { alg, ...keys } });
      head(`suite-${alg}-ok-pinned`, sth, guardian.pub, true, { [guardian.pub]: pk }, alg);
      if (alg !== 'less-cat1') head(`suite-${alg}-no-pin`, sth, guardian.pub, false, undefined, alg);
    }
  }

  // ---- witness cosignatures ---------------------------------------------------------------------------------------
  const cosigs = [];
  const cosig = (name, sth, key, policy, intended, pins) => {
    const v = { name, sth, guardian_public: key, policy, ...(pins ? { pins } : {}) };
    v.expect = { ok: led.verifyTreeHead(sth, key, policy ?? undefined, pins ? { pqPins: pins } : undefined) };
    want('ledger_cosign', name, v.expect.ok, intended);
    cosigs.push(v);
  };
  const withW = (sth, ...ws) => ({ ...sth, witnesses: ws });
  const cs = (sth, w) => led.cosignTreeHead(sth, w.sk);
  const pol = (keys, threshold) => ({ witnessKeys: keys.map((k) => k.pub), threshold });
  const S = sthAt(8, 7);
  cosig('threshold-zero-needs-nothing', S, guardian.pub, pol([], 0), true);
  cosig('threshold-zero-with-garbage-witnesses', { ...S, witnesses: 'x' }, guardian.pub, pol([w1], 0), true);
  cosig('one-of-one', withW(S, cs(S, w1)), guardian.pub, pol([w1], 1), true);
  cosig('one-of-one-missing', S, guardian.pub, pol([w1], 1), false);
  cosig('one-of-one-empty-array', { ...S, witnesses: [] }, guardian.pub, pol([w1], 1), false);
  cosig('two-of-three-two-valid', withW(S, cs(S, w1), cs(S, w3)), guardian.pub, pol([w1, w2, w3], 2), true);
  cosig('two-of-three-all-valid', withW(S, cs(S, w1), cs(S, w2), cs(S, w3)), guardian.pub, pol([w1, w2, w3], 2), true);
  cosig('two-of-three-one-valid', withW(S, cs(S, w2)), guardian.pub, pol([w1, w2, w3], 2), false);
  cosig('duplicate-witness-counts-once', withW(S, cs(S, w1), cs(S, w1)), guardian.pub, pol([w1, w2], 2), false);
  cosig('unknown-witness-does-not-count', withW(S, cs(S, w1), cs(S, stranger)), guardian.pub, pol([w1, w2], 2), false);
  cosig('stranger-only', withW(S, cs(S, stranger)), guardian.pub, pol([w1, w2], 1), false);
  cosig('cosignature-bit-flip', withW(S, { ...cs(S, w1), sig: flip(cs(S, w1).sig) }), guardian.pub, pol([w1], 1), false);
  cosig('cosignature-key-mismatch', withW(S, { ...cs(S, w1), key: w2.pub }), guardian.pub, pol([w1, w2], 1), false);
  cosig('cosignature-for-other-size', withW(S, cs(sthAt(9, 8), w1)), guardian.pub, pol([w1], 1), false);
  cosig('cosignature-for-other-root', withW(S, cs({ ...S, root: flip(S.root) }, w1)), guardian.pub, pol([w1], 1), false);
  cosig('cosignature-for-other-principal', withW(S, cs({ ...S, principal: 'grant-2' }, w1)), guardian.pub, pol([w1], 1), false);
  cosig('cosignature-for-other-instance', withW(S, cs({ ...S, instance_id: 'inst-2' }, w1)), guardian.pub, pol([w1], 1), false);
  cosig('cosignature-for-other-prev-root', withW(S, cs({ ...S, prev_root: rootAt(3) }, w1)), guardian.pub, pol([w1], 1), false);
  cosig('epoch-bound-ok', ((s) => withW(s, cs(s, w1)))({ ...S, guardian_epoch: 3 }), guardian.pub, pol([w1], 1), true);
  cosig('epoch-bound-mismatch', ((s) => ({ ...withW(s, cs(s, w1)), guardian_epoch: 4 }))({ ...S, guardian_epoch: 3 }), guardian.pub, pol([w1], 1), false);
  cosig('epoch-absent-equals-zero', ((s) => withW({ ...S }, cs(s, w1)))({ ...S, guardian_epoch: 0 }), guardian.pub, pol([w1], 1), true);
  cosig('guardian-signature-still-required', withW(sthAt(8, 7, { signer: other }), cs(S, w1)), guardian.pub, pol([w1], 1), false);
  cosig('threshold-above-keys', withW(S, cs(S, w1)), guardian.pub, pol([w1], 2), false);
  cosig('threshold-negative', withW(S, cs(S, w1)), guardian.pub, pol([w1], -1), false);
  cosig('threshold-fraction', withW(S, cs(S, w1)), guardian.pub, pol([w1], 1.5), false);
  cosig('threshold-string', withW(S, cs(S, w1)), guardian.pub, { witnessKeys: [w1.pub], threshold: '1' }, false);
  cosig('witness-keys-empty-threshold-one', withW(S, cs(S, w1)), guardian.pub, pol([], 1), false);
  cosig('witness-keys-missing', withW(S, cs(S, w1)), guardian.pub, { threshold: 1 }, false);
  cosig('witnesses-not-an-array', { ...S, witnesses: { 0: cs(S, w1) } }, guardian.pub, pol([w1], 1), false);
  cosig('witness-entry-null-skipped', withW(S, null, cs(S, w1)), guardian.pub, pol([w1], 1), true);
  cosig('witness-entry-missing-sig-skipped', withW(S, { key: w1.pub }, cs(S, w1)), guardian.pub, pol([w1], 1), true);
  cosig('witness-alg-unknown-skipped', withW(S, { ...cs(S, w1), alg: 'bogus-suite' }), guardian.pub, pol([w1], 1), false);
  cosig('no-policy-no-witness-needed', S, guardian.pub, null, true);
  // post-quantum witnesses: the policy carries `pqPins` ({ <witness ed25519 identity>: <ML-DSA-65 public key> })
  {
    const polPq = (keys, threshold, pins) => ({ ...pol(keys, threshold), ...(pins ? { pqPins: pins } : {}) });
    const pin1 = { [w1.pub]: w1ML.pub };
    const csPq = (sth, w, m, alg) => led.cosignTreeHead(sth, w.sk, suiteOf(alg, m));
    for (const [tag, alg] of [['ml', ML], ['hybrid', HY]]) {
      const c = csPq(S, w1, w1ML, alg);
      cosig(`pq-${tag}-one-of-one-pinned`, withW(S, c), guardian.pub, polPq([w1], 1, pin1), true);
      cosig(`pq-${tag}-no-pin`, withW(S, c), guardian.pub, polPq([w1], 1), false);
      cosig(`pq-${tag}-wrong-pin`, withW(S, c), guardian.pub, polPq([w1], 1, { [w1.pub]: w2ML.pub }), false);
      cosig(`pq-${tag}-over-other-head`, withW(S, csPq(sthAt(9, 8), w1, w1ML, alg)), guardian.pub, polPq([w1], 1, pin1), false);
      cosig(`pq-${tag}-alg-stripped`, withW(S, ((x) => (delete x.alg, x))(clone(c))), guardian.pub, polPq([w1], 1, pin1), false);
      cosig(`pq-${tag}-alg-unknown`, withW(S, { ...c, alg: 'bogus-suite' }), guardian.pub, polPq([w1], 1, pin1), false);
      cosig(`pq-${tag}-sig-bit-flip`, withW(S, { ...c, sig: flip(c.sig) }), guardian.pub, polPq([w1], 1, pin1), false);
    }
    cosig('pq-hybrid-pq-sig-stripped', withW(S, ((x) => (delete x.pq_sig, x))(clone(csPq(S, w1, w1ML, HY)))), guardian.pub, polPq([w1], 1, pin1), false);
    const pins12 = { [w1.pub]: w1ML.pub, [w2.pub]: w2ML.pub };
    cosig('pq-mixed-ed25519-and-ml-two-of-two', withW(S, cs(S, w1), csPq(S, w2, w2ML, ML)), guardian.pub, polPq([w1, w2], 2, pins12), true);
    cosig('pq-mixed-unpinned-ml-does-not-count', withW(S, cs(S, w1), csPq(S, w2, w2ML, ML)), guardian.pub, polPq([w1, w2], 2, pin1), false);
    cosig('pq-mixed-unpinned-ml-skipped-threshold-one', withW(S, csPq(S, w2, w2ML, ML), cs(S, w1)), guardian.pub, polPq([w1, w2], 1, pin1), true);
    // the witness policy's pqPins pin COSIGNERS only: the guardian head's own ML-DSA key needs the separate head pin, so this is refused
    // an explicit `pins: {}` replaces the policy's pqPins (cosigners fall back to the policy only when `pins` is ABSENT)
    cosig('pq-ml-one-of-one-empty-pins-overrides-policy-pqPins', withW(S, csPq(S, w1, w1ML, ML)), guardian.pub, polPq([w1], 1, pin1), false, {});
    cosig('pq-ml-one-of-one-pins-supply-the-cosigner-pin', withW(S, csPq(S, w1, w1ML, ML)), guardian.pub, polPq([w1], 1), true, pin1);
    {
      const fnW = core.fnDsa512Keygen(seed('ledger/witness-fn'));
      const cf = led.cosignTreeHead(S, w1.sk, { alg: 'fn-dsa-512', fnDsa512: { ...fnW, signSeed: seed('fn-sign-w') } });
      cosig('suite-fn-dsa-512-one-of-one-pinned', withW(S, cf), guardian.pub, polPq([w1], 1, { [w1.pub]: core.encodeFnDsaPublicKey(fnW.verifyingKey) }), true);
      cosigs[cosigs.length - 1].requires_suite = 'fn-dsa-512';
      cosig('suite-fn-dsa-512-no-pin', withW(S, cf), guardian.pub, polPq([w1], 1), false);
      cosigs[cosigs.length - 1].requires_suite = 'fn-dsa-512';
    }
    cosig('pq-ml-guardian-head-not-pinned-by-witness-policy', withW(sthAt(8, 7, { suite: suiteOf(ML, gML) }), csPq(sthAt(8, 7, { suite: suiteOf(ML, gML) }), w1, w1ML, ML)), guardian.pub, polPq([w1], 1, { ...pin1, [guardian.pub]: gML.pub }), false);
  }

  // ---- head to head ---------------------------------------------------------------------------------------------------
  const hh = [];
  const pair = (name, older, newer, proof, key, intended, pins) => {
    const v = { name, older, newer, proof, guardian_public: key, ...(pins ? { pins } : {}) };
    v.expect = { ok: led.verifyHeadConsistency(older, newer, proof, key, undefined, pins ? { pqPins: pins } : undefined) };
    want('ledger_head_consistency', name, v.expect.ok, intended);
    hh.push(v);
  };
  const A7 = sthAt(7, 6);
  const A8 = sthAt(8, 7);
  const A12 = sthAt(12, 11);
  const prf = (m, n) => LOG.consistencyProof(m, n);
  pair('ok-adjacent', A7, A8, prf(7, 8), guardian.pub, true);
  pair('ok-skip-ahead', A7, A12, prf(7, 12), guardian.pub, true);
  pair('ok-equal', A8, A8, prf(8, 8), guardian.pub, true);
  pair('ok-from-empty', sthAt(0, undefined, { root: EMPTY }), A8, prf(0, 8), guardian.pub, true);
  pair('ok-power-of-two-boundary', sthAt(16, 15), sthAt(17, 16), prf(16, 17), guardian.pub, true);
  pair('adjacent-wrong-prev-root', A7, sthAt(8, 7, { prevRoot: rootAt(3) }), prf(7, 8), guardian.pub, false);
  pair('adjacent-empty-prev-root', A7, sthAt(8, 7, { prevRoot: '' }), prf(7, 8), guardian.pub, false);
  pair('skip-ahead-prev-root-unchecked', A7, sthAt(12, 11, { prevRoot: flip(rootAt(11)) }), prf(7, 12), guardian.pub, true);
  pair('different-principal', A7, sthAt(8, 7, { principal: 'grant-2' }), prf(7, 8), guardian.pub, false);
  pair('different-instance', A7, sthAt(8, 7, { instance: 'inst-2' }), prf(7, 8), guardian.pub, false);
  pair('proof-sizes-mismatch-old', A7, A8, { ...prf(7, 8), oldSize: 6 }, guardian.pub, false);
  pair('proof-sizes-mismatch-new', A7, A8, { ...prf(7, 8), newSize: 9 }, guardian.pub, false);
  pair('proof-path-tampered', A7, A12, { ...prf(7, 12), path: prf(7, 12).path.map((h, i) => (i === 0 ? flip(h) : h)) }, guardian.pub, false);
  pair('reversed-order', A8, A7, prf(7, 8), guardian.pub, false);
  pair('reversed-order-reversed-proof', A8, A7, { oldSize: 8, newSize: 7, path: [] }, guardian.pub, false);
  pair('equal-size-different-roots', A8, sthAt(8, 7, { root: flip(rootAt(8)) }), prf(8, 8), guardian.pub, false);
  pair('newer-forged-signature', A7, { ...A8, sig: flip(A8.sig) }, prf(7, 8), guardian.pub, false);
  pair('older-forged-signature', { ...A7, sig: flip(A7.sig) }, A8, prf(7, 8), guardian.pub, false);
  pair('newer-signed-by-other', A7, sthAt(8, 7, { signer: other }), prf(7, 8), guardian.pub, false);
  pair('rewritten-history-same-sizes', A7, sthAt(8, 7, { root: new led.TransparencyLedger('x').head().root }), prf(7, 8), guardian.pub, false);
  pair('forked-log', A7, ((l) => { for (let i = 0; i < 7; i++) l.appendCommitment(leaves[i]); l.appendCommitment(commit(999)); return sthAt(8, 7, { root: l.head().root }); })(new led.TransparencyLedger(PRINCIPAL)), prf(7, 8), guardian.pub, false);
  pair('proof-null', A7, A8, null, guardian.pub, false);
  {
    const pin = { [guardian.pub]: gML.pub };
    const m7 = sthAt(7, 6, { suite: suiteOf(ML, gML) });
    const m8 = sthAt(8, 7, { suite: suiteOf(ML, gML) });
    pair('pq-ml-ok-pinned', m7, m8, prf(7, 8), guardian.pub, true, pin);
    pair('pq-ml-no-pin', m7, m8, prf(7, 8), guardian.pub, false);
    pair('pq-ml-mixed-ed25519-older-pq-newer', A7, m8, prf(7, 8), guardian.pub, true, pin);
    pair('pq-ml-newer-forged', m7, { ...m8, sig: flip(m8.sig) }, prf(7, 8), guardian.pub, false, pin);
  }

  // ---- checkpoint chains ---------------------------------------------------------------------------------------------
  const chains = [];
  const chain = (name, cps, key, policy, intended, pins) => {
    const v = { name, chain: cps, guardian_public: key, policy: policy ?? null, ...(pins ? { pins } : {}) };
    const r = led.verifyCheckpointChain(cps, key, policy ?? undefined, pins ? { pqPins: pins } : undefined);
    v.expect = r.ok ? { ok: true } : { ok: false, at: r.at };
    want('ledger_checkpoint_chain', name, v.expect, intended);
    chains.push(v);
  };
  const cp = (size, prev, from) => ({ sth: sthAt(size, prev), ...(from === undefined ? {} : { proof: prf(from, size) }) });
  const good = [cp(1), cp(2, 1, 1), cp(5, 4, 2), cp(8, 7, 5), cp(13, 12, 8), cp(64, 63, 13)];
  chain('ok-single', [cp(8, 7)], guardian.pub, null, { ok: true });
  chain('ok-six-checkpoints', good, guardian.pub, null, { ok: true });
  chain('ok-equal-sizes', [cp(8, 7), { sth: sthAt(8, 7), proof: prf(8, 8) }], guardian.pub, null, { ok: true });
  chain('ok-with-witnesses', [{ sth: withW(sthAt(8, 7), cs(sthAt(8, 7), w1)) }, { sth: withW(sthAt(12, 11), cs(sthAt(12, 11), w1)), proof: prf(8, 12) }], guardian.pub, pol([w1], 1), { ok: true });
  chain('witness-missing-on-second', [{ sth: withW(sthAt(8, 7), cs(sthAt(8, 7), w1)) }, { sth: sthAt(12, 11), proof: prf(8, 12) }], guardian.pub, pol([w1], 1), { ok: false, at: 1 });
  chain('empty', [], guardian.pub, null, { ok: false, at: 0 });
  chain('first-head-forged', [{ sth: { ...sthAt(8, 7), sig: flip(sthAt(8, 7).sig) } }, cp(12, 11, 8)], guardian.pub, null, { ok: false, at: 0 });
  chain('proof-missing', [good[0], { sth: good[1].sth }], guardian.pub, null, { ok: false, at: 1 });
  chain('proof-for-wrong-pair', [good[0], good[1], { sth: good[2].sth, proof: prf(1, 5) }], guardian.pub, null, { ok: false, at: 2 });
  chain('rewritten-between-checkpoints', [good[0], good[1], good[2], { sth: sthAt(8, 7, { root: flip(rootAt(8)) }), proof: prf(5, 8) }], guardian.pub, null, { ok: false, at: 3 });
  chain('dropped-history-shrinking-log', [good[3], { sth: sthAt(5, 4), proof: { oldSize: 8, newSize: 5, path: [] } }], guardian.pub, null, { ok: false, at: 1 });
  chain('prev-root-link-broken', [good[0], { sth: sthAt(2, 1, { prevRoot: rootAt(5) }), proof: prf(1, 2) }], guardian.pub, null, { ok: false, at: 1 });
  chain('late-signature-forged', [good[0], good[1], { sth: { ...good[2].sth, sig: flip(good[2].sth.sig) }, proof: good[2].proof }], guardian.pub, null, { ok: false, at: 2 });
  chain('other-guardian', good, other.pub, null, { ok: false, at: 0 });
  chain('not-an-array', 'chain', guardian.pub, null, { ok: false, at: 0 });
  chain('entry-null', [good[0], null], guardian.pub, null, { ok: false, at: 1 });
  {
    const pin = { [guardian.pub]: gML.pub };
    const pcp = (size, prev, from, alg) => ({ sth: sthAt(size, prev, { suite: suiteOf(alg, gML) }), ...(from === undefined ? {} : { proof: prf(from, size) }) });
    for (const [tag, alg] of [['ml', ML], ['hybrid', HY]]) {
      const pc = [pcp(5, 4, undefined, alg), pcp(8, 7, 5, alg), pcp(13, 12, 8, alg)];
      chain(`pq-${tag}-ok-pinned`, pc, guardian.pub, null, { ok: true }, pin);
      chain(`pq-${tag}-no-pin`, pc, guardian.pub, null, { ok: false, at: 0 });
      chain(`pq-${tag}-late-forged`, [pc[0], pc[1], { sth: { ...pc[2].sth, sig: flip(pc[2].sth.sig) }, proof: pc[2].proof }], guardian.pub, null, { ok: false, at: 2 }, pin);
    }
    chain('pq-mixed-ed25519-then-ml', [cp(5, 4), pcp(8, 7, 5, ML)], guardian.pub, null, { ok: true }, pin);
  }

  // ---- legacy witnessed heads and equivocation -----------------------------------------------------------------------
  const witnessed = [];
  const wh = (name, headObj, key, intended, pins) => {
    const v = { name, head: headObj, witness_public: key, ...(pins ? { pins } : {}) };
    v.expect = { ok: led.verifyWitnessedHead(headObj, key, pins ? { pqPins: pins } : undefined) };
    want('ledger_witnessed_head', name, v.expect.ok, intended);
    witnessed.push(v);
  };
  const W8 = mkLog(8).witnessHead(w1.sk);
  const W8b = mkLog(8, 'grant-1').witnessHead(w1.sk);
  wh('ok-basic', W8, w1.pub, true);
  wh('ok-empty-principal', mkLog(8, '').witnessHead(w1.sk), w1.pub, true);
  wh('wrong-witness-key', W8, w2.pub, false);
  wh('witness-field-differs', { ...W8, witness: w2.pub }, w1.pub, false);
  wh('tamper-size', { ...W8, size: 9 }, w1.pub, false);
  wh('tamper-root', { ...W8, root: flip(W8.root) }, w1.pub, false);
  wh('tamper-principal', { ...W8, principal: 'grant-2' }, w1.pub, false);
  wh('sig-bit-flip', { ...W8, sig: flip(W8.sig) }, w1.pub, false);
  wh('alg-unknown', { ...W8, alg: 'bogus-suite' }, w1.pub, false);
  wh('malformed-null', null, w1.pub, false);
  wh('domain-confusion-sth-signature', (() => { const s = sthAt(8, 7); return { principal: PRINCIPAL, size: 8, root: rootAt(8), witness: guardian.pub, sig: s.sig }; })(), guardian.pub, false);
  {
    const pin = { [w1.pub]: w1ML.pub };
    for (const [tag, alg] of [['ml', ML], ['hybrid', HY]]) {
      const h = mkLog(8).witnessHead(w1.sk, suiteOf(alg, w1ML));
      wh(`pq-${tag}-ok-pinned`, h, w1.pub, true, pin);
      wh(`pq-${tag}-no-pin`, h, w1.pub, false);
      wh(`pq-${tag}-wrong-pin`, h, w1.pub, false, { [w1.pub]: w2ML.pub });
      wh(`pq-${tag}-tamper-size`, { ...h, size: 9 }, w1.pub, false, pin);
      wh(`pq-${tag}-tamper-root`, { ...h, root: flip(h.root) }, w1.pub, false, pin);
      wh(`pq-${tag}-alg-stripped`, ((x) => (delete x.alg, x))(clone(h)), w1.pub, false, pin);
      wh(`pq-${tag}-alg-unknown`, { ...h, alg: 'bogus-suite' }, w1.pub, false, pin);
    }
    const hh2 = mkLog(8).witnessHead(w1.sk, suiteOf(HY, w1ML));
    wh('pq-hybrid-pq-sig-stripped', ((x) => (delete x.pq_sig, x))(clone(hh2)), w1.pub, false, pin);
    wh('pq-hybrid-pq-sig-bit-flip', { ...hh2, pq_sig: flip(hh2.pq_sig) }, w1.pub, false, pin);
    wh('pq-ml-empty-pins', mkLog(8).witnessHead(w1.sk, suiteOf(ML, w1ML)), w1.pub, false, {});
    {
      const slhK = core.slhDsa128fKeygen(seed48('ledger/witness-slh'));
      const hs = mkLog(8).witnessHead(w1.sk, { alg: 'slh-dsa-sha2-128f', slhDsa: slhK });
      wh('suite-slh-dsa-sha2-128f-ok-pinned', hs, w1.pub, true, { [w1.pub]: core.encodeSlhDsaPublicKey(slhK.publicKey) });
      witnessed[witnessed.length - 1].requires_suite = 'slh-dsa-sha2-128f';
      wh('suite-slh-dsa-sha2-128f-no-pin', hs, w1.pub, false);
      witnessed[witnessed.length - 1].requires_suite = 'slh-dsa-sha2-128f';
    }
  }
  const equiv = [];
  const eq = (name, a, b, key, intended) => {
    const v = { name, a, b, witness_public: key };
    v.expect = { equivocation: led.detectEquivocation(a, b, key) };
    want('ledger_equivocation', name, v.expect.equivocation, intended);
    equiv.push(v);
  };
  const fork = (() => { const l = new led.TransparencyLedger('grant-1'); for (let i = 0; i < 7; i++) l.appendCommitment(leaves[i]); l.appendCommitment(commit(500)); return l.witnessHead(w1.sk); })();
  eq('same-size-different-roots', W8, fork, w1.pub, true);
  eq('same-head-twice', W8, W8b, w1.pub, false);
  eq('different-sizes', W8, mkLog(9).witnessHead(w1.sk), w1.pub, false);
  eq('different-principals', W8, ((l) => { for (let i = 0; i < 7; i++) l.appendCommitment(leaves[i]); l.appendCommitment(commit(500)); return l.witnessHead(w1.sk); })(new led.TransparencyLedger('grant-2')), w1.pub, false);
  eq('one-forged', W8, { ...fork, sig: flip(fork.sig) }, w1.pub, false);
  eq('other-witness-key', W8, fork, w2.pub, false);
  eq('both-forged', { ...W8, sig: flip(W8.sig) }, { ...fork, sig: flip(fork.sig) }, w1.pub, false);

  return settled({
    format: 1,
    layer: 'extension',
    description: 'Transparency-ledger wire vectors (conformance/LAYERS.md, layer extension): RFC 6962 inclusion, RFC 9162 consistency, signed tree heads, witness cosignatures, checkpoint chains. Generated by packages/pca/scripts/gen-conformance-ext.mjs from the TypeScript reference; do not edit. Vectors named pq-* use ml-dsa-65 / hybrid-ed25519-ml-dsa-65: a vector with `pins` ({ <ed25519 identity b64u>: <ML-DSA-65 public key b64u> }) verifies under that pin set, a vector without `pins` has no pin (a pure-PQ or hybrid artifact is then refused); ledger_cosign carries its pins in `policy.pqPins`. A verifier without a suite refuses it as unsupported. Vectors named suite-* use a registered suite beyond ML-DSA (slh-dsa-sha2-128f, fn-dsa-512, less-cat1) and carry `requires_suite`: a verifier that implements the suite must return expect, one that lacks it must refuse (false), never accept. `pins: {}` is an explicit empty pin set (it replaces ledger_cosign\'s policy.pqPins), `pins` absent falls back to the policy.',
    keys: { guardian: guardian.pub, other: other.pub, witness_1: w1.pub, witness_2: w2.pub, witness_3: w3.pub, stranger: stranger.pub },
    empty_tree_root: EMPTY,
    domains: { sth: 'atlas-pca/sth/v1\u0000', sth_witness: 'atlas-pca/sth-witness/v2\u0000', ledger_head: 'atlas-pca/ledger-head/v1\u0000', optimistic_claim: 'atlas-pca/optimistic/v1\u0000', settlement: 'atlas-pca/bond-settlement/v1\u0000' },
    counts: { ledger_inclusion: inclusion.length, ledger_consistency: consistency.length, ledger_tree_head: heads.length, ledger_cosign: cosigs.length, ledger_head_consistency: hh.length, ledger_checkpoint_chain: chains.length, ledger_witnessed_head: witnessed.length, ledger_equivocation: equiv.length },
    ledger_inclusion: inclusion,
    ledger_consistency: consistency,
    ledger_tree_head: heads,
    ledger_cosign: cosigs,
    ledger_head_consistency: hh,
    ledger_checkpoint_chain: chains,
    ledger_witnessed_head: witnessed,
    ledger_equivocation: equiv,
  });
}

const pinOf = (v) => (v.pins ? { pqPins: v.pins } : undefined);

export function evaluateLedger({ led }, table, v) {
  switch (table) {
    case 'ledger_inclusion':
      return { ok: led.verifyLedgerInclusion(v.root, v.proof, v.leaf) };
    case 'ledger_consistency':
      return { ok: led.verifyLedgerConsistency(v.old_root, v.new_root, v.proof) };
    case 'ledger_tree_head':
      return { ok: led.verifyTreeHead(v.sth, v.guardian_public, undefined, pinOf(v)) };
    case 'ledger_cosign':
      return { ok: led.verifyTreeHead(v.sth, v.guardian_public, v.policy ?? undefined, pinOf(v)) };
    case 'ledger_head_consistency':
      return { ok: led.verifyHeadConsistency(v.older, v.newer, v.proof, v.guardian_public, undefined, pinOf(v)) };
    case 'ledger_checkpoint_chain': {
      const r = led.verifyCheckpointChain(v.chain, v.guardian_public, v.policy ?? undefined, pinOf(v));
      return r.ok ? { ok: true } : { ok: false, at: r.at };
    }
    case 'ledger_witnessed_head':
      return { ok: led.verifyWitnessedHead(v.head, v.witness_public, pinOf(v)) };
    case 'ledger_equivocation':
      return { equivocation: led.detectEquivocation(v.a, v.b, v.witness_public) };
    default:
      throw new Error(`unknown ledger table ${table}`);
  }
}

export const OPTIMISTIC_TABLES = ['optimistic_claim', 'optimistic_window', 'optimistic_fraud_proof', 'optimistic_settlement'];
export const LEDGER_TABLES = ['ledger_inclusion', 'ledger_consistency', 'ledger_tree_head', 'ledger_cosign', 'ledger_head_consistency', 'ledger_checkpoint_chain', 'ledger_witnessed_head', 'ledger_equivocation'];

/** One vector per line, like the rest of the corpus (valid JSON, diffable). */
export function serializeExt(doc) {
  const tables = new Set([...OPTIMISTIC_TABLES, ...LEDGER_TABLES]);
  const head = Object.entries(doc).filter(([k]) => !tables.has(k));
  const out = ['{'];
  const parts = head.map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  for (const t of Object.keys(doc).filter((k) => tables.has(k))) {
    parts.push(`  ${JSON.stringify(t)}: [\n${doc[t].map((x) => '    ' + JSON.stringify(x)).join(',\n')}\n  ]`);
  }
  out.push(parts.join(',\n'), '}', '');
  return out.join('\n');
}
