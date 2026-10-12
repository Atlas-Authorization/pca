// GlueContract.dfy - the contract between the TypeScript GLUE and the proved decision core, written down in Dafny.
//
// The verified core never evaluates a primitive: it consumes booleans / Res values / lazy closures that the glue computes
// (packages/pca/src/verified-decision.ts and the call sites in pcactn.ts, capability.ts, threshold.ts, replay.ts, server/verify.ts).
// This file states, as PRECONDITIONS ON THOSE BOOLEANS, what each one must mean, and proves what follows when the glue meets
// the contract: "the core accepted" => "the primitive facts really hold". It is a separate module that includes (never edits)
// the proved modules; it is verified with `dafny verify GlueContract.dfy --verify-included-files` (see ../../tools/pca-trustbase/run-all.sh).
//
// The contract is split in two halves, because the two directions matter differently:
//   SOUND  (b ==> P)  : the boolean is true only if the primitive property P holds.  Needed for "no wrong accept". This is
//                       what a signature-verification disagreement between two crypto libraries would break.
//   EXACT  (b <==> P) : additionally, a holding property is reported as true.      Needed for "no spurious deny" (completeness).
// The runtime contract-checking mode (packages/pca-verified-core/test/diverse/glue/**) enforces the SOUND half and the EXACT half
// against an independent recomputation (second library) on every call during tests and fuzzing.
//
// No assume, no {:axiom}, no extern. Primitive semantics are ordinary values in `World` (a signature-validity relation), so the
// theorems are about ANY primitive behaviour; they say nothing about whether a real library implements that relation.
include "Common.dfy"
include "Chain.dfy"
include "Threshold.dfy"
include "Replay.dfy"
include "Verdict.dfy"

module GlueContract {
  import opened Common
  import opened Chain
  import opened Threshold
  import opened Replay
  import opened Verdict

  // The abstract world: what "this signature verifies under this key for this message" means. `Key`, `Msg`, `Sig` are the
  // glue's own canonical encodings (b64u-decoded key bytes, domain-separated canonical message bytes, signature bytes), per suite.
  datatype World<!Key, !Msg, !Sig> = World(sigValid: (Key, Msg, Sig) -> bool)

  // What the glue READ from the artifact for one hop (independent of any primitive result).
  datatype HopSpec<Key, Msg, Sig, D> = HopSpec(
    issuer: Key,        // c.issuer
    holder: Key,        // c.holder
    msg: Msg,           // canonical signed body of the capability (domain-separated)
    sig: Sig,           // c.sig
    claimedParent: D,   // c.parent
    selfDigest: D)      // capHash(c)

  // ------------------------------------------------------------------------------------------------------------------
  // 1. Capability chain (Chain.Hop booleans)
  // ------------------------------------------------------------------------------------------------------------------

  // The key a hop's signature must verify under: the root's issuer, else the PARENT hop's holder.
  function SignerKey<Key, Msg, Sig, D>(specs: seq<HopSpec<Key, Msg, Sig, D>>, k: nat): Key
    requires k < |specs|
  { if k == 0 then specs[0].issuer else specs[k - 1].holder }

  // GLUE CONTRACT (sound half), per hop k:
  //   sig()                  is Ok  ==> the signature verifies under SignerKey(k) over msg_k      (body digest + suite signature check)
  //   parentLinkOk()         is true ==> hop.parent equals capHash(parent hop)                     (k >= 1)
  //   issuerIsParentHolder() is true ==> hop.issuer equals parent.holder                           (k >= 1)
  ghost predicate ChainGlueSound<M, C, Key, Msg, Sig, D>(hops: seq<Hop<M, C>>, specs: seq<HopSpec<Key, Msg, Sig, D>>, w: World<Key, Msg, Sig>) {
    |hops| == |specs| &&
    (forall k :: 0 <= k < |hops| ==> (hops[k].sig().Ok? ==> w.sigValid(SignerKey(specs, k), specs[k].msg, specs[k].sig))) &&
    (forall k :: 1 <= k < |hops| ==> (hops[k].parentLinkOk() ==> specs[k].claimedParent == specs[k - 1].selfDigest)) &&
    (forall k :: 1 <= k < |hops| ==> (hops[k].issuerIsParentHolder() ==> specs[k].issuer == specs[k - 1].holder))
  }

  // THEOREM (chain): if the glue meets the sound contract, an accepted chain is a real delegation chain: every hop's signature
  // verifies under its signer (root: the issuer; others: the parent's holder), each hop names its parent's digest, and each
  // issuer is the parent's holder.
  lemma ChainAcceptedMeansRealDelegation<M, C, Key, Msg, Sig, D>(
      hops: seq<Hop<M, C>>, specs: seq<HopSpec<Key, Msg, Sig, D>>, w: World<Key, Msg, Sig>,
      ceq: (C, C) -> bool, alloc: () -> Res<M>)
    requires ChainGlueSound(hops, specs, w)
    requires VerifyChain(hops, ceq, alloc) == ChainOk
    ensures 1 <= |hops| <= MaxDepth
    ensures forall k :: 0 <= k < |hops| ==> w.sigValid(SignerKey(specs, k), specs[k].msg, specs[k].sig)
    ensures forall k :: 1 <= k < |hops| ==>
              specs[k].claimedParent == specs[k - 1].selfDigest && specs[k].issuer == specs[k - 1].holder &&
              w.sigValid(specs[k - 1].holder, specs[k].msg, specs[k].sig)
  {
    ChainSound(hops, ceq, alloc);
  }

  // The EXACT half: the converse direction of the three booleans (needed for completeness: no spurious deny).
  ghost predicate ChainGlueExact<M, C, Key, Msg, Sig, D>(hops: seq<Hop<M, C>>, specs: seq<HopSpec<Key, Msg, Sig, D>>, w: World<Key, Msg, Sig>) {
    |hops| == |specs| &&
    (forall k :: 0 <= k < |hops| ==> (hops[k].sig().Ok? <==> w.sigValid(SignerKey(specs, k), specs[k].msg, specs[k].sig))) &&
    (forall k :: 1 <= k < |hops| ==> (hops[k].parentLinkOk() <==> specs[k].claimedParent == specs[k - 1].selfDigest)) &&
    (forall k :: 1 <= k < |hops| ==> (hops[k].issuerIsParentHolder() <==> specs[k].issuer == specs[k - 1].holder))
  }

  // ------------------------------------------------------------------------------------------------------------------
  // 2. Leaf signature (Verdict.LeafDecision: `verify` and `sigIsString`)
  // ------------------------------------------------------------------------------------------------------------------
  // GLUE CONTRACT: verify() is true ==> the leaf signature verifies under the leaf holder's key over the PCActn signing message.
  lemma LeafPassMeansValidSignature<M, Key, Msg, Sig>(
      w: World<Key, Msg, Sig>, holder: Key, msg: Msg, sig: Sig,
      leafPresent: bool, suiteErr: () -> Res<M>, sigIsString: bool, verify: () -> bool)
    requires verify() ==> w.sigValid(holder, msg, sig)
    requires LeafDecision(leafPresent, suiteErr, sigIsString, verify).LeafPass?
    ensures leafPresent && suiteErr().Ok? && sigIsString && w.sigValid(holder, msg, sig)
  { LeafSound(leafPresent, suiteErr, sigIsString, verify); }

  // ------------------------------------------------------------------------------------------------------------------
  // 3. Threshold shares (Threshold.Share.sigOk, Baseline.leafSigOk)
  // ------------------------------------------------------------------------------------------------------------------
  // The key set whose signatures are "backed": every counted key belongs to a well-formed share whose sigOk() held, or is the
  // baseline agent whose leafSigOk() held.
  ghost predicate ShareBacked<K(==)>(shares: seq<Share<K>>, k: K) {
    exists j :: 0 <= j < |shares| && shares[j].wellFormed && shares[j].key == k && shares[j].sigOk()
  }
  ghost predicate AllBacked<K(==)>(shares: seq<Share<K>>, ks: seq<K>) {
    forall i :: 0 <= i < |ks| ==> ShareBacked(shares, ks[i])
  }

  lemma FoldBacked<K(==)>(reg: Reg<K>, shares: seq<Share<K>>, i: nat, st: St<K>)
    requires i <= |shares|
    requires AllBacked(shares, st.keys)
    ensures AllBacked(shares, Fold(reg, shares, i, st).keys)
    decreases |shares| - i
  {
    if i < |shares| {
      var st2 := Step(reg, i, shares[i], st);
      // Step either leaves keys unchanged or appends shares[i].key after sigOk() held on a well-formed share
      if st2.keys != st.keys {
        assert st2.keys == st.keys + [shares[i].key];
        assert shares[i].wellFormed && shares[i].sigOk();
        assert ShareBacked(shares, shares[i].key);
      }
      assert AllBacked(shares, st2.keys);
      FoldBacked(reg, shares, i + 1, st2);
    }
  }

  // THEOREM (threshold): if Verify accepts, every counted key is backed by a true sigOk() (or the baseline leaf signature).
  // With the glue contract "sigOk() ==> the share's signature verifies under its key over the role/set/t-bound message"
  // (ShareSigContract) this yields: every counted role has a really valid signature, i.e. t distinct real signers.
  ghost predicate ShareSigContract<K(==), Msg, Sig>(shares: seq<Share<K>>, w: World<K, Msg, Sig>, msgs: seq<Msg>, sigs: seq<Sig>) {
    |shares| == |msgs| == |sigs| &&
    forall j :: 0 <= j < |shares| ==> (shares[j].sigOk() ==> w.sigValid(shares[j].key, msgs[j], sigs[j]))
  }

  // Every key the accepted verdict counts is either (a) a key of a well-formed share whose sigOk() held, hence (by the glue
  // contract) a REAL valid signature by that key, or (b) the baseline agent key whose leafSigOk() held (hence a real leaf signature).
  lemma ThresholdCountedKeysHaveValidSignatures<K(==), Msg, Sig>(
      es: seq<Signer<K>>, shares: seq<Share<K>>, t: int, baseline: Option<Baseline<K>>,
      w: World<K, Msg, Sig>, msgs: seq<Msg>, sigs: seq<Sig>, bmsg: Msg, bsig: Sig)
    requires ShareSigContract(shares, w, msgs, sigs)
    requires baseline.Some? ==> (baseline.v.leafSigOk() ==> w.sigValid(baseline.v.holder, bmsg, bsig))
    requires Verify(es, shares, t, baseline).ok
    ensures BuildReg(es, 0, []).RegOk?
    ensures var reg := BuildReg(es, 0, []).reg;
            var st := BaselineStep(reg, baseline, Fold(reg, shares, 0, St([], [], None)));
            |st.keys| >= t &&
            forall i :: 0 <= i < |st.keys| ==>
              (exists j :: 0 <= j < |shares| && shares[j].key == st.keys[i] && w.sigValid(st.keys[i], msgs[j], sigs[j])) ||
              (baseline.Some? && baseline.v.holder == st.keys[i] && w.sigValid(st.keys[i], bmsg, bsig))
  {
    ThresholdSound(es, shares, t, baseline);
    var reg := BuildReg(es, 0, []).reg;
    var st0 := Fold(reg, shares, 0, St([], [], None));
    FoldBacked(reg, shares, 0, St([], [], None));
    var st := BaselineStep(reg, baseline, st0);
    assert |st.keys| >= t;
    forall i | 0 <= i < |st.keys|
      ensures (exists j :: 0 <= j < |shares| && shares[j].key == st.keys[i] && w.sigValid(st.keys[i], msgs[j], sigs[j])) ||
              (baseline.Some? && baseline.v.holder == st.keys[i] && w.sigValid(st.keys[i], bmsg, bsig))
    {
      if i < |st0.keys| {
        assert ShareBacked(shares, st0.keys[i]);
        var j :| 0 <= j < |shares| && shares[j].wellFormed && shares[j].key == st0.keys[i] && shares[j].sigOk();
        assert w.sigValid(shares[j].key, msgs[j], sigs[j]);
      } else {
        // the only way keys grow in BaselineStep is the baseline branch, which required bl.leafSigOk()
        assert baseline.Some? && baseline.v.leafSigOk() && st.keys[i] == baseline.v.holder;
      }
    }
  }

  // The backed-ness invariant itself (what the contract is applied to): the keys the Verify fold counts, before the baseline.
  lemma VerifyCountsOnlyBackedKeys<K(==)>(es: seq<Signer<K>>, shares: seq<Share<K>>)
    requires BuildReg(es, 0, []).RegOk?
    ensures var reg := BuildReg(es, 0, []).reg;
            AllBacked(shares, Fold(reg, shares, 0, St([], [], None)).keys)
  {
    var reg := BuildReg(es, 0, []).reg;
    FoldBacked(reg, shares, 0, St([], [], None));
  }

  // ------------------------------------------------------------------------------------------------------------------
  // 4. Integer / clock facts (Replay.Facts, Verdict.ValidityDecision)
  // ------------------------------------------------------------------------------------------------------------------
  // JavaScript numbers: the glue passes `iat/exp/now` as Dafny ints only when Number.isSafeInteger holds. The `*Ok` booleans
  // MUST mean "the TypeScript value is a safe integer (iat/exp additionally >= 0)". Outside that range the TS double arithmetic
  // (e.g. `p.exp + skew` in replay.ts) is not exact, which the core's mathematical-integer reasoning does not model.
  const MaxSafe: int := 9007199254740991

  ghost predicate SafeInt(n: int) { -MaxSafe <= n <= MaxSafe }
  ghost predicate SafeNonNeg(n: int) { 0 <= n <= MaxSafe }

  ghost predicate ReplayFactsContract(f: Facts) {
    (f.nowOk ==> SafeInt(f.now)) &&
    (f.iatOk ==> SafeNonNeg(f.iat)) &&
    (f.expOk ==> SafeNonNeg(f.exp)) &&
    (0 <= f.skew <= Replay.MaxSkewMs)   // glue floors the (possibly fractional) skew and clamps it to the protocol maximum
  }

  // Everything the core's Pre-pass guarantees about integers is only meaningful under ReplayFactsContract:
  lemma PreNoneImpliesWellFormedWindow(f: Facts)
    requires ReplayFactsContract(f)
    requires Pre(f).None?
    ensures f.nowOk && f.iatOk && f.expOk && SafeInt(f.now) && SafeNonNeg(f.iat) && SafeNonNeg(f.exp)
  { }

  // DOCUMENTED GAP (found by the diverse-compilation campaign): the retention horizon exp + skew can leave the safe-integer
  // range even though every input satisfies the contract. The core computes it exactly; a TypeScript caller that computes it
  // in doubles (replayRetainUntil via .toNumber(), or `p.exp + skew` in replay.ts) rounds above 2^53. Both ends are year ~287,396
  // epoch-ms, so the effect is a retention horizon off by 1 ms there; the lemma is the machine-checked witness.
  lemma RetainUntilCanLeaveSafeRange()
    ensures exists f: Facts :: ReplayFactsContract(f) && !SafeInt(RetainUntil(f))
  {
    var f := Facts(true, true, true, true, true, true, 0, MaxSafe, 0, 1, true, true, true, true, true, true, true);
    assert RetainUntil(f) == MaxSafe + 1;
    assert ReplayFactsContract(f);
  }
}
