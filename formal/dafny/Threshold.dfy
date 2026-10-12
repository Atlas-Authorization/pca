// Threshold.dfy - t-of-n distinct-role counting (threshold.ts: verifyThreshold) as a verified pure function.
//
// Trusted base (supplied by the glue): per-share signature verification (`sigOk`), the agent-leaf baseline
// signature (`leafSigOk`), key well-formedness (`keyOk`, `pqOk`), suite knowledge (`algKnown`),
// and whether a share that names its own `pq_pk` names exactly its role's registered one (`pqPkOk`; naming none is fine).
// Proved here: signer-set validation (one key per role, one role per key), the share-counting loop,
// the distinct-key/role count, and the t decision.
include "Common.dfy"
module Threshold {
  import opened Common

  datatype Role = Agent | Guardian | Principal

  datatype Signer<K> = Signer(role: Option<Role>, keyOk: bool, pqOk: bool, key: K)
  datatype Share<K> = Share(wellFormed: bool, role: Option<Role>, key: K, algKnown: bool, pqPkOk: bool, sigOk: () -> bool)
  datatype Baseline<K> = Baseline(holderIsString: bool, holder: K, pqKeyOk: () -> bool, leafSigOk: () -> bool)

  datatype ThReason =
    | InvalidT
    | SetMalformed
    | SetPq
    | TwoKeysForRole(entry: nat)
    | OneKeyTwoRoles
    | MalformedShare
    | RoleNotInSet(share: nat)
    | KeyNotRegistered(share: nat)
    | UnknownAlg(share: nat)
    | PqPkMismatch(share: nat)
    | InvalidSig(share: nat)
    | NeedMore

  datatype ThVerdict = ThVerdict(ok: bool, count: nat, roles: seq<Role>, reason: Option<ThReason>)

  type Reg<K> = seq<(Role, K)>

  function ValidT(t: int): bool { t == 1 || t == 2 || t == 3 }

  function LookupKey<K(==)>(reg: Reg<K>, r: Role): Option<K>
    decreases |reg|
  { if |reg| == 0 then None else if reg[0].0 == r then Some(reg[0].1) else LookupKey(reg[1..], r) }

  function LookupRole<K(==)>(reg: Reg<K>, k: K): Option<Role>
    decreases |reg|
  { if |reg| == 0 then None else if reg[0].1 == k then Some(reg[0].0) else LookupRole(reg[1..], k) }

  // Registry well-formedness: one key per role, one role per key.
  ghost predicate RegValid<K(==)>(reg: Reg<K>) {
    forall i, j :: 0 <= i < j < |reg| ==> reg[i].0 != reg[j].0 && reg[i].1 != reg[j].1
  }

  datatype RegResult<K> = RegOk(reg: Reg<K>) | RegBad(r: ThReason)

  function BuildReg<K(==)>(es: seq<Signer<K>>, from: nat, reg: Reg<K>): RegResult<K>
    requires from <= |es|
    decreases |es| - from
  {
    if from == |es| then RegOk(reg)
    else
      var e := es[from];
      if !(e.role.Some? && e.keyOk) then RegBad(SetMalformed)
      else if !e.pqOk then RegBad(SetPq)
      else
        var r := e.role.v;
        var prevKey := LookupKey(reg, r);
        if prevKey.Some? && prevKey.v != e.key then RegBad(TwoKeysForRole(from))
        else
          var prevRole := LookupRole(reg, e.key);
          if prevRole.Some? && prevRole.v != r then RegBad(OneKeyTwoRoles)
          else BuildReg(es, from + 1, if prevKey.Some? then reg else reg + [(r, e.key)])
  }

  lemma LookupKeyIn<K(==)>(reg: Reg<K>, r: Role)
    ensures LookupKey(reg, r).Some? <==> exists i :: 0 <= i < |reg| && reg[i].0 == r
    ensures LookupKey(reg, r).Some? ==> exists i :: 0 <= i < |reg| && reg[i].0 == r && reg[i].1 == LookupKey(reg, r).v
    decreases |reg|
  {
    if |reg| > 0 && reg[0].0 != r {
      LookupKeyIn(reg[1..], r);
      if LookupKey(reg[1..], r).Some? { var i :| 0 <= i < |reg[1..]| && reg[1..][i].0 == r && reg[1..][i].1 == LookupKey(reg[1..], r).v; assert reg[i + 1] == reg[1..][i]; }
      if exists i :: 0 <= i < |reg| && reg[i].0 == r { var i :| 0 <= i < |reg| && reg[i].0 == r; assert i >= 1; assert reg[1..][i - 1].0 == r; }
    }
  }

  lemma LookupRoleIn<K(==)>(reg: Reg<K>, k: K)
    ensures LookupRole(reg, k).Some? <==> exists i :: 0 <= i < |reg| && reg[i].1 == k
    ensures LookupRole(reg, k).Some? ==> exists i :: 0 <= i < |reg| && reg[i].1 == k && reg[i].0 == LookupRole(reg, k).v
    decreases |reg|
  {
    if |reg| > 0 && reg[0].1 != k {
      LookupRoleIn(reg[1..], k);
      if LookupRole(reg[1..], k).Some? { var i :| 0 <= i < |reg[1..]| && reg[1..][i].1 == k && reg[1..][i].0 == LookupRole(reg[1..], k).v; assert reg[i + 1] == reg[1..][i]; }
      if exists i :: 0 <= i < |reg| && reg[i].1 == k { var i :| 0 <= i < |reg| && reg[i].1 == k; assert i >= 1; assert reg[1..][i - 1].1 == k; }
    }
  }

  lemma BuildRegValid<K(==)>(es: seq<Signer<K>>, from: nat, reg: Reg<K>)
    requires from <= |es|
    requires RegValid(reg)
    ensures BuildReg(es, from, reg).RegOk? ==> RegValid(BuildReg(es, from, reg).reg)
    ensures BuildReg(es, from, reg).RegOk? ==> |BuildReg(es, from, reg).reg| <= |reg| + (|es| - from)
    // every registry entry produced is a (role, key) from a signer entry
    ensures BuildReg(es, from, reg).RegOk? ==> |BuildReg(es, from, reg).reg| <= 3
    decreases |es| - from
  {
    if from < |es| {
      var e := es[from];
      if e.role.Some? && e.keyOk && e.pqOk {
        var r := e.role.v;
        var prevKey := LookupKey(reg, r);
        LookupKeyIn(reg, r);
        LookupRoleIn(reg, e.key);
        if !(prevKey.Some? && prevKey.v != e.key) {
          var prevRole := LookupRole(reg, e.key);
          if !(prevRole.Some? && prevRole.v != r) {
            if prevKey.Some? {
              BuildRegValid(es, from + 1, reg);
            } else {
              // no entry with role r; and no entry with key e.key (else prevRole == Some(r) forces a role-r entry)
              assert prevRole.None? by {
                if prevRole.Some? {
                  assert prevRole.v == r;
                  var i :| 0 <= i < |reg| && reg[i].1 == e.key && reg[i].0 == prevRole.v;
                  assert reg[i].0 == r;
                }
              }
              var reg2 := reg + [(r, e.key)];
              assert RegValid(reg2) by {
                forall i, j | 0 <= i < j < |reg2| ensures reg2[i].0 != reg2[j].0 && reg2[i].1 != reg2[j].1 {
                  if j == |reg| {
                    // i < |reg|: reg[i].0 != r and reg[i].1 != e.key
                    assert reg2[j] == (r, e.key);
                    if reg[i].0 == r { assert exists i0 :: 0 <= i0 < |reg| && reg[i0].0 == r; }
                    if reg[i].1 == e.key { assert exists i0 :: 0 <= i0 < |reg| && reg[i0].1 == e.key; }
                  }
                }
              }
              BuildRegValid(es, from + 1, reg2);
            }
          }
        }
      }
    }
    // |reg| <= 3 : RegValid implies injective into the 3-element Role type
    if BuildReg(es, from, reg).RegOk? {
      var out := BuildReg(es, from, reg).reg;
      assert RegValid(out);
      RegBounded(out);
    }
  }

  // A registry with distinct roles has at most 3 entries (the Role type has 3 values).
  lemma RegBounded<K(==)>(reg: Reg<K>)
    requires forall i, j :: 0 <= i < j < |reg| ==> reg[i].0 != reg[j].0
    ensures |reg| <= 3
  {
    var rs := seq(|reg|, i requires 0 <= i < |reg| => reg[i].0);
    assert forall i, j :: 0 <= i < j < |rs| ==> rs[i] != rs[j];
    DistinctBounded(rs);
  }

  lemma SubsetCardinality<T>(a: set<T>, b: set<T>)
    requires a <= b
    ensures |a| <= |b|
    decreases |a|
  {
    if a != {} {
      var x :| x in a;
      SubsetCardinality(a - {x}, b - {x});
    }
  }

  lemma StrictSubsetCardinality<T>(a: set<T>, b: set<T>)
    requires a < b
    ensures |a| < |b|
  {
    var x :| x in b && x !in a;
    SubsetCardinality(a, b - {x});
  }

  const AllRoles: set<Role> := {Agent, Guardian, Principal}

  lemma AllRolesCard() ensures |AllRoles| == 3 {}

  // ---- the share-counting loop ----
  datatype St<K> = St(keys: seq<K>, roles: seq<Role>, reason: Option<ThReason>)

  function First(a: Option<ThReason>, b: ThReason): Option<ThReason> { if a.Some? then a else Some(b) }

  function Contains<K(==)>(ks: seq<K>, k: K): bool { exists i :: 0 <= i < |ks| && ks[i] == k }

  predicate ContainsB<K(==)>(ks: seq<K>, k: K)
    decreases |ks|
  { |ks| > 0 && (ks[0] == k || ContainsB(ks[1..], k)) }

  lemma ContainsBIff<K(==)>(ks: seq<K>, k: K)
    ensures ContainsB(ks, k) <==> Contains(ks, k)
    decreases |ks|
  {
    if |ks| > 0 {
      ContainsBIff(ks[1..], k);
      if Contains(ks, k) && ks[0] != k { var i :| 0 <= i < |ks| && ks[i] == k; assert i >= 1; assert ks[1..][i - 1] == k; }
      if Contains(ks[1..], k) { var i :| 0 <= i < |ks[1..]| && ks[1..][i] == k; assert ks[i + 1] == k; }
    }
  }

  function Step<K(==)>(reg: Reg<K>, i: nat, sh: Share<K>, st: St<K>): St<K> {
    if !sh.wellFormed then St(st.keys, st.roles, First(st.reason, MalformedShare))
    else if ContainsB(st.keys, sh.key) then st
    else
      var rk := if sh.role.Some? then LookupKey(reg, sh.role.v) else None;
      if rk.None? then St(st.keys, st.roles, First(st.reason, RoleNotInSet(i)))
      else if rk.v != sh.key then St(st.keys, st.roles, First(st.reason, KeyNotRegistered(i)))
      else if !sh.algKnown then St(st.keys, st.roles, First(st.reason, UnknownAlg(i)))
      else if !sh.pqPkOk then St(st.keys, st.roles, First(st.reason, PqPkMismatch(i)))
      else if !sh.sigOk() then St(st.keys, st.roles, First(st.reason, InvalidSig(i)))
      else St(st.keys + [sh.key], st.roles + [sh.role.v], st.reason)
  }

  function Fold<K(==)>(reg: Reg<K>, shares: seq<Share<K>>, i: nat, st: St<K>): St<K>
    requires i <= |shares|
    decreases |shares| - i
  {
    if i == |shares| then st else Fold(reg, shares, i + 1, Step(reg, i, shares[i], st))
  }

  function BaselineStep<K(==)>(reg: Reg<K>, b: Option<Baseline<K>>, st: St<K>): St<K> {
    if b.None? then st
    else
      var bl := b.v;
      var agentKey := LookupKey(reg, Agent);
      if bl.holderIsString && agentKey.Some? && bl.holder == agentKey.v && !ContainsB(st.keys, agentKey.v)
         && bl.pqKeyOk() && bl.leafSigOk()
      then St(st.keys + [agentKey.v], st.roles + [Agent], st.reason)
      else st
  }

  function Verify<K(==)>(es: seq<Signer<K>>, shares: seq<Share<K>>, t: int, baseline: Option<Baseline<K>>): ThVerdict {
    if !ValidT(t) then ThVerdict(false, 0, [], Some(InvalidT))
    else match BuildReg(es, 0, []) {
      case RegBad(r) => ThVerdict(false, 0, [], Some(r))
      case RegOk(reg) =>
        var st := BaselineStep(reg, baseline, Fold(reg, shares, 0, St([], [], None)));
        var count := |st.keys|;
        if count >= t then ThVerdict(true, count, st.roles, None)
        else ThVerdict(false, count, st.roles, if st.reason.Some? then st.reason else Some(NeedMore))
    }
  }

  // ---- invariants and theorems ----
  ghost predicate Inv<K(==)>(reg: Reg<K>, st: St<K>) {
    |st.keys| == |st.roles| &&
    (forall i, j :: 0 <= i < j < |st.keys| ==> st.keys[i] != st.keys[j]) &&
    (forall i :: 0 <= i < |st.keys| ==> (st.roles[i], st.keys[i]) in reg)
  }

  lemma StepInv<K(==)>(reg: Reg<K>, i: nat, sh: Share<K>, st: St<K>)
    requires RegValid(reg) && Inv(reg, st)
    ensures Inv(reg, Step(reg, i, sh, st))
    // the step only ever appends a registered (role,key) with a verified signature
    ensures |Step(reg, i, sh, st).keys| == |st.keys| || |Step(reg, i, sh, st).keys| == |st.keys| + 1
    ensures st.keys <= Step(reg, i, sh, st).keys && st.roles <= Step(reg, i, sh, st).roles
  {
    var s2 := Step(reg, i, sh, st);
    if sh.wellFormed && !ContainsB(st.keys, sh.key) {
      var rk := if sh.role.Some? then LookupKey(reg, sh.role.v) else None;
      if rk.Some? && rk.v == sh.key && sh.algKnown && sh.pqPkOk && sh.sigOk() {
        LookupKeyIn(reg, sh.role.v);
        ContainsBIff(st.keys, sh.key);
        assert (sh.role.v, sh.key) in reg by {
          var q :| 0 <= q < |reg| && reg[q].0 == sh.role.v && reg[q].1 == rk.v;
          assert reg[q] == (sh.role.v, sh.key);
        }
        assert !Contains(st.keys, sh.key);
        assert forall a, b :: 0 <= a < b < |s2.keys| ==> s2.keys[a] != s2.keys[b] by {
          forall a, b | 0 <= a < b < |s2.keys| ensures s2.keys[a] != s2.keys[b] {
            if b == |st.keys| { assert s2.keys[b] == sh.key; assert s2.keys[a] == st.keys[a]; assert st.keys[a] != sh.key by { if st.keys[a] == sh.key { assert Contains(st.keys, sh.key); } } }
            else { assert s2.keys[a] == st.keys[a] && s2.keys[b] == st.keys[b]; }
          }
        }
      }
    }
  }

  lemma FoldInv<K(==)>(reg: Reg<K>, shares: seq<Share<K>>, i: nat, st: St<K>)
    requires i <= |shares| && RegValid(reg) && Inv(reg, st)
    ensures Inv(reg, Fold(reg, shares, i, st))
    ensures st.keys <= Fold(reg, shares, i, st).keys
    decreases |shares| - i
  {
    if i < |shares| {
      StepInv(reg, i, shares[i], st);
      FoldInv(reg, shares, i + 1, Step(reg, i, shares[i], st));
    }
  }

  lemma BaselineInv<K(==)>(reg: Reg<K>, b: Option<Baseline<K>>, st: St<K>)
    requires RegValid(reg) && Inv(reg, st)
    ensures Inv(reg, BaselineStep(reg, b, st))
  {
    if b.Some? {
      var bl := b.v;
      var agentKey := LookupKey(reg, Agent);
      if bl.holderIsString && agentKey.Some? && bl.holder == agentKey.v && !ContainsB(st.keys, agentKey.v) && bl.pqKeyOk() && bl.leafSigOk() {
        LookupKeyIn(reg, Agent);
        ContainsBIff(st.keys, agentKey.v);
        var q :| 0 <= q < |reg| && reg[q].0 == Agent && reg[q].1 == agentKey.v;
        assert reg[q] == (Agent, agentKey.v);
        var s2 := BaselineStep(reg, b, st);
        forall a, c | 0 <= a < c < |s2.keys| ensures s2.keys[a] != s2.keys[c] {
          if c == |st.keys| { assert s2.keys[a] == st.keys[a]; if st.keys[a] == agentKey.v { assert Contains(st.keys, agentKey.v); } }
        }
      }
    }
  }

  lemma RolesDistinct<K(==)>(reg: Reg<K>, st: St<K>)
    requires RegValid(reg) && Inv(reg, st)
    ensures forall i, j :: 0 <= i < j < |st.roles| ==> st.roles[i] != st.roles[j]
  {
    forall i, j | 0 <= i < j < |st.roles| ensures st.roles[i] != st.roles[j] {
      var qi :| 0 <= qi < |reg| && reg[qi] == (st.roles[i], st.keys[i]);
      var qj :| 0 <= qj < |reg| && reg[qj] == (st.roles[j], st.keys[j]);
      if st.roles[i] == st.roles[j] {
        // same role in the registry => same entry => same key, contradicting distinct keys
        if qi != qj { if qi < qj { assert reg[qi].0 != reg[qj].0; } else { assert reg[qj].0 != reg[qi].0; } }
        assert qi == qj;
        assert st.keys[i] == st.keys[j];
      }
    }
  }

  // THEOREM (threshold soundness, all signer sets / share lists of any length): if Verify accepts then
  //   t in {1,2,3}; the signer set is a valid registry (one key per role, one role per key); the accepted
  //   roles are pairwise distinct, each registered, there are at least t of them, and at most 3.
  lemma ThresholdSound<K(==)>(es: seq<Signer<K>>, shares: seq<Share<K>>, t: int, baseline: Option<Baseline<K>>)
    requires Verify(es, shares, t, baseline).ok
    ensures ValidT(t)
    ensures BuildReg(es, 0, []).RegOk?
    ensures var v := Verify(es, shares, t, baseline);
            v.count == |v.roles| && v.count >= t && v.count <= 3 &&
            (forall i, j :: 0 <= i < j < |v.roles| ==> v.roles[i] != v.roles[j]) &&
            v.reason.None?
    ensures var reg := BuildReg(es, 0, []).reg;
            RegValid(reg) &&
            forall r :: r in Verify(es, shares, t, baseline).roles ==> LookupKey(reg, r).Some?
  {
    var reg := BuildReg(es, 0, []).reg;
    BuildRegValid(es, 0, []);
    var st0 := St([], [], None);
    var f := Fold(reg, shares, 0, st0);
    FoldInv(reg, shares, 0, st0);
    BaselineInv(reg, baseline, f);
    var st := BaselineStep(reg, baseline, f);
    RolesDistinct(reg, st);
    RegBounded(reg);
    // |st.roles| <= |reg| <= 3 by distinct roles
    DistinctBounded(st.roles);
    forall r | r in st.roles ensures LookupKey(reg, r).Some? {
      var i :| 0 <= i < |st.roles| && st.roles[i] == r;
      assert (st.roles[i], st.keys[i]) in reg;
      var q :| 0 <= q < |reg| && reg[q] == (r, st.keys[i]);
      LookupKeyIn(reg, r);
    }
  }

  lemma DistinctBounded(rs: seq<Role>)
    requires forall i, j :: 0 <= i < j < |rs| ==> rs[i] != rs[j]
    ensures |rs| <= 3
  {
    var s := set i | 0 <= i < |rs| :: rs[i];
    DistinctCard(rs, s);
  }

  lemma DistinctCard(rs: seq<Role>, s: set<Role>)
    requires forall i, j :: 0 <= i < j < |rs| ==> rs[i] != rs[j]
    requires s == set i | 0 <= i < |rs| :: rs[i]
    ensures |s| == |rs| && |rs| <= 3
    decreases |rs|
  {
    if |rs| > 0 {
      var rest := rs[..|rs| - 1];
      var s2 := set i | 0 <= i < |rest| :: rest[i];
      assert s == s2 + {rs[|rs| - 1]};
      assert rs[|rs| - 1] !in s2;
      DistinctCard(rest, s2);
    }
    assert s <= AllRoles;
    SubsetCardinality(s, AllRoles);
    AllRolesCard();
  }

  // THEOREM (exactly t distinct roles needed): t = 3 accepted => agent, guardian AND principal all contributed.
  lemma ThresholdThreeNeedsAllRoles<K(==)>(es: seq<Signer<K>>, shares: seq<Share<K>>, baseline: Option<Baseline<K>>)
    requires Verify(es, shares, 3, baseline).ok
    ensures var v := Verify(es, shares, 3, baseline);
            Agent in v.roles && Guardian in v.roles && Principal in v.roles
  {
    ThresholdSound(es, shares, 3, baseline);
    var v := Verify(es, shares, 3, baseline);
    var s := set i | 0 <= i < |v.roles| :: v.roles[i];
    DistinctCard(v.roles, s);
    assert |s| == 3;
    AllRolesCard();
    assert s <= AllRoles;
    if s != AllRoles { StrictSubsetCardinality(s, AllRoles); }
    assert s == AllRoles;
    forall r | r in AllRoles ensures r in v.roles {
      assert r in s;
      var i :| 0 <= i < |v.roles| && v.roles[i] == r;
    }
  }

  // Fail-closed: invalid t, or a malformed signer set, can never be rescued by shares or baseline.
  lemma FailsClosed<K(==)>(es: seq<Signer<K>>, shares: seq<Share<K>>, t: int, baseline: Option<Baseline<K>>)
    ensures !ValidT(t) ==> !Verify(es, shares, t, baseline).ok
    ensures BuildReg(es, 0, []).RegBad? ==> !Verify(es, shares, t, baseline).ok
  {}

  // A share that names a pq_pk other than its role's registered key is never counted (whatever its signatures).
  lemma PqPkMismatchNeverCounts<K(==)>(reg: Reg<K>, i: nat, sh: Share<K>, st: St<K>)
    requires !sh.pqPkOk
    ensures Step(reg, i, sh, st).keys == st.keys
  {}

  // A repeated key is never counted twice.
  lemma DuplicateIgnored<K(==)>(reg: Reg<K>, i: nat, sh: Share<K>, st: St<K>)
    requires sh.wellFormed && ContainsB(st.keys, sh.key)
    ensures Step(reg, i, sh, st) == st
  {}

  // THEOREM (determinism / extensionality): the verdict depends only on the observable facts of the shares
  // (flags, role, key, and the BOOLEAN each lazy check returns), never on anything else.
  lemma StepExt<K(==)>(reg: Reg<K>, i: nat, a: Share<K>, b: Share<K>, st: St<K>)
    requires a.wellFormed == b.wellFormed && a.role == b.role && a.key == b.key && a.algKnown == b.algKnown && a.pqPkOk == b.pqPkOk && a.sigOk() == b.sigOk()
    ensures Step(reg, i, a, st) == Step(reg, i, b, st)
  {}

  lemma FoldExt<K(==)>(reg: Reg<K>, s1: seq<Share<K>>, s2: seq<Share<K>>, i: nat, st: St<K>)
    requires |s1| == |s2| && i <= |s1|
    requires forall k :: 0 <= k < |s1| ==>
      s1[k].wellFormed == s2[k].wellFormed && s1[k].role == s2[k].role && s1[k].key == s2[k].key &&
      s1[k].algKnown == s2[k].algKnown && s1[k].pqPkOk == s2[k].pqPkOk && s1[k].sigOk() == s2[k].sigOk()
    ensures Fold(reg, s1, i, st) == Fold(reg, s2, i, st)
    decreases |s1| - i
  {
    if i < |s1| {
      StepExt(reg, i, s1[i], s2[i], st);
      FoldExt(reg, s1, s2, i + 1, Step(reg, i, s1[i], st));
    }
  }
}
