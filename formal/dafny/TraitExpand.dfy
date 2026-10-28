// TraitExpand.dfy - the executable trait algebra of the PCA action kit (docs/pca/specs/action-kit.md section 3.4), with
// theorems T1 .. T7 as lemmas. STANDALONE (no includes), no assume / axiom / extern. Compiled to JavaScript by
// formal/dafny/build-ext.sh TraitExpand (same recipe as the other extension components); the Lean development
// formal/intent/lean/PcaIntent/TraitAlg.lean proves the same statements on abstract (possibly infinite) sets.
//
// Model: a registry is a sequence of traits (a trait id is its index), a trait implies a set of ids and has a floor
// Profile, the closure is `Fuel` rounds of one-step implication (Fuel = 8 = the maximum implication depth the registry
// loader accepts, so for every loadable registry this IS the full transitive closure), the floor of a trait set is the
// join of the floors of its closure, and the effective profile of a def is its declared profile joined with that floor.
module TraitExpand {

  // ---- T1: the profile lattice -------------------------------------------------------------------------------------------

  datatype Profile = P(risk: nat, rev: nat, blast: nat, esc: nat, cav: set<nat>, ctx: set<nat>, pr: set<nat>)

  function Max(a: nat, b: nat): nat { if a >= b then a else b }

  function Join(p: Profile, q: Profile): Profile {
    P(Max(p.risk, q.risk), Max(p.rev, q.rev), Max(p.blast, q.blast), Max(p.esc, q.esc), p.cav + q.cav, p.ctx + q.ctx, p.pr + q.pr)
  }

  const Bot: Profile := P(0, 0, 0, 0, {}, {}, {})

  predicate Leq(p: Profile, q: Profile) {
    p.risk <= q.risk && p.rev <= q.rev && p.blast <= q.blast && p.esc <= q.esc && p.cav <= q.cav && p.ctx <= q.ctx && p.pr <= q.pr
  }

  lemma LeqRefl(p: Profile) ensures Leq(p, p) {}
  lemma LeqTrans(p: Profile, q: Profile, r: Profile) requires Leq(p, q) && Leq(q, r) ensures Leq(p, r) {}
  lemma LeqAntisym(p: Profile, q: Profile) requires Leq(p, q) && Leq(q, p) ensures p == q {}
  lemma BotLeq(p: Profile) ensures Leq(Bot, p) {}
  lemma LeqJoinLeft(p: Profile, q: Profile) ensures Leq(p, Join(p, q)) {}
  lemma LeqJoinRight(p: Profile, q: Profile) ensures Leq(q, Join(p, q)) {}
  lemma JoinLub(p: Profile, q: Profile, r: Profile) requires Leq(p, r) && Leq(q, r) ensures Leq(Join(p, q), r) {}
  lemma JoinComm(p: Profile, q: Profile) ensures Join(p, q) == Join(q, p) {}
  lemma JoinAssoc(p: Profile, q: Profile, r: Profile) ensures Join(Join(p, q), r) == Join(p, Join(q, r)) {}
  lemma JoinIdem(p: Profile) ensures Join(p, p) == p {}
  lemma JoinBot(p: Profile) ensures Join(p, Bot) == p {}
  lemma JoinMono(p: Profile, p2: Profile, q: Profile, q2: Profile)
    requires Leq(p, p2) && Leq(q, q2)
    ensures Leq(Join(p, q), Join(p2, q2))
  {}

  // Finite height: a strictly increasing step strictly increases the height measure, so every chain is finite.
  function Height(p: Profile): nat { p.risk + p.rev + p.blast + p.esc + |p.cav| + |p.ctx| + |p.pr| }

  lemma SubsetCard(a: set<nat>, b: set<nat>)
    requires a <= b
    ensures |a| <= |b|
    decreases |a|
  {
    if a != {} {
      var x :| x in a;
      assert a == (a - {x}) + {x};
      assert x !in a - {x};
      assert b == (b - {x}) + {x};
      assert x !in b - {x};
      SubsetCard(a - {x}, b - {x});
    }
  }

  lemma StrictCard(a: set<nat>, b: set<nat>)
    requires a <= b && a != b
    ensures |a| < |b|
  {
    var y :| y in b && y !in a;
    SubsetCard(a, b - {y});
    assert b == (b - {y}) + {y};
    assert y !in b - {y};
  }

  lemma HeightStrict(p: Profile, q: Profile)
    requires Leq(p, q) && p != q
    ensures Height(p) < Height(q)
  {
    SubsetCard(p.cav, q.cav);
    SubsetCard(p.ctx, q.ctx);
    SubsetCard(p.pr, q.pr);
    if p.cav != q.cav {
      StrictCard(p.cav, q.cav);
    } else if p.ctx != q.ctx {
      StrictCard(p.ctx, q.ctx);
    } else if p.pr != q.pr {
      StrictCard(p.pr, q.pr);
    } else {
      assert p.risk < q.risk || p.rev < q.rev || p.blast < q.blast || p.esc < q.esc;
    }
  }

  // ---- registry, closure, floors -------------------------------------------------------------------------------------------

  datatype Trait = Trait(implies: set<nat>, floor: Profile)

  const Fuel: nat := 8

  function ImpliedAll(reg: seq<Trait>, s: set<nat>, i: nat): set<nat>
    requires i <= |reg|
    decreases |reg| - i
  {
    if i == |reg| then {} else (if i in s then reg[i].implies else {}) + ImpliedAll(reg, s, i + 1)
  }

  function Step(reg: seq<Trait>, s: set<nat>): set<nat> { s + ImpliedAll(reg, s, 0) }

  function Iter(reg: seq<Trait>, s: set<nat>, k: nat): set<nat>
    decreases k
  {
    if k == 0 then s else Iter(reg, Step(reg, s), k - 1)
  }

  function Closure(reg: seq<Trait>, s: set<nat>): set<nat> { Iter(reg, s, Fuel) }

  lemma ImpliedAllMono(reg: seq<Trait>, s: set<nat>, s2: set<nat>, i: nat)
    requires i <= |reg| && s <= s2
    ensures ImpliedAll(reg, s, i) <= ImpliedAll(reg, s2, i)
    decreases |reg| - i
  {
    if i < |reg| {
      ImpliedAllMono(reg, s, s2, i + 1);
    }
  }

  lemma StepMono(reg: seq<Trait>, s: set<nat>, s2: set<nat>)
    requires s <= s2
    ensures Step(reg, s) <= Step(reg, s2)
  {
    ImpliedAllMono(reg, s, s2, 0);
  }

  lemma IterMono(reg: seq<Trait>, s: set<nat>, s2: set<nat>, k: nat)
    requires s <= s2
    ensures Iter(reg, s, k) <= Iter(reg, s2, k)
    decreases k
  {
    if k > 0 {
      StepMono(reg, s, s2);
      IterMono(reg, Step(reg, s), Step(reg, s2), k - 1);
    }
  }

  lemma IterExtensive(reg: seq<Trait>, s: set<nat>, k: nat)
    ensures s <= Iter(reg, s, k)
    decreases k
  {
    if k > 0 {
      IterExtensive(reg, Step(reg, s), k - 1);
    }
  }

  lemma ClosureMono(reg: seq<Trait>, s: set<nat>, s2: set<nat>)
    requires s <= s2
    ensures Closure(reg, s) <= Closure(reg, s2)
  {
    IterMono(reg, s, s2, Fuel);
  }

  lemma ClosureExtensive(reg: seq<Trait>, s: set<nat>)
    ensures s <= Closure(reg, s)
  {
    IterExtensive(reg, s, Fuel);
  }

  /// The join of the floors of the traits of `c` that lie at index >= i.
  function JoinFloors(reg: seq<Trait>, c: set<nat>, i: nat): Profile
    requires i <= |reg|
    decreases |reg| - i
  {
    if i == |reg| then Bot
    else if i in c then Join(reg[i].floor, JoinFloors(reg, c, i + 1))
    else JoinFloors(reg, c, i + 1)
  }

  /// F_R(S): the floor of a trait set is the join of the floors of its closure.
  function FloorOf(reg: seq<Trait>, s: set<nat>): Profile { JoinFloors(reg, Closure(reg, s), 0) }

  lemma JoinFloorsHas(reg: seq<Trait>, c: set<nat>, i: nat, t: nat)
    requires i <= t < |reg| && t in c
    ensures Leq(reg[t].floor, JoinFloors(reg, c, i))
    decreases |reg| - i
  {
    if i == t {
      LeqJoinLeft(reg[t].floor, JoinFloors(reg, c, i + 1));
    } else {
      JoinFloorsHas(reg, c, i + 1, t);
      if i in c {
        LeqJoinRight(reg[i].floor, JoinFloors(reg, c, i + 1));
        LeqTrans(reg[t].floor, JoinFloors(reg, c, i + 1), JoinFloors(reg, c, i));
      }
    }
  }

  lemma JoinFloorsLeast(reg: seq<Trait>, c: set<nat>, i: nat, q: Profile)
    requires i <= |reg|
    requires forall t :: i <= t < |reg| && t in c ==> Leq(reg[t].floor, q)
    ensures Leq(JoinFloors(reg, c, i), q)
    decreases |reg| - i
  {
    if i < |reg| {
      JoinFloorsLeast(reg, c, i + 1, q);
      if i in c {
        JoinLub(reg[i].floor, JoinFloors(reg, c, i + 1), q);
      }
    } else {
      BotLeq(q);
    }
  }

  /// T2 (traits only add): S <= S2 implies F(S) <= F(S2).
  lemma FloorOfMono(reg: seq<Trait>, s: set<nat>, s2: set<nat>)
    requires s <= s2
    ensures Leq(FloorOf(reg, s), FloorOf(reg, s2))
  {
    ClosureMono(reg, s, s2);
    var c := Closure(reg, s);
    var c2 := Closure(reg, s2);
    forall t | 0 <= t < |reg| && t in c
      ensures Leq(reg[t].floor, JoinFloors(reg, c2, 0))
    {
      JoinFloorsHas(reg, c2, 0, t);
    }
    JoinFloorsLeast(reg, c, 0, JoinFloors(reg, c2, 0));
  }

  // ---- defs, effective profile, T2 / T3 --------------------------------------------------------------------------------------

  datatype Def = Def(decl: Profile, traits: set<nat>)

  /// eff_R(d) = decl(d) join F_R(T(d)).
  function Eff(reg: seq<Trait>, d: Def): Profile { Join(d.decl, FloorOf(reg, d.traits)) }

  function AddTrait(d: Def, t: nat): Def { Def(d.decl, d.traits + {t}) }

  lemma T2AddTrait(reg: seq<Trait>, d: Def, t: nat)
    ensures Leq(Eff(reg, d), Eff(reg, AddTrait(d, t)))
  {
    FloorOfMono(reg, d.traits, d.traits + {t});
    LeqRefl(d.decl);
    JoinMono(d.decl, d.decl, FloorOf(reg, d.traits), FloorOf(reg, d.traits + {t}));
  }

  /// T2 for many traits at once.
  lemma T2Superset(reg: seq<Trait>, d: Def, extra: set<nat>)
    ensures Leq(Eff(reg, d), Eff(reg, Def(d.decl, d.traits + extra)))
  {
    FloorOfMono(reg, d.traits, d.traits + extra);
    LeqRefl(d.decl);
    JoinMono(d.decl, d.decl, FloorOf(reg, d.traits), FloorOf(reg, d.traits + extra));
  }

  /// T3 (inheritance): every trait in the closure contributes its floor to eff(d).
  lemma T3Inherit(reg: seq<Trait>, d: Def, t: nat)
    requires t < |reg| && t in Closure(reg, d.traits)
    ensures Leq(reg[t].floor, Eff(reg, d))
  {
    JoinFloorsHas(reg, Closure(reg, d.traits), 0, t);
    LeqJoinRight(d.decl, FloorOf(reg, d.traits));
    LeqTrans(reg[t].floor, FloorOf(reg, d.traits), Eff(reg, d));
  }

  /// T3 corollary: tagging any def with t gives it t's floor.
  lemma T3Tagged(reg: seq<Trait>, d: Def, t: nat)
    requires t < |reg|
    ensures Leq(reg[t].floor, Eff(reg, AddTrait(d, t)))
  {
    ClosureExtensive(reg, d.traits + {t});
    T3Inherit(reg, AddTrait(d, t), t);
  }

  /// The declared profile is clamped, never honoured below a floor.
  lemma T3Decl(reg: seq<Trait>, d: Def)
    ensures Leq(d.decl, Eff(reg, d))
  {
    LeqJoinLeft(d.decl, FloorOf(reg, d.traits));
  }

  /// T5 (custom trait soundness, the part that is pure order theory): a registry that accepts a custom trait (its floor is
  /// at least the floor of everything it implies) can never produce a profile below the core one, because adding traits
  /// only adds (T2). The extension-invariance statement over arbitrary registries is TraitAlg.T5_core_preserved in Lean.
  predicate Accepts(reg: seq<Trait>) {
    forall t :: 0 <= t < |reg| ==> forall u :: u in reg[t].implies && 0 <= u < |reg| ==> Leq(reg[u].floor, reg[t].floor)
  }

  lemma T5NoLowering(reg: seq<Trait>, core: set<nat>, custom: set<nat>)
    ensures Leq(FloorOf(reg, core), FloorOf(reg, core + custom))
  {
    FloorOfMono(reg, core, core + custom);
  }

  // ---- T4: the floor decision is antitone -----------------------------------------------------------------------------------------

  datatype Grant = G(cav: set<nat>, maxEsc: nat, pre: nat)

  /// 0 = deny, 1 = escalate, 2 = allow.
  function FD(g: Grant, call: set<nat>, p: Profile): nat {
    if g.maxEsc < p.esc then 0
    else if p.cav <= g.cav && p.ctx <= call && p.esc <= g.pre then 2
    else 1
  }

  function Min(a: nat, b: nat): nat { if a <= b then a else b }

  lemma FDAntitone(g: Grant, call: set<nat>, p: Profile, q: Profile)
    requires Leq(p, q)
    ensures FD(g, call, q) <= FD(g, call, p)
  {}

  /// The final decision is the meet of the policy decision and the floor decision.
  lemma DecAntitone(g: Grant, call: set<nat>, pol: nat, p: Profile, q: Profile)
    requires Leq(p, q)
    ensures Min(pol, FD(g, call, q)) <= Min(pol, FD(g, call, p))
  {
    FDAntitone(g, call, p, q);
  }

  /// T4 end to end: tagging a def with another trait never raises the decision.
  lemma T4Tagging(reg: seq<Trait>, d: Def, t: nat, g: Grant, call: set<nat>, pol: nat)
    ensures Min(pol, FD(g, call, Eff(reg, AddTrait(d, t)))) <= Min(pol, FD(g, call, Eff(reg, d)))
  {
    T2AddTrait(reg, d, t);
    DecAntitone(g, call, pol, Eff(reg, d), Eff(reg, AddTrait(d, t)));
  }

  // ---- T7: selectors --------------------------------------------------------------------------------------------------------------

  datatype Sel = Trt(t: nat) | AllOf(ts: set<nat>) | AnyOf(ts: set<nat>) | Conj(a: Sel, b: Sel) | Neg(a: Sel)

  predicate Holds(s: Sel, tr: set<nat>) {
    match s
    case Trt(t) => t in tr
    case AllOf(ts) => ts <= tr
    case AnyOf(ts) => ts * tr != {}
    case Conj(a, b) => Holds(a, tr) && Holds(b, tr)
    case Neg(a) => !Holds(a, tr)
  }

  predicate Positive(s: Sel) {
    match s
    case Neg(_) => false
    case Conj(a, b) => Positive(a) && Positive(b)
    case _ => true
  }

  /// T7: a positive selector stays matched when traits are added.
  lemma HoldsMono(s: Sel, tr: set<nat>, tr2: set<nat>)
    requires Positive(s) && tr <= tr2 && Holds(s, tr)
    ensures Holds(s, tr2)
  {
    match s {
      case Trt(t) =>
      case AllOf(ts) =>
      case AnyOf(ts) =>
      case Conj(a, b) =>
        HoldsMono(a, tr, tr2);
        HoldsMono(b, tr, tr2);
      case Neg(a) =>
    }
  }

  /// A negated selector is not monotone: tagging can switch it off (why allow selectors forbid negation).
  lemma NegNotMono()
    ensures Holds(Neg(Trt(0)), {}) && !Holds(Neg(Trt(0)), {0}) && ({} <= {0})
  {}

  // ---- T6: registry growth ---------------------------------------------------------------------------------------------------------

  datatype Pol = Pol(pinned: set<nat>, allow: seq<Sel>, prohibit: seq<Sel>)

  predicate AnyHolds(ss: seq<Sel>, tr: set<nat>) {
    exists i :: 0 <= i < |ss| && Holds(ss[i], tr)
  }

  /// Policy decision for an action (verb v, trait closure tr): 0 deny, 1 escalate, 2 allow.
  function PDec(p: Pol, escalateNew: bool, v: nat, tr: set<nat>): nat {
    if AnyHolds(p.prohibit, tr) then 0
    else if v !in p.pinned then (if escalateNew then 1 else 0)
    else if AnyHolds(p.allow, tr) then 2
    else 0
  }

  /// (b) an action outside the pinned pack is never allowed.
  lemma NewActionNotAllowed(p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    requires v !in p.pinned
    ensures PDec(p, escalateNew, v, tr) != 2
  {}

  /// (a') a matching prohibit selector always denies.
  lemma ProhibitDenies(p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    requires AnyHolds(p.prohibit, tr)
    ensures PDec(p, escalateNew, v, tr) == 0
  {}

  /// (a) the set of actions a prohibit predicate covers only grows when the registry (the set of actions) grows.
  lemma CoverGrows(acts: set<nat>, acts2: set<nat>, covered: nat -> bool)
    requires acts <= acts2
    ensures (set a | a in acts && covered(a)) <= (set a | a in acts2 && covered(a))
  {}

  /// (c) the decision of an action depends only on the policy, the verb and its own trait closure, so it is unchanged when
  /// other actions are added to the registry and the action's trait closure is unchanged (T5 gives the latter for extensions).
  lemma DecisionIsLocal(p: Pol, escalateNew: bool, v: nat, tr: set<nat>, tr2: set<nat>)
    requires tr == tr2
    ensures PDec(p, escalateNew, v, tr) == PDec(p, escalateNew, v, tr2)
  {}

  // ---- UNCONFIRMED MEANS MAXIMALLY DANGEROUS ---------------------------------------------------------------------------------
  // A def has a confirmation status. Without a valid human confirmation (a signed review attestation by a pinned reviewer key
  // over the def digest and the registry digest - checked outside this model, by the verifier) its EFFECTIVE trait set is the TOP
  // of the registry: every trait. Machine-authored traits (declared by an importer, inferred by a pack, a suggestion rule, a union
  // or a model) are `machine`: metadata only. Only a signed confirmation sets the effective set, to `signed` (the traits the
  // reviewer signed, plus those the signed def's own facts imply). Everything is on the same executable sets as T1 .. T7.

  /// Top(R): every trait of the registry.
  function Top(reg: seq<Trait>): set<nat> { set i: nat | i < |reg| :: i }

  datatype RDef = RDef(decl: Profile, machine: set<nat>, confirmed: bool, signed: set<nat>)

  /// The effective trait set: the signed set when confirmed, the TOP otherwise. `machine` is never read.
  function EffTraits(reg: seq<Trait>, d: RDef): set<nat> { if d.confirmed then d.signed else Top(reg) }

  /// The effective profile of a def with a confirmation status.
  function REff(reg: seq<Trait>, d: RDef): Profile { Join(d.decl, FloorOf(reg, EffTraits(reg, d))) }

  /// (1) unconfirmed => the effective trait set is the top element.
  lemma UnconfirmedIsTop(reg: seq<Trait>, d: RDef)
    requires !d.confirmed
    ensures EffTraits(reg, d) == Top(reg)
  {}

  /// (2) no machine-only input can lower (or change) the effective profile of an unconfirmed def: whatever the machine traits and
  /// whatever `signed` holds (it means nothing without a confirmation), the profile is the one of the top.
  lemma NoMachineInputLowers(reg: seq<Trait>, d: RDef, machine2: set<nat>, signed2: set<nat>)
    requires !d.confirmed
    ensures REff(reg, RDef(d.decl, machine2, false, signed2)) == REff(reg, d)
    ensures REff(reg, d) == Join(d.decl, FloorOf(reg, Top(reg)))
  {}

  /// Every trait of the registry contributes its floor to the effective profile of an unconfirmed def (T3 for the top).
  lemma UnconfirmedInherits(reg: seq<Trait>, d: RDef, t: nat)
    requires !d.confirmed && t < |reg|
    ensures Leq(reg[t].floor, REff(reg, d))
  {
    ClosureExtensive(reg, Top(reg));
    assert t in Top(reg);
    T3Inherit(reg, Def(d.decl, Top(reg)), t);
  }

  /// A confirmed version of a def: the same declaration, any machine traits, any signed set drawn from the registry.
  predicate ConfirmedVersion(reg: seq<Trait>, d: RDef, c: RDef) {
    !d.confirmed && c.confirmed && c.decl == d.decl && c.signed <= Top(reg)
  }

  /// (3a) the unconfirmed profile is at least the profile of EVERY confirmed version of the def.
  lemma UnconfirmedAboveEveryConfirmed(reg: seq<Trait>, d: RDef, c: RDef)
    requires ConfirmedVersion(reg, d, c)
    ensures Leq(REff(reg, c), REff(reg, d))
  {
    FloorOfMono(reg, c.signed, Top(reg));
    LeqRefl(d.decl);
    JoinMono(d.decl, d.decl, FloorOf(reg, c.signed), FloorOf(reg, Top(reg)));
  }

  /// (3b) the floor decision for an unconfirmed def is at most the one for any confirmed version.
  lemma UnconfirmedFloorDecisionAntitone(reg: seq<Trait>, d: RDef, c: RDef, g: Grant, call: set<nat>)
    requires ConfirmedVersion(reg, d, c)
    ensures FD(g, call, REff(reg, d)) <= FD(g, call, REff(reg, c))
  {
    UnconfirmedAboveEveryConfirmed(reg, d, c);
    FDAntitone(g, call, REff(reg, c), REff(reg, d));
  }

  /// Policy decision with confirmation status. Prohibit (forbid / cap) selectors match an unconfirmed def whatever they say; allow
  /// selectors never match one. For a confirmed def it is PDec.
  function PDecC(p: Pol, escalateNew: bool, v: nat, tr: set<nat>, confirmed: bool): nat {
    if confirmed then PDec(p, escalateNew, v, tr)
    else if |p.prohibit| > 0 then 0
    else if v !in p.pinned then (if escalateNew then 1 else 0)
    else 0
  }

  /// An allow selector never admits an unconfirmed def.
  lemma UnconfirmedNeverAllowed(p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    ensures PDecC(p, escalateNew, v, tr, false) != 2
  {}

  /// A forbid / cap selector denies an unconfirmed def, whatever its content (a carve-out or a classifier miss cannot exempt it).
  lemma ProhibitCoversUnconfirmed(p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    requires |p.prohibit| > 0
    ensures PDecC(p, escalateNew, v, tr, false) == 0
  {}

  /// (3c) the policy decision for an unconfirmed def is at most the one for the same action once confirmed (any trait closure).
  lemma UnconfirmedPolicyAntitone(p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    ensures PDecC(p, escalateNew, v, tr, false) <= PDecC(p, escalateNew, v, tr, true)
  {
    if |p.prohibit| == 0 {
      assert !AnyHolds(p.prohibit, tr);
    }
  }

  /// (3) END TO END: the final decision (meet of the policy decision and the floor decision) for an unconfirmed def is at most the
  /// one for any confirmed version of it. Unconfirmed can only be treated the same or stricter, never looser.
  lemma UnconfirmedFinalAntitone(reg: seq<Trait>, d: RDef, c: RDef, g: Grant, call: set<nat>, p: Pol, escalateNew: bool, v: nat, tr: set<nat>)
    requires ConfirmedVersion(reg, d, c)
    ensures Min(PDecC(p, escalateNew, v, tr, false), FD(g, call, REff(reg, d))) <= Min(PDecC(p, escalateNew, v, tr, true), FD(g, call, REff(reg, c)))
  {
    UnconfirmedPolicyAntitone(p, escalateNew, v, tr);
    UnconfirmedFloorDecisionAntitone(reg, d, c, g, call);
  }

  /// Confirmation is the only way down, and it goes down to exactly the signed set: a confirmed def's profile is the one of its
  /// signed traits (so a reviewer's dismissal, being absence from `signed`, is honoured and nothing else lowers it).
  lemma ConfirmedIsSigned(reg: seq<Trait>, d: RDef)
    requires d.confirmed
    ensures EffTraits(reg, d) == d.signed
    ensures REff(reg, d) == Eff(reg, Def(d.decl, d.signed))
  {}

  /// Revoking a confirmation (a changed def digest or registry digest makes the attestation stale) never lowers the profile.
  lemma StaleNeverLowers(reg: seq<Trait>, c: RDef)
    requires c.confirmed && c.signed <= Top(reg)
    ensures Leq(REff(reg, c), REff(reg, RDef(c.decl, c.machine, false, c.signed)))
  {
    UnconfirmedAboveEveryConfirmed(reg, RDef(c.decl, c.machine, false, c.signed), c);
  }

  // ---- the confirmation applies only to the facts the reviewer saw ----------------------------------------------------------------
  // The reviewer signs the digest of the schema verb's facts next to the def digest. The verifier recomputes the digest of the facts
  // it is PRESENTED with; a mismatch (a fact edited after confirmation, or the digest of another definition claimed) means unconfirmed.

  datatype FDef = FDef(base: RDef, signedFacts: nat, presentedFacts: nat)

  /// Confirmed only if the confirmation is valid AND it signs exactly the presented facts.
  function FConfirmed(f: FDef): bool { f.base.confirmed && f.signedFacts == f.presentedFacts }

  function WithStatus(f: FDef): RDef { RDef(f.base.decl, f.base.machine, FConfirmed(f), f.base.signed) }

  /// A mismatch between the presented facts and the confirmed facts gives the top, whatever the signature says.
  lemma FactsMismatchIsTop(reg: seq<Trait>, f: FDef)
    requires f.signedFacts != f.presentedFacts
    ensures !FConfirmed(f)
    ensures EffTraits(reg, WithStatus(f)) == Top(reg)
  {}

  /// When the facts match, the status is exactly the validity of the confirmation.
  lemma FactsMatchKeepsStatus(f: FDef)
    requires f.signedFacts == f.presentedFacts
    ensures FConfirmed(f) == f.base.confirmed
  {}

  /// Editing the facts of a confirmed def can only raise its effective profile (to the top).
  lemma FactsEditNeverLowers(reg: seq<Trait>, f: FDef)
    requires f.base.confirmed && f.base.signed <= Top(reg) && f.signedFacts != f.presentedFacts
    ensures Leq(REff(reg, f.base), REff(reg, WithStatus(f)))
  {
    UnconfirmedAboveEveryConfirmed(reg, WithStatus(f), f.base);
  }
}
