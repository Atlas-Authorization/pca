(* PcaPrg.ec -- Lemma GG-1 of docs/pca/security/proofs/04-ratchet.md: the length-doubling generator
   G(s) = (F_s(c0), F_s(c1)), c0 <> c1, is a PRG with
        Adv^prg_G(D)  <=  Adv^prf_F(B(D))        where B(D) makes exactly 2 oracle queries.
   Proved as two program equivalences (real PRG = real PRF game of B; ideal PRG = ideal PRF game of B),
   so the bound is an EQUALITY of advantages. *)
require import AllCore Distr FMap.

type key.
type inp.
type out.
op dk : key distr.
op dout : out distr.
op F : key -> inp -> out.
op c0 : inp.
op c1 : inp.
axiom c01 : c0 <> c1.
axiom dout_ll : is_lossless dout.
axiom dk_ll : is_lossless dk.

module type PRGDist = { proc dist(y0 : out, y1 : out) : bool }.

module PRGReal (D : PRGDist) = {
  proc main() : bool = {
    var k : key; var y0 : out; var y1 : out; var b : bool;
    k <$ dk;
    y0 <- F k c0;
    y1 <- F k c1;
    b <@ D.dist(y0, y1);
    return b;
  }
}.

module PRGIdeal (D : PRGDist) = {
  proc main() : bool = {
    var y0 : out; var y1 : out; var b : bool;
    y0 <$ dout;
    y1 <$ dout;
    b <@ D.dist(y0, y1);
    return b;
  }
}.

module type Orcl = { proc f(x : inp) : out }.
module type PRFDist (O : Orcl) = { proc dist() : bool { O.f } }.

module OReal : Orcl = {
  var k : key
  proc f(x : inp) : out = { return F k x; }
}.

module OIdeal : Orcl = {
  var m : (inp, out) fmap
  proc f(x : inp) : out = {
    var y : out;
    if (x \notin m) {
      y <$ dout;
      m.[x] <- y;
    }
    return oget m.[x];
  }
}.

module PRFReal (A : PRFDist) = {
  proc main() : bool = {
    var b : bool;
    OReal.k <$ dk;
    b <@ A(OReal).dist();
    return b;
  }
}.

module PRFIdeal (A : PRFDist) = {
  proc main() : bool = {
    var b : bool;
    OIdeal.m <- empty;
    b <@ A(OIdeal).dist();
    return b;
  }
}.

module B (D : PRGDist) (O : Orcl) = {
  proc dist() : bool = {
    var y0 : out; var y1 : out; var b : bool;
    y0 <@ O.f(c0);
    y1 <@ O.f(c1);
    b <@ D.dist(y0, y1);
    return b;
  }
}.

section.
declare module D <: PRGDist {-OReal, -OIdeal}.

lemma real_eq &m : Pr[PRGReal(D).main() @ &m : res] = Pr[PRFReal(B(D)).main() @ &m : res].
proof.
byequiv (_ : ={glob D} ==> ={res}) => //.
proc; inline *.
by wp; call (_ : true); wp; rnd; skip => />.
qed.

lemma ideal_eq &m : Pr[PRGIdeal(D).main() @ &m : res] = Pr[PRFIdeal(B(D)).main() @ &m : res].
proof.
byequiv (_ : ={glob D} ==> ={res}) => //.
proc; inline *.
wp.
call (_ : true).
wp.
rcondt{2} 3; first by auto => />; smt(mem_empty).
rcondt{2} 7; first by auto => />; smt(mem_set mem_empty c01).
wp; rnd; wp; rnd; wp; skip => />; smt(get_setE mem_set c01).
qed.

lemma prg_le_prf &m :
  `| Pr[PRGReal(D).main() @ &m : res] - Pr[PRGIdeal(D).main() @ &m : res] |
  = `| Pr[PRFReal(B(D)).main() @ &m : res] - Pr[PRFIdeal(B(D)).main() @ &m : res] |.
proof. by rewrite (real_eq &m) (ideal_eq &m). qed.
end section.
