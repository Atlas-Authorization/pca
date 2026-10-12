(* Sig.ec -- abstract (stateless, possibly randomised) signature scheme and its
   unforgeability games.  Used for Ed25519 (deterministic: dsig is a point mass),
   and, for the hybrid combiner, for any second component.

   A scheme is the triple (dkey, dsig, ver):
     dkey : key-pair distribution,
     dsig : sk -> msg -> sg distr   (signing, a distribution so that randomised
                                     schemes are covered; deterministic = point mass),
     ver  : pk -> msg -> sg -> bool (deterministic verification predicate; for
                                     Ed25519 this is the strict predicate Ver-star).
   Nothing about correctness is assumed: unforgeability does not need it. *)
require import AllCore List Distr.

abstract theory Scheme.

type pk.
type sk.
type msg.
type sg.

op dkey : (pk * sk) distr.
op dsig : sk -> msg -> sg distr.
op ver  : pk -> msg -> sg -> bool.

axiom dkey_ll : is_lossless dkey.
axiom dsig_ll : forall sk m, is_lossless (dsig sk m).

module type Orcl = {
  proc sign(m : msg) : sg
}.

module type Forger(O : Orcl) = {
  proc forge(pk : pk) : msg * sg {O.sign}
}.

(* EUF-CMA: the forged message was never submitted to the signing oracle. *)
module EUF(F : Forger) = {
  var sk : sk
  var qm : msg list

  module O : Orcl = {
    proc sign(m : msg) : sg = {
      var s : sg;
      s <$ dsig sk m;
      qm <- m :: qm;
      return s;
    }
  }

  proc main() : bool = {
    var k : pk * sk;
    var m : msg;
    var s : sg;
    k <$ dkey;
    sk <- k.`2;
    qm <- [];
    (m, s) <@ F(O).forge(k.`1);
    return ver k.`1 m s /\ !(m \in qm);
  }
}.

(* SUF-CMA: the forged (message, signature) pair was never returned by the oracle. *)
module SUF(F : Forger) = {
  var sk : sk
  var qs : (msg * sg) list

  module O : Orcl = {
    proc sign(m : msg) : sg = {
      var s : sg;
      s <$ dsig sk m;
      qs <- (m, s) :: qs;
      return s;
    }
  }

  proc main() : bool = {
    var k : pk * sk;
    var m : msg;
    var s : sg;
    k <$ dkey;
    sk <- k.`2;
    qs <- [];
    (m, s) <@ F(O).forge(k.`1);
    return ver k.`1 m s /\ !((m, s) \in qs);
  }
}.

(* SUF-CMA implies EUF-CMA: the same forger, same advantage up to the (trivial)
   containment  m in dom(qs)  =>  (m,s) in qs fails, i.e. EUF-win => SUF-win. *)
section.
declare module F <: Forger {-EUF, -SUF}.

lemma euf_le_suf &m :
  Pr[EUF(F).main() @ &m : res] <= Pr[SUF(F).main() @ &m : res].
proof.
byequiv (_ : ={glob F} ==> res{1} => res{2}) => //.
proc.
inline *.
wp.
call (_ : EUF.sk{1} = SUF.sk{2} /\ (forall m s, (m, s) \in SUF.qs{2} => m \in EUF.qm{1})).
+ proc; inline *; auto => /> *; smt().
auto => /> *; smt().
qed.
end section.

end Scheme.
