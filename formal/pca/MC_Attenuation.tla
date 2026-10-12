--------------------------- MODULE MC_Attenuation ---------------------------
(* TLC harness for Attenuation.  Concrete finite bounds live in the .cfg    *)
(* files.  Run the POSITIVE check (invariant should HOLD):                  *)
(*   java -cp tla2tools.jar tlc2.TLC -config MC_Attenuation.cfg MC_Attenuation *)
(* Run the NEGATIVE control (invariant should FAIL with a counterexample):  *)
(*   java -cp tla2tools.jar tlc2.TLC -config MC_Attenuation_widen.cfg MC_Attenuation *)
EXTENDS Attenuation
=============================================================================
