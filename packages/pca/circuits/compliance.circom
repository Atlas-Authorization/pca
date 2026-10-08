pragma circom 2.1.6;

// ---------------------------------------------------------------------------
// PCA §9B — zero-knowledge proof-of-compliance circuit (Groth16 / BN254).
//
// The agent proves to the Resource Server "action A is a valid release under
// policy P over committed plan Π" WITHOUT revealing P, Π, or its reasoning.
//
// WHAT THIS CIRCUIT PROVES (in zero-knowledge over the private witness):
//   1. Commitment OPENINGS — the prover knows attribute preimages opening three
//      Poseidon commitments it publishes as outputs:
//        policyCommit = Poseidon(verb, resource, policySalt)
//        planCommit   = Poseidon(planVerb, planSalt)
//        actionCommit = Poseidon(verb, resource, actionSalt)
//      The verb/resource are SHARED between the policy opening and the action
//      opening, so the proof establishes "the policy's permitted (verb,resource)
//      is exactly the action's (verb,resource)" without revealing either.
//   2. The DECISION (a well-defined sub-statement of the Policy VM in policy-vm.ts):
//        (a) action verb == the committed plan node's verb  (plan membership)
//        (b) risk <= budget                                 (within risk budget)
//      => allow = (a) AND (b); the circuit asserts allow == 1. A deny witness
//         (verb mismatch or risk > budget) makes `allow === 1` UNSATISFIABLE, so
//         a false statement is unprovable (you cannot forge an allow).
//   3. BINDING — shaPolicy/shaPlan/shaAction are public inputs carrying the field
//      encodings of the RS's sha256 commitments (policy/plan/action). Groth16
//      binds the proof to these exact public values, so a proof minted for one
//      (policy, plan, action) is cryptographically rejected when a verifier
//      checks it against a different commitment set (replay/transplant binding).
//
// WHAT THIS CIRCUIT DOES **NOT** YET ENFORCE (documented, honest scope):
//   - It does not recompute the RS's sha256(canonical(P|Π|A)) commitments IN
//     CIRCUIT from the full canonical-JSON preimages (a sha256-over-variable-
//     length-JSON circuit is out of scope for a one-shot). The ZK openings use a
//     ZK-friendly Poseidon commitment; the correspondence between those openings
//     and the RS's sha256 commitments is established by the honest prover (which
//     derives both from the same data). Consequently the private (verb,resource,
//     risk,budget) are NOT proven to be the literal sha256 preimages — a full
//     version closes this with sha256-in-circuit.
//   - The decision is a SUBSET of the full Policy VM: it enforces plan-membership
//     of the action verb and risk<=budget. It does not yet encode the complete
//     predicate / caveat / prohibition / attenuation-chain logic of policy-vm.ts.
// ---------------------------------------------------------------------------

include "poseidon.circom";
include "comparators.circom";

template Compliance() {
    // ---- private witness (hidden from the Resource Server) ----
    signal input verb;        // the action/policy verb code
    signal input resource;    // the action/policy resource code
    signal input planVerb;    // the committed plan node's verb code
    signal input policySalt;  // blinding for the policy commitment
    signal input planSalt;    // blinding for the plan commitment
    signal input actionSalt;  // blinding for the action commitment
    signal input risk;        // the Policy VM's computed risk (integer scale)
    signal input budget;      // the committed risk budget (integer scale)

    // ---- public inputs ----
    signal input shaPolicy;   // field(sha256 policy commitment) — binds to the RS's policy commitment
    signal input shaPlan;     // field(sha256 plan commitment)
    signal input shaAction;   // field(sha256 action commitment)
    signal input allow;       // asserted == 1 (the released-allow bit)

    // ---- public outputs: the ZK-friendly commitments the circuit opens ----
    signal output policyCommit;
    signal output planCommit;
    signal output actionCommit;

    // (1) commitment openings — prove knowledge of the attribute preimages.
    component pc = Poseidon(3);
    pc.inputs[0] <== verb;
    pc.inputs[1] <== resource;
    pc.inputs[2] <== policySalt;
    policyCommit <== pc.out;

    component plc = Poseidon(2);
    plc.inputs[0] <== planVerb;
    plc.inputs[1] <== planSalt;
    planCommit <== plc.out;

    component ac = Poseidon(3);
    ac.inputs[0] <== verb;
    ac.inputs[1] <== resource;
    ac.inputs[2] <== actionSalt;
    actionCommit <== ac.out;

    // (2) decision — a sub-statement of the Policy VM.
    //   (a) the action's verb equals the committed plan node's verb (plan membership)
    component veq = IsEqual();
    veq.in[0] <== verb;
    veq.in[1] <== planVerb;
    //   (b) risk within budget: risk <= budget (both < 2^64)
    component rle = LessEqThan(64);
    rle.in[0] <== risk;
    rle.in[1] <== budget;

    signal computedAllow;
    computedAllow <== veq.out * rle.out; // boolean AND of the two conditions
    allow === computedAllow;             // allow is DERIVED, not free
    allow === 1;                         // and must be release

    // (3) binding — pull the sha256 commitment tags into the constraint system so
    // the prover is committed to them (Groth16 then binds the proof to these exact
    // public values). `allow` is 1 here, so this is a faithful quadratic reference.
    signal bindTag;
    bindTag <== (shaPolicy + shaPlan + shaAction) * allow;
}

// Public signals (snarkjs order = outputs, then public inputs):
//   [0] policyCommit  [1] planCommit  [2] actionCommit
//   [3] shaPolicy     [4] shaPlan     [5] shaAction     [6] allow
component main {public [shaPolicy, shaPlan, shaAction, allow]} = Compliance();
