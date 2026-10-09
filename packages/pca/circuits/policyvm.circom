pragma circom 2.1.6;

// ===========================================================================================
// PCA §9B — FULL Policy-VM zero-knowledge proof-of-compliance circuit (Groth16 / BN254).
//
// This is the "full Policy VM" successor to compliance.circom. It closes the two documented gaps of
// that circuit:
//   (A) the three public commitments are computed with sha256 IN-CIRCUIT over a fixed-layout,
//       quantized struct — so the commitment is PROVEN to equal sha256(fields), not prover-asserted
//       via a Poseidon opening whose sha256-correspondence the honest prover merely promised; and
//   (B) the decision encodes the Policy VM (decide / risk.ts / predicates.ts / capability.ts) itself,
//       quantized to fixed-point integers: the risk functional + clamp + monotone floor, the
//       threshold ladder, the predicate (verb/resource allowlist + one numeric `where` bound), the
//       six built-in conjunctive caveats (expires / not_before / max_blast_radius / delegation_depth
//       / reversibility_max / rate) and the attenuation-chain narrowing (budget_alloc monotonicity +
//       depth bound). The released-allow bit is DERIVED from all of these ANDed together, so a deny
//       witness (any check failing) makes `allow === 1` UNSATISFIABLE — you cannot forge an allow.
//
// FIXED-POINT.  Every [0,1] quantity (risk inputs, weights, thresholds, κ, budget) is represented as
// an integer in [0, S] with S = 1_000_000 (6 decimal places). Divisions are proven by the standard
// quotient/remainder decomposition with range checks (no floating point exists in a field).
//
// ------------------------------------------------------------------------------------------------
// FIXED-LAYOUT STRUCTS (big-endian; each field is a 64-bit unsigned integer, serialized as 8 bytes
// MSB-first, concatenated; the JS side in zk.ts serializes identically and sha256s it). The sha256
// digest (256 bits) is exposed as two 128-bit field halves (hi = bits[0..128), lo = bits[128..256)).
//
//   ACTION struct (4 fields = 256 bits = 1 sha256 block after padding -> but 256+65 > 512 so 2 blocks):
//     [0] verb            verb code
//     [1] resource        resource code
//     [2] reversibility   reversibility-class index (0 reversible, 1 rate_limited, 2 irreversible)
//     [3] paramScalar     a numeric action parameter (e.g. an amount) checked by the `where` bound
//
//   PLAN struct (4 fields = 256 bits):
//     [0] planVerb        the committed plan node's verb code (plan membership)
//     [1] planResource    the committed plan node's resource code
//     [2] semanticDist    quantized plan geodesic distance d in [0,S] (also the risk `d` input)
//     [3] planSalt        blinding, so planCommit is hiding
//
//   POLICY struct (20 fields = 1280 bits): the whole quantized policy P that the VM evaluates:
//     [0..6)  wAlpha wBeta wGamma wDelta wEpsilon wZeta   risk weights, scale S
//     [6]  theta1    [7] theta2    threshold ladder, scale S  (require theta1 <= theta2)
//     [8]  kappa     cost scale, scale S
//     [9]  budgetB   committed trust budget B (already leaked to `now`), scale S
//     [10] policyVerb       the permitted verb (predicate allowlist, single entry)
//     [11] policyResource   the permitted resource (predicate allowlist, single entry)
//     [12] policyParamBound upper bound for the numeric `where` condition (paramScalar <= bound)
//     [13] expiresAt        `expires` caveat bound (same time unit as `now`)
//     [14] notBefore        `not_before` caveat bound
//     [15] maxBlast         `max_blast_radius` caveat bound, scale S
//     [16] maxDepth         `delegation_depth` caveat bound
//     [17] revMax           `reversibility_max` caveat bound (class index)
//     [18] rateMax          `rate` caveat bound (max admitted actions in window)
//     [19] allocParent      parent carried budget_alloc (attenuation chain), scale S
//   (allocChild is the action's own carried allocation, a PUBLIC INPUT, checked <= allocParent.)
//
// PUBLIC SIGNALS (snarkjs order = outputs, then declared public inputs):
//   OUTPUTS  [0] actionHi [1] actionLo [2] policyHi [3] policyLo [4] planHi [5] planLo
//            [6] r (computed risk, scale S)  [7] t (threshold 1|2|3)  [8] admit (auto-admit bit)
//   INPUTS   [9] allow (asserted == 1)  [10] now  [11] blast  [12] delegationDepth
//            [13] recentCount  [14] allocChild
//
// ------------------------------------------------------------------------------------------------
// HONEST REMAINING GAP (NOT in-circuit — documented, not hidden):
//   - FIXED LAYOUT, not full canonical JSON. sha256 is over a fixed quantized struct, not the
//     variable-length canonical-JSON that `hashCanonical` in hash.ts produces. Wiring this into the
//     production PCActn flow therefore requires the RS to recompute its commitments in THIS fixed
//     layout (or a separate proof that the JSON projects to it). The circuit proves the commitment is
//     sha256 of the committed FIELDS — it does not prove those fields are the canonical-JSON preimage.
//   - PREDICATES are a single (verb,resource) allowlist entry + one numeric `where` (lte) bound. The
//     full predicate engine — multiple predicates OR'd, verb lists / '*', resource prefix (`/x/*`) &
//     `re:` regex matching, and the full condition DSL (eq/ne/in/nin/prefix/exists over dotted JSON
//     paths) — is NOT encoded.
//   - RISK MAGNITUDE INPUTS (taint, confidence, age, reversibility score, semanticDist) and the
//     context (blast, recentCount) are prover-supplied witnesses; they are NOT independently attested
//     in-circuit. So the derived r / t / admit are only as trustworthy as those inputs. The HARD,
//     unforgeable guarantee is the release gate (predicate AND caveats AND chain); it does not depend
//     on the risk magnitudes.
//   - NO Ed25519 chain-signature verification (verifyChain's per-hop signatures), no plan-geodesic BFS,
//     no rate-window filtering — the attenuation narrowing encoded here is the budget_alloc
//     monotonicity and the depth bound; the signature/structure checks stay in the host verifier.
// ===========================================================================================

include "sha256/sha256.circom";
include "comparators.circom";
include "bitify.circom";
include "gates.circom";

// Serialize a 64-bit field as big-endian (MSB-first) bits, suitable for feeding sha256.
template Field64BE() {
    signal input in;
    signal output bits[64];
    component n2b = Num2Bits(64);
    n2b.in <== in;
    // Num2Bits is little-endian (out[0] = LSB); sha256 wants MSB-first, so reverse.
    for (var i = 0; i < 64; i++) {
        bits[i] <== n2b.out[63 - i];
    }
}

// sha256 over N 64-bit big-endian fields; outputs the digest as hi/lo 128-bit halves.
template Sha256Struct(nFields) {
    signal input fields[nFields];
    signal output hi;
    signal output lo;

    component ser[nFields];
    component h = Sha256(nFields * 64);
    for (var f = 0; f < nFields; f++) {
        ser[f] = Field64BE();
        ser[f].in <== fields[f];
        for (var b = 0; b < 64; b++) {
            h.in[f * 64 + b] <== ser[f].bits[b];
        }
    }
    // Pack the 256-bit digest (MSB-first) into two 128-bit field elements.
    component hiNum = Bits2Num(128);
    component loNum = Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        // Bits2Num is little-endian; digest bit 0 is the MSB. Feed so hi = big-endian value of top 128 bits.
        hiNum.in[i] <== h.out[127 - i];
        loNum.in[i] <== h.out[255 - i];
    }
    hi <== hiNum.out;
    lo <== loNum.out;
}

template PolicyVM() {
    var S = 1000000; // fixed-point scale (1.0)

    // ---------------- private witness: ACTION ----------------
    signal input verb;
    signal input resource;
    signal input reversibility;   // class index 0/1/2
    signal input paramScalar;

    // ---------------- private witness: PLAN ----------------
    signal input planVerb;
    signal input planResource;
    signal input semanticDist;    // d in [0,S]
    signal input planSalt;

    // ---------------- private witness: POLICY ----------------
    signal input wAlpha;
    signal input wBeta;
    signal input wGamma;
    signal input wDelta;
    signal input wEpsilon;
    signal input wZeta;
    signal input theta1;
    signal input theta2;
    signal input kappa;
    signal input budgetB;
    signal input policyVerb;
    signal input policyResource;
    signal input policyParamBound;
    signal input expiresAt;
    signal input notBefore;
    signal input maxBlast;
    signal input maxDepth;
    signal input revMax;
    signal input rateMax;
    signal input allocParent;

    // ---------------- private witness: remaining risk magnitudes ----------------
    signal input revScore;   // reversibility in [0,S] (risk input; 1 = fully reversible)
    signal input taint;      // [0,S]
    signal input conf;       // [0,S]
    signal input age;        // [0,S]
    signal input rFloorIn;   // monotone risk floor in [0,S] (the signed caution)

    // division witnesses (prover-supplied, then proven correct)
    signal input rQ;         // floor(rNum / S)
    signal input rRem;       // rNum - rQ*S
    signal input costQ;      // floor(kappa*rFinal / S)
    signal input costRem;

    // ---------------- public inputs ----------------
    signal input allow;              // asserted == 1
    signal input now;                // decision time (same unit as expiresAt/notBefore)
    signal input blast;              // blast radius in [0,S] (risk input + max_blast caveat)
    signal input delegationDepth;    // chain.length - 1
    signal input recentCount;        // admitted actions in the rate window
    signal input allocChild;         // this hop's carried budget_alloc (<= allocParent)

    // ---------------- public outputs ----------------
    signal output actionHi;
    signal output actionLo;
    signal output policyHi;
    signal output policyLo;
    signal output planHi;
    signal output planLo;
    signal output r;
    signal output t;
    signal output admit;

    // ============================================================
    // (A) sha256-in-circuit commitments over the fixed-layout structs.
    // ============================================================
    component actH = Sha256Struct(4);
    actH.fields[0] <== verb;
    actH.fields[1] <== resource;
    actH.fields[2] <== reversibility;
    actH.fields[3] <== paramScalar;
    actionHi <== actH.hi;
    actionLo <== actH.lo;

    component planH = Sha256Struct(4);
    planH.fields[0] <== planVerb;
    planH.fields[1] <== planResource;
    planH.fields[2] <== semanticDist;
    planH.fields[3] <== planSalt;
    planHi <== planH.hi;
    planLo <== planH.lo;

    component polH = Sha256Struct(20);
    polH.fields[0] <== wAlpha;
    polH.fields[1] <== wBeta;
    polH.fields[2] <== wGamma;
    polH.fields[3] <== wDelta;
    polH.fields[4] <== wEpsilon;
    polH.fields[5] <== wZeta;
    polH.fields[6] <== theta1;
    polH.fields[7] <== theta2;
    polH.fields[8] <== kappa;
    polH.fields[9] <== budgetB;
    polH.fields[10] <== policyVerb;
    polH.fields[11] <== policyResource;
    polH.fields[12] <== policyParamBound;
    polH.fields[13] <== expiresAt;
    polH.fields[14] <== notBefore;
    polH.fields[15] <== maxBlast;
    polH.fields[16] <== maxDepth;
    polH.fields[17] <== revMax;
    polH.fields[18] <== rateMax;
    polH.fields[19] <== allocParent;
    policyHi <== polH.hi;
    policyLo <== polH.lo;

    // ============================================================
    // (B.1) risk functional  r = clamp( a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1 )
    // Each weight (scale S) * input (scale S) is scale S^2; the six-term sum rNum is scale S^2.
    // ============================================================
    // range-bind the [0,S] inputs so (S - x) cannot underflow the field into a huge value.
    component rngRev = LessEqThan(32); rngRev.in[0] <== revScore; rngRev.in[1] <== S; rngRev.out === 1;
    component rngConf = LessEqThan(32); rngConf.in[0] <== conf;    rngConf.in[1] <== S; rngConf.out === 1;
    component rngD   = LessEqThan(32); rngD.in[0]   <== semanticDist; rngD.in[1] <== S; rngD.out === 1;
    component rngBl  = LessEqThan(32); rngBl.in[0]  <== blast;     rngBl.in[1] <== S; rngBl.out === 1;
    component rngTa  = LessEqThan(32); rngTa.in[0]  <== taint;     rngTa.in[1] <== S; rngTa.out === 1;
    component rngAge = LessEqThan(32); rngAge.in[0] <== age;       rngAge.in[1] <== S; rngAge.out === 1;
    component rngFl  = LessEqThan(32); rngFl.in[0]  <== rFloorIn;  rngFl.in[1] <== S; rngFl.out === 1;

    signal termA; termA <== wAlpha * semanticDist;
    signal termB; termB <== wBeta  * (S - revScore);
    signal termG; termG <== wGamma * blast;
    signal termD; termD <== wDelta * taint;
    signal termE; termE <== wEpsilon * (S - conf);
    signal termZ; termZ <== wZeta  * age;
    signal rNum; rNum <== termA + termB + termG + termD + termE + termZ;

    // proven integer division rNum = rQ*S + rRem, 0 <= rRem < S, rQ range-checked.
    rNum === rQ * S + rRem;
    component remOk = LessThan(32); remOk.in[0] <== rRem; remOk.in[1] <== S; remOk.out === 1;
    component rqRange = Num2Bits(48); rqRange.in <== rQ; // rQ < 2^48 (rNum < 6*S^2 < 2^43)

    // upper clamp to S:  rClamped = (rQ <= S) ? rQ : S
    component clampLe = LessEqThan(48); clampLe.in[0] <== rQ; clampLe.in[1] <== S;
    signal rClamped; rClamped <== clampLe.out * rQ + (1 - clampLe.out) * S;

    // monotone floor:  rFinal = max(rClamped, rFloorIn)
    //   written as a single-product mux (rFloorIn + sel*(rClamped - rFloorIn)) so the constraint is
    //   quadratic: `sel*rClamped + (1-sel)*rFloorIn` would be TWO signal*signal products (non-quadratic).
    component floorLe = LessEqThan(32); floorLe.in[0] <== rFloorIn; floorLe.in[1] <== rClamped;
    signal rFinal; rFinal <== rFloorIn + floorLe.out * (rClamped - rFloorIn);
    r <== rFinal;

    // ============================================================
    // (B.2) threshold ladder:  r<=theta1 -> t=1 ; r<=theta2 -> t=2 ; else t=3   (theta1<=theta2)
    // ============================================================
    component thOrder = LessEqThan(32); thOrder.in[0] <== theta1; thOrder.in[1] <== theta2; thOrder.out === 1;
    component t1c = LessEqThan(32); t1c.in[0] <== rFinal; t1c.in[1] <== theta1;
    component t2c = LessEqThan(32); t2c.in[0] <== rFinal; t2c.in[1] <== theta2;
    signal t1; t1 <== t1c.out;
    signal t2; t2 <== t2c.out;
    t <== 3 - t1 - t2;

    // ============================================================
    // (B.3) budget admission:  cost = kappa*rFinal/S ; admit = (t==1) AND (budgetB >= cost)
    // ============================================================
    signal costNum; costNum <== kappa * rFinal;
    costNum === costQ * S + costRem;
    component costRemOk = LessThan(32); costRemOk.in[0] <== costRem; costRemOk.in[1] <== S; costRemOk.out === 1;
    component costRange = Num2Bits(48); costRange.in <== costQ;
    component budgetGe = GreaterEqThan(48); budgetGe.in[0] <== budgetB; budgetGe.in[1] <== costQ;
    admit <== t1 * budgetGe.out;

    // ============================================================
    // (B.4) predicates (single allowlist entry + one numeric where bound) and plan membership.
    // ============================================================
    component vEqP = IsEqual(); vEqP.in[0] <== verb;     vEqP.in[1] <== policyVerb;
    component rEqP = IsEqual(); rEqP.in[0] <== resource; rEqP.in[1] <== policyResource;
    component whereLe = LessEqThan(64); whereLe.in[0] <== paramScalar; whereLe.in[1] <== policyParamBound;
    component vEqPlan = IsEqual(); vEqPlan.in[0] <== verb;     vEqPlan.in[1] <== planVerb;
    component rEqPlan = IsEqual(); rEqPlan.in[0] <== resource; rEqPlan.in[1] <== planResource;

    signal predVR; predVR <== vEqP.out * rEqP.out;
    signal predicatesOK; predicatesOK <== predVR * whereLe.out;
    signal planOK; planOK <== vEqPlan.out * rEqPlan.out;

    // ============================================================
    // (B.5) built-in conjunctive caveats (all must hold).
    // ============================================================
    component cavExpires = LessThan(64);   cavExpires.in[0] <== now;        cavExpires.in[1] <== expiresAt;   // now < expiresAt
    component cavNotBef  = LessEqThan(64);  cavNotBef.in[0] <== notBefore;   cavNotBef.in[1] <== now;          // now >= notBefore
    component cavBlast   = LessEqThan(32);  cavBlast.in[0] <== blast;        cavBlast.in[1] <== maxBlast;      // blast <= maxBlast
    component cavDepth   = LessEqThan(16);  cavDepth.in[0] <== delegationDepth; cavDepth.in[1] <== maxDepth;   // depth <= maxDepth
    component cavRev     = LessEqThan(8);   cavRev.in[0] <== reversibility;  cavRev.in[1] <== revMax;          // revClass <= revMax
    component cavRate    = LessThan(32);    cavRate.in[0] <== recentCount;   cavRate.in[1] <== rateMax;        // recentCount < rateMax

    component caveatsAnd = MultiAND(6);
    caveatsAnd.in[0] <== cavExpires.out;
    caveatsAnd.in[1] <== cavNotBef.out;
    caveatsAnd.in[2] <== cavBlast.out;
    caveatsAnd.in[3] <== cavDepth.out;
    caveatsAnd.in[4] <== cavRev.out;
    caveatsAnd.in[5] <== cavRate.out;
    signal caveatsOK; caveatsOK <== caveatsAnd.out;

    // ============================================================
    // (B.6) attenuation-chain narrowing: budget_alloc monotone + depth bound (MAX_CHAIN_DEPTH = 16).
    // ============================================================
    component allocLe = LessEqThan(48); allocLe.in[0] <== allocChild; allocLe.in[1] <== allocParent;
    component chainDepth = LessEqThan(16); chainDepth.in[0] <== delegationDepth; chainDepth.in[1] <== 16;
    signal chainOK; chainOK <== allocLe.out * chainDepth.out;

    // ============================================================
    // (B.7) release gate: allow = predicatesOK AND planOK AND caveatsOK AND chainOK.
    //   `allow` is DERIVED (not free) and asserted == 1; any failing check makes it UNSATISFIABLE.
    // ============================================================
    signal gate1; gate1 <== predicatesOK * planOK;
    signal gate2; gate2 <== gate1 * caveatsOK;
    signal computedAllow; computedAllow <== gate2 * chainOK;
    allow === computedAllow;
    allow === 1;
}

component main {public [allow, now, blast, delegationDepth, recentCount, allocChild]} = PolicyVM();
