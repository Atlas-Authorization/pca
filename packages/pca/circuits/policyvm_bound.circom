pragma circom 2.1.6;

// ---------------------------------------------------------------------------
// Circuit 'pca-policyvm-v2': the full Policy-VM circuit (identical statement and constraints to
// 'pca-policyvm-v1', instantiated unchanged) PLUS a sha256 commitment to the five risk magnitudes the
// prover otherwise supplies unattested: (revScore, taint, conf, age, rFloorIn). The commitment is exposed as
// the public outputs riskHi / riskLo (two 128-bit halves, same layout as the action/policy/plan halves).
// A resource server that knows the attested values of those five inputs recomputes the digest and pins it, so
// the proven risk r / tier t / admit can no longer come from magnitudes the prover chose freely.
//
// Public signals (snarkjs order = outputs, then declared public inputs):
//   [0] actionHi [1] actionLo [2] policyHi [3] policyLo [4] planHi [5] planLo [6] r [7] t [8] admit
//   [9] riskHi [10] riskLo
//   [11] allow [12] now [13] blast [14] delegationDepth [15] recentCount [16] allocChild
// ---------------------------------------------------------------------------

include "policyvm_lib.circom";

template PolicyVMBound() {
    signal input verb;
    signal input resource;
    signal input reversibility;
    signal input paramScalar;
    signal input planVerb;
    signal input planResource;
    signal input semanticDist;
    signal input planSalt;
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
    signal input revScore;
    signal input taint;
    signal input conf;
    signal input age;
    signal input rFloorIn;
    signal input rQ;
    signal input rRem;
    signal input costQ;
    signal input costRem;
    signal input allow;
    signal input now;
    signal input blast;
    signal input delegationDepth;
    signal input recentCount;
    signal input allocChild;
    signal output actionHi;
    signal output actionLo;
    signal output policyHi;
    signal output policyLo;
    signal output planHi;
    signal output planLo;
    signal output r;
    signal output t;
    signal output admit;
    signal output riskHi;
    signal output riskLo;

    component core = PolicyVM();
    core.verb <== verb;
    core.resource <== resource;
    core.reversibility <== reversibility;
    core.paramScalar <== paramScalar;
    core.planVerb <== planVerb;
    core.planResource <== planResource;
    core.semanticDist <== semanticDist;
    core.planSalt <== planSalt;
    core.wAlpha <== wAlpha;
    core.wBeta <== wBeta;
    core.wGamma <== wGamma;
    core.wDelta <== wDelta;
    core.wEpsilon <== wEpsilon;
    core.wZeta <== wZeta;
    core.theta1 <== theta1;
    core.theta2 <== theta2;
    core.kappa <== kappa;
    core.budgetB <== budgetB;
    core.policyVerb <== policyVerb;
    core.policyResource <== policyResource;
    core.policyParamBound <== policyParamBound;
    core.expiresAt <== expiresAt;
    core.notBefore <== notBefore;
    core.maxBlast <== maxBlast;
    core.maxDepth <== maxDepth;
    core.revMax <== revMax;
    core.rateMax <== rateMax;
    core.allocParent <== allocParent;
    core.revScore <== revScore;
    core.taint <== taint;
    core.conf <== conf;
    core.age <== age;
    core.rFloorIn <== rFloorIn;
    core.rQ <== rQ;
    core.rRem <== rRem;
    core.costQ <== costQ;
    core.costRem <== costRem;
    core.allow <== allow;
    core.now <== now;
    core.blast <== blast;
    core.delegationDepth <== delegationDepth;
    core.recentCount <== recentCount;
    core.allocChild <== allocChild;
    actionHi <== core.actionHi;
    actionLo <== core.actionLo;
    policyHi <== core.policyHi;
    policyLo <== core.policyLo;
    planHi <== core.planHi;
    planLo <== core.planLo;
    r <== core.r;
    t <== core.t;
    admit <== core.admit;

    component riskH = Sha256Struct(5);
    riskH.fields[0] <== revScore;
    riskH.fields[1] <== taint;
    riskH.fields[2] <== conf;
    riskH.fields[3] <== age;
    riskH.fields[4] <== rFloorIn;
    riskHi <== riskH.hi;
    riskLo <== riskH.lo;
}

component main {public [allow, now, blast, delegationDepth, recentCount, allocChild]} = PolicyVMBound();
