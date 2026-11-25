pragma circom 2.1.6;

// Circuit 'pca-policyvm-v1': the full Policy-VM circuit. All templates and the statement description live in
// policyvm_lib.circom (shared with policyvm_bound.circom); this file only instantiates them.
include "policyvm_lib.circom";

component main {public [allow, now, blast, delegationDepth, recentCount, allocChild]} = PolicyVM();
