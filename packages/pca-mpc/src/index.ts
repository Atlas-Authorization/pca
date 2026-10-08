/**
 * @atlasauth/pca-mpc — PCA evolution B5 reference prototype.
 *
 * A multi-stakeholder Policy VM composed under secure multi-party computation, so user + org +
 * regulator decide allow / threshold jointly WITHOUT any party revealing its own policy. Two layers:
 *   - SEMI-HONEST: additive secret sharing over a prime field + Beaver-triple multiplication
 *     (`sharing.ts`, `beaver.ts`, `runner.ts`).
 *   - MALICIOUS-WITH-ABORT (dishonest-majority): SPDZ-style authenticated sharing with
 *     information-theoretic MACs + a commit-then-open MAC-check that ABORTS on any deviation
 *     (`spdz.ts`, `spdz-runner.ts`). Result is correct, or an abort — never a silent wrong answer.
 * See docs/specs/pca-mpc-policy-vm.md for the security model and the trusted-dealer / no-dealer boundary.
 */

export * from './field';
export * from './sharing';
export * from './beaver';
export * from './thermometer';
export * from './party';
export * from './compose';
export * from './runner';
export * from './spdz';
export * from './spdz-runner';
export * from './ec';
export * from './gf128';
export * from './csprng';
export * from './ot';
export * from './kem-ot';
export * from './mascot';
