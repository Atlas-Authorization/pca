/**
 * `@atlasauth/pca/ext/optimistic`: Optimistic execution: claims, challenge window, fraud proofs, bond settlement.
 *
 * Tier: production (pending CI), no in-memory default: durable settlement is `StoreBondLedger` over a `BondStore`; the Map-backed `BondLedger` and `InMemoryBondAccount` are test doubles in `@atlasauth/pca/ext/optimistic-testing` (0.5, B17). Not part of PCA Core and not re-exported from the root `@atlasauth/pca`.
 */
export * from '../optimistic';
export * from '../bond-settlement';
export * from '../bond-store';
