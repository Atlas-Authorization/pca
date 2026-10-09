/**
 * Centralized re-exports of the two upstream packages this gate is built on. The CI gate does NOT
 * re-implement any static analysis — it drives the real `@atlasauth/pca-analyzer` decision procedure
 * and reads the real `@atlasauth/pca` policy shapes.
 */

export {
  alwaysAllows,
  alwaysDenies,
  disjoint,
  equivalent,
  reachable,
  subsumes,
  predicateNumericSatisfiable,
  tightenInterval,
  intervalEmpty,
  FULL_INTERVAL,
} from '@atlasauth/pca-analyzer';

export type {
  AnalyzerAction,
  AnalyzerOptions,
  PolicyInput,
  NumInterval,
  ReachableResult,
  AlwaysAllowsResult,
  AlwaysDeniesResult,
  SubsumesResult,
} from '@atlasauth/pca-analyzer';

export { ENVELOPE_CAVEAT, isLeafCondition } from '@atlasauth/pca';
export type { Capability, Caveat, Condition, Envelope, LeafCondition, Predicate, RiskPolicy } from '@atlasauth/pca';
