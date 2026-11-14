// digests.ts - the content digests of the goal-to-decision flow (strict canonical JSON from @atlasauth/pca: safe integers only).
import { hashCanonical } from '@atlasauth/pca';
import type { Goal } from './ir';

/** Digest of the whole signed Goal. Throws TypeError on a float, undefined or cycle. */
export const goalDigest = (goal: Goal): string => hashCanonical({ d: 'atlas-pca/goal-ir/v1', goal });
/** Digest of the instruction text a goal was interpreted from (what `Goal.nlDigest` must equal). */
export const nlDigest = (instruction: string): string => hashCanonical({ d: 'atlas-pca/goal-nl/v1', text: instruction });
/** Digest of the model set that produced a goal: sorted, de-duplicated ids (empty for a deterministic interpreter). */
export const modelSetDigest = (models: readonly string[]): string => hashCanonical({ d: 'atlas-pca/goal-model-set/v1', models: [...new Set(models)].sort() });
/** Digest of an approval's covered fields (the digests it pins plus its expiry): any changed member changes it (W4). */
export const approvalDigest = (body: Record<string, string | number>): string => hashCanonical({ d: 'atlas-pca/goal-approval-body/v1', body });
