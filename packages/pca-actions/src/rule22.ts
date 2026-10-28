// rule22.ts - the trait engine the verifier's rule 22 (`traits`) calls. @atlasauth/pca cannot import this package (it depends on
// pca), so the verifier takes the engine through its context: `{ rule22: RULE22_ENGINE }`. A v2 schema is refused without it.
//   integrity: the document's traits and materialized floors are recomputed from the verb's visible facts and the carried registry
//   (`schemaFloorError`); a forged floor or a dropped implied trait refuses the schema.
//   decision: FloorDecision of the verb's materialized floors against what the grant provides and the call context.

import type { Rule22Engine } from '@atlasauth/pca/ext/intent';
import type { ReviewerPins } from './confirmation';
import { schemaFloorError } from './derive';
import { CAVEAT_KINDS, type CaveatKind } from './def';
import { floorDecision, isContextKey, profileError, type Profile } from './traits';

const isCaveatKind = (x: string): x is CaveatKind => (CAVEAT_KINDS as readonly string[]).includes(x);

export const RULE22_ENGINE: Rule22Engine = {
  schemaError(doc, reviewers) {
    try {
      return schemaFloorError(doc as Parameters<typeof schemaFloorError>[0], reviewers as ReviewerPins | undefined);
    } catch (e) {
      return `schema_floor_forged: ${(e as Error).message}`;
    }
  },
  decide({ doc, verb, grant, context }) {
    try {
      const v = (doc as { verbs?: Array<{ verb: string; floors?: unknown }> }).verbs?.find((x) => x.verb === verb);
      if (v === undefined || profileError(v.floors) !== null) return 'deny';
      const kinds = grant.caveats.filter(isCaveatKind);
      const ctx = context.filter(isContextKey);
      return floorDecision({ caveats: kinds, max_esc: grant.max_esc, preauth_esc: grant.preauth_esc }, { context: ctx }, v.floors as Profile);
    } catch {
      return 'deny';
    }
  },
};
