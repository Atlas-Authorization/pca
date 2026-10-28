/**
 * The full PCActn verifier entry: `verifyPCActnCore` and `validateWireV2` with the Intent Layer extension loaded.
 *
 * `@atlasauth/pca/core` exports the same functions WITHOUT the extension (a PCActn or policy that needs the intent
 * layer is refused there, fail closed). The root `@atlasauth/pca` entry and the server verifier (`verifyPCActn`,
 * `requirePCA`, `authorize`) use these, so their behaviour is unchanged.
 */
import { type CoreExtensions, type PCActn, verifyPCActnCore as verifyCore } from './pcactn';
import { type WireExtensions, validateWireV2 as validateWire } from './wire';
import { decideIntentBinding, validateIntentWire } from './intent-binding';
import { validateIntentSessionWire } from './intent-session';
import { decideIntentV2 } from './intent-v2';
import { decideFreshAt, validateFreshAtWire } from './fresh-at';

/** The Intent Layer extension, as the full verifier loads it. */
export const INTENT_WIRE_EXTENSION: WireExtensions = { intent: validateIntentWire, intentSession: validateIntentSessionWire, freshAt: validateFreshAtWire };
export const FULL_EXTENSIONS: CoreExtensions = { wire: INTENT_WIRE_EXTENSION, intentBinding: decideIntentBinding, intentV2: decideIntentV2, freshAt: decideFreshAt };

/** `verifyPCActnCore` with the intent layer loaded (same options; `extensions` may override). */
export function verifyPCActnCore(p: PCActn, opts: Parameters<typeof verifyCore>[1]): ReturnType<typeof verifyCore> {
  return verifyCore(p, { ...opts, extensions: opts.extensions ?? FULL_EXTENSIONS });
}

/** `validateWireV2` with the intent slots validated. */
export function validateWireV2(p: unknown, ext: WireExtensions = INTENT_WIRE_EXTENSION): string | null {
  return validateWire(p, ext);
}
