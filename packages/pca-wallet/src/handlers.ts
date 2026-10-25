import type { TrustedChannel } from './channel';
import type { SignedIntentRequired } from '@atlasauth/pca';
import { isObj, type PcaAction } from './wire';

/**
 * Framework-neutral handlers for the two wallet endpoints named in the session root (§3.3 item 3, §3.14). The HTTP
 * routes themselves live with the session store (in the hosting server); these functions are what such a route calls,
 * so the wire behaviour is fixed and tested here.
 *
 *   POST /v1/pca/intent/sessions/:sid/questions   { "intent_required": <M5 pca body>, "action": <the PCActn action, raw params> }
 *   POST /v1/pca/intent/sessions/:sid/clarify     { "candidates": [...], "reason": <enum> }
 *
 * Neither response carries p or any map content: the agent (or site) learns a question id, a dry-run verdict, or a
 * refusal code, exactly what an attempt would teach it.
 */

export interface HandlerResponse {
  status: number;
  body: Record<string, unknown>;
}

export type ChannelResolver = (sessionId: string) => TrustedChannel | undefined;

const STATUS_OF_REFUSAL: Record<string, number> = {
  bad_site_signature: 401,
  wrong_session: 409,
  stale_map: 409,
  action_mismatch: 422,
  cell_mismatch: 422,
  not_uncertain: 409,
  already_asked: 409,
  frozen: 429,
  cap_session: 429,
  cap_hour: 429,
  cell_too_large: 422,
  bad_request: 400,
  render_failed: 422,
};

function actionOf(v: unknown): PcaAction | null {
  if (!isObj(v) || typeof v.verb !== 'string' || typeof v.resource !== 'string' || typeof v.reversibility_class !== 'string' || !isObj(v.params)) return null;
  for (const k of Object.keys(v)) if (!['verb', 'resource', 'params', 'reversibility_class'].includes(k)) return null;
  return { verb: v.verb, resource: v.resource, params: v.params, reversibility_class: v.reversibility_class };
}

/** The question endpoint: a site delivers (or an agent relays, unchanged) a site-signed intent_required. */
export function questionHandler(resolve: ChannelResolver) {
  return (sessionId: string, body: unknown): HandlerResponse => {
    const ch = resolve(sessionId);
    if (!ch) return { status: 404, body: { error: 'unknown_session' } };
    if (!isObj(body)) return { status: 400, body: { error: 'bad_request' } };
    for (const k of Object.keys(body)) if (k !== 'intent_required' && k !== 'action') return { status: 400, body: { error: 'bad_request', detail: `unknown member "${k}"` } };
    const action = actionOf(body.action);
    if (!action || !isObj(body.intent_required)) return { status: 400, body: { error: 'bad_request' } };
    const r = ch.receive(body.intent_required as unknown as SignedIntentRequired, { action });
    if (r.ok) return { status: 202, body: { question_id: r.questionId, friction: r.friction } };
    return { status: STATUS_OF_REFUSAL[r.code] ?? 400, body: { error: r.code } };
  };
}

/** The clarification endpoint (§3.14). */
export function clarifyHandler(resolve: ChannelResolver) {
  return (sessionId: string, body: unknown): HandlerResponse => {
    const ch = resolve(sessionId);
    if (!ch) return { status: 404, body: { error: 'unknown_session' } };
    const r = ch.clarify(body);
    if (r.error !== undefined) return { status: 400, body: { error: 'bad_request', detail: r.error } };
    return {
      status: r.status,
      body: { verdicts: r.verdicts, ...(r.questionId !== undefined ? { question_id: r.questionId } : {}), ...(r.refused !== undefined ? { refused: r.refused } : {}) },
    };
  };
}
