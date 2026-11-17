/** Webhook and SIEM renderings of a directive event. Pure; delivery is the host's (it owns the network guard and the secrets). */
import { webhookHeaders } from '@atlasauth/pca-events';
import type { Directive, Lift } from './types';

export interface DirectiveEvent {
  type: 'directive.issued' | 'directive.lifted';
  at: number;
  directive: Directive;
  lift?: Lift;
}

/** Webhook event names (the hosted API uses these exact strings). */
export const DIRECTIVE_WEBHOOK_TYPES = { issued: 'pca.control.directive.issued', lifted: 'pca.control.directive.lifted' } as const;

/** The JSON body of a webhook delivery. Carries the signed directive, so a receiver can verify it with the control-plane key. */
export function directiveWebhookBody(e: DirectiveEvent): { object: 'pca_control_directive_event'; type: string; at: number; directive: Directive; lift: Lift | null } {
  return { object: 'pca_control_directive_event', type: e.type === 'directive.issued' ? DIRECTIVE_WEBHOOK_TYPES.issued : DIRECTIVE_WEBHOOK_TYPES.lifted, at: e.at, directive: e.directive, lift: e.lift ?? null };
}

/** A signed webhook request: the body and the `PCA-Signature` header (verify with `verifyWebhook` from `@atlasauth/pca-events`). */
export function signDirectiveWebhook(secret: string | Uint8Array, e: DirectiveEvent, opts?: { timestamp?: number }): { body: string; headers: Record<string, string> } {
  const body = JSON.stringify(directiveWebhookBody(e));
  return { body, headers: webhookHeaders(secret, body, opts) };
}

export type SiemFormat = 'ocsf' | 'cef' | 'ecs';
export interface DirectiveSiemEvent {
  format: SiemFormat;
  object?: Record<string, unknown>;
  /** One line ready to ship (NDJSON for ocsf and ecs). */
  line: string;
}

const SEVERITY = { tighten: 4, shrink_budget: 6, require_step_up: 6, freeze: 9 } as const;
const cefHeader = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
const cefExt = (s: string) => s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/[\r\n]+/g, ' ');

/** One directive event in a SIEM schema. Reasons are caller text and are escaped, never interpreted. */
export function directiveSiemEvent(e: DirectiveEvent, format: SiemFormat): DirectiveSiemEvent {
  const d = e.directive;
  const sev = SEVERITY[d.kind];
  const action = e.type === 'directive.issued' ? 'issued' : 'lifted';
  const msg = `${action} ${d.kind} on ${d.subject.kind} ${d.subject.id}: ${d.reason}`.slice(0, 600);
  if (format === 'cef') {
    const ext = [`rt=${e.at}`, `act=${action}`, `cs1Label=directive cs1=${cefExt(d.id)}`, `cs2Label=subject cs2=${cefExt(`${d.subject.kind}:${d.subject.id}`)}`, `cs3Label=cause cs3=${d.cause}`, `suser=${cefExt(d.by)}`, `msg=${cefExt(d.reason)}`];
    return { format, line: `CEF:0|Atlas|PCA Control Plane|1|pca.control.directive.${action}|${cefHeader(msg)}|${sev}|${ext.join(' ')}` };
  }
  const object: Record<string, unknown> =
    format === 'ocsf'
      ? { class_uid: 2004, category_uid: 2, activity_name: action, time: e.at, severity_id: Math.min(5, Math.ceil(sev / 2)), message: msg, finding_info: { uid: d.id, title: `${d.kind} (${d.cause})`, desc: d.reason }, resources: [{ type: d.subject.kind, uid: d.subject.id }], actor: { user: { name: d.by } }, metadata: { product: { name: 'Atlas PCA Control Plane' }, version: '1.1.0' } }
      : { '@timestamp': new Date(e.at).toISOString(), event: { kind: 'alert', category: ['iam'], type: [action === 'issued' ? 'change' : 'allowed'], action: `directive.${action}`, id: d.id, severity: sev }, message: msg, labels: { directive_kind: d.kind, cause: d.cause, subject_kind: d.subject.kind }, user: { name: d.by }, host: { id: d.subject.id } };
  return { format, object, line: JSON.stringify(object) };
}
