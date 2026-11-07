// naming.ts - verb segments from an HTTP method + path (or an operationId).
import { isActionWord, tokens } from './classify';

export const snake = (s: string): string =>
  s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

const VERSIONISH = /^(v\d+(?:\.\d+)?(?:beta\d*|alpha\d*)?|api|rest|restapi|rest_api|public|\d{4}-\d{2}-\d{2}|2\.0|_?internal)$/;
const isParam = (s: string): boolean => /^\{.*\}$/.test(s) || /^:[A-Za-z_]/.test(s) || /^<.*>$/.test(s);
const plural = (s: string): boolean => /s$/.test(s) && !/(ss|us|is)$/.test(s);

const STOP = new Set(['for', 'the', 'a', 'an', 'of', 'in', 'to', 'by', 'with', 'on', 'and', 'or', 'from', 'as', 'at', 'is']);

/** Fit one verb segment into 32 chars: drop stop words, then keep the first (action) word and as many trailing words as fit. */
export function fit(seg: string, max = 32): string {
  const s = seg.replace(/^_+|_+$/g, '');
  if (s.length <= max) return s;
  let w = s.split('_').filter(Boolean);
  const k = w.filter((x) => !STOP.has(x));
  if (k.length) w = k;
  if (w.join('_').length <= max) return w.join('_');
  const head = w[0]!;
  const tail: string[] = [];
  for (let i = w.length - 1; i > 0; i--) {
    const next = [w[i]!, ...tail];
    if ([head, ...next].join('_').length > max) break;
    tail.unshift(w[i]!);
  }
  return [head, ...tail].join('_').slice(0, max).replace(/_+$/g, '');
}

/** Cap a noun list at 4 (first 2 + last 2), each segment <= 32 chars, de-duplicated neighbours. */
export function capNouns(ns: string[]): string[] {
  const out: string[] = [];
  for (const n of ns) {
    const t = fit(n);
    if (t && out[out.length - 1] !== t) out.push(t);
  }
  return out.length <= 4 ? out : [out[0]!, out[1]!, out[out.length - 2]!, out[out.length - 1]!];
}

/** Verb segments (after the ns) for a REST operation, derived from the path shape. */
export function pathName(method: string, httpPath: string): string[] {
  let segs = httpPath.split('/').filter(Boolean);
  while (segs.length && VERSIONISH.test(segs[0]!.toLowerCase())) segs = segs.slice(1);
  // google style custom method: /things/{id}:cancel
  let custom: string | undefined;
  const lastRaw = segs[segs.length - 1];
  if (lastRaw && /:[A-Za-z]/.test(lastRaw) && !isParam(lastRaw)) {
    const [a, b] = lastRaw.split(':');
    segs[segs.length - 1] = a!;
    custom = b;
  } else if (lastRaw && /\}:[A-Za-z]/.test(lastRaw)) {
    custom = lastRaw.split('}:')[1];
    segs[segs.length - 1] = lastRaw.split(':')[0]!;
  }
  const last = segs[segs.length - 1];
  const lastIsParam = last !== undefined && isParam(last);
  const statics = segs.filter((s) => !isParam(s)).map((s) => snake(s.replace(/\.json$/, ''))).filter(Boolean);
  const m = method.toUpperCase();
  let action: string;
  let nouns = statics;
  if (custom) action = snake(custom);
  else if (lastIsParam) action = m === 'GET' || m === 'HEAD' ? 'get' : m === 'DELETE' ? 'delete' : m === 'POST' || m === 'PUT' || m === 'PATCH' ? 'update' : snake(m);
  else if (m === 'GET' || m === 'HEAD') action = statics.length && plural(statics[statics.length - 1]!) ? 'list' : 'get';
  else if (m === 'DELETE') action = 'delete';
  else if (m === 'PUT' || m === 'PATCH') {
    const ls = statics[statics.length - 1] ?? '';
    if (ls && !plural(ls) && isActionWord(tokens(ls)[0] ?? '')) { action = ls; nouns = statics.slice(0, -1); } else action = 'update';
  } else {
    const ls = statics[statics.length - 1] ?? '';
    const prevIsParam = segs.length >= 2 && isParam(segs[segs.length - 2]!);
    // an action word names the action anywhere; a singular word right after an id (/things/{id}/finalize) is an action by position
    if (ls && !plural(ls) && (isActionWord(tokens(ls)[0] ?? '') || prevIsParam)) {
      action = ls;
      nouns = statics.slice(0, -1);
    } else action = 'create';
  }
  if (custom && m === 'GET' && !isActionWord(tokens(action)[0] ?? '')) action = `get_${action}`;
  nouns = capNouns(nouns);
  return [...nouns, fit(action)];
}

/** Verb segments from an operationId such as `repos/create-fork`, `chat.postMessage`, `getIssue`. */
export function opIdName(opId: string): string[] {
  const parts = opId.split(/[/.:]+/).filter(Boolean).map(snake).filter(Boolean);
  return capNouns(parts.slice(0, -1)).concat([fit(parts[parts.length - 1]!)]);
}
