/**
 * Two things A2A 1.0 section 8.4 needs from an Agent Card implementation:
 *
 *  1. `jcsBytes`: RFC 8785 JSON Canonicalization (the bytes an Agent Card signature covers). Object members are sorted by
 *     UTF-16 code units (NOT by UTF-8 bytes: the two orders differ when a key holds a character above U+FFFF next to one in
 *     U+E000..U+FFFF), numbers are written with the ECMAScript number-to-string rule, strings with the minimal JSON escapes.
 *     Anything with no JSON form (undefined, functions, bigint, non-finite numbers, lone surrogates, cycles, non-plain
 *     objects, nesting over 64) throws.
 *  2. `validateAgentCard1`: the A2A 1.0 `AgentCard` message (specification/a2a.proto, ProtoJSON camelCase names).
 *
 * This file is identical in `@atlasauth/pca-a2a` and `@atlasauth/pca-agentcard`.
 */

const MAX_DEPTH = 64;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function jcs(v: unknown, seen: Set<object>, depth: number): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('jcs: non-finite number');
      return JSON.stringify(v); // ECMAScript Number::toString; -0 serializes as 0, as RFC 8785 requires
    case 'string':
      if (LONE_SURROGATE.test(v)) throw new TypeError('jcs: lone surrogate in string');
      return JSON.stringify(v);
    case 'object':
      break;
    default:
      throw new TypeError(`jcs: unsupported type ${typeof v}`);
  }
  const o = v as object;
  if (depth > MAX_DEPTH) throw new TypeError('jcs: nesting too deep');
  if (seen.has(o)) throw new TypeError('jcs: cycle');
  seen.add(o);
  try {
    if (Array.isArray(o)) return `[${o.map((x) => jcs(x, seen, depth + 1)).join(',')}]`;
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('jcs: non-plain object');
    const rec = o as Record<string, unknown>;
    return `{${Object.keys(rec)
      .sort() // default sort = UTF-16 code unit order
      .map((k) => {
        if (LONE_SURROGATE.test(k)) throw new TypeError('jcs: lone surrogate in key');
        return `${JSON.stringify(k)}:${jcs(rec[k], seen, depth + 1)}`;
      })
      .join(',')}}`;
  } finally {
    seen.delete(o);
  }
}

/** RFC 8785 canonical UTF-8 bytes of a JSON value. Throws a `TypeError` for a value with no JSON form. */
export function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcs(value, new Set(), 1));
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';

/**
 * Check an object against the A2A 1.0 `AgentCard` message. Returns the problems found, each with a JSON path (empty = valid).
 * Required fields must be present (and non-empty where the message has no sensible empty value); optional fields, when
 * present, must have the right type. Unknown members are allowed (A2A cards are extensible; this package adds `pcaPassport`).
 * `securitySchemes` and `securityRequirements` are checked for shape only.
 */
export function validateAgentCard1(card: unknown): string[] {
  const p: string[] = [];
  if (!isObj(card)) return ['$: the agent card must be an object'];
  const reqStr = (o: Record<string, unknown>, k: string, at: string): void => {
    if (!isStr(o[k]) || o[k] === '') p.push(`${at}.${k}: required non-empty string`);
  };
  const optStr = (o: Record<string, unknown>, k: string, at: string): void => {
    if (o[k] !== undefined && !isStr(o[k])) p.push(`${at}.${k}: must be a string`);
  };
  const optBool = (o: Record<string, unknown>, k: string, at: string): void => {
    if (o[k] !== undefined && typeof o[k] !== 'boolean') p.push(`${at}.${k}: must be a boolean`);
  };
  const strArray = (v: unknown, at: string, nonEmpty: boolean): void => {
    if (!Array.isArray(v) || !v.every(isStr)) p.push(`${at}: must be an array of strings`);
    else if (nonEmpty && v.length === 0) p.push(`${at}: must not be empty`);
  };
  const objArray = (o: Record<string, unknown>, k: string, at: string, required: boolean, nonEmpty: boolean, each: (e: Record<string, unknown>, at: string) => void): void => {
    const v = o[k];
    if (v === undefined) {
      if (required) p.push(`${at}.${k}: required array`);
      return;
    }
    if (!Array.isArray(v)) {
      p.push(`${at}.${k}: must be an array`);
      return;
    }
    if (nonEmpty && v.length === 0) p.push(`${at}.${k}: must not be empty`);
    v.forEach((e, i) => (isObj(e) ? each(e, `${at}.${k}[${i}]`) : p.push(`${at}.${k}[${i}]: must be an object`)));
  };

  reqStr(card, 'name', '$');
  reqStr(card, 'description', '$');
  reqStr(card, 'version', '$');
  optStr(card, 'documentationUrl', '$');
  optStr(card, 'iconUrl', '$');
  objArray(card, 'supportedInterfaces', '$', true, true, (e, at) => {
    reqStr(e, 'url', at);
    reqStr(e, 'protocolBinding', at);
    reqStr(e, 'protocolVersion', at);
    optStr(e, 'tenant', at);
  });
  if (card.provider !== undefined) {
    if (!isObj(card.provider)) p.push('$.provider: must be an object');
    else {
      reqStr(card.provider, 'url', '$.provider');
      reqStr(card.provider, 'organization', '$.provider');
    }
  }
  if (!isObj(card.capabilities)) p.push('$.capabilities: required object');
  else {
    const c = card.capabilities;
    optBool(c, 'streaming', '$.capabilities');
    optBool(c, 'pushNotifications', '$.capabilities');
    optBool(c, 'extendedAgentCard', '$.capabilities');
    objArray(c, 'extensions', '$.capabilities', false, false, (e, at) => {
      optStr(e, 'uri', at);
      optStr(e, 'description', at);
      optBool(e, 'required', at);
      if (e.params !== undefined && !isObj(e.params)) p.push(`${at}.params: must be an object`);
    });
  }
  if (card.securitySchemes !== undefined && !isObj(card.securitySchemes)) p.push('$.securitySchemes: must be an object');
  if (card.securityRequirements !== undefined && !Array.isArray(card.securityRequirements)) p.push('$.securityRequirements: must be an array');
  if (card.defaultInputModes === undefined) p.push('$.defaultInputModes: required array of strings');
  else strArray(card.defaultInputModes, '$.defaultInputModes', true);
  if (card.defaultOutputModes === undefined) p.push('$.defaultOutputModes: required array of strings');
  else strArray(card.defaultOutputModes, '$.defaultOutputModes', true);
  objArray(card, 'skills', '$', true, false, (e, at) => {
    reqStr(e, 'id', at);
    reqStr(e, 'name', at);
    reqStr(e, 'description', at);
    if (e.tags === undefined) p.push(`${at}.tags: required array of strings`);
    else strArray(e.tags, `${at}.tags`, false);
    for (const k of ['examples', 'inputModes', 'outputModes'] as const) if (e[k] !== undefined) strArray(e[k], `${at}.${k}`, false);
    if (e.securityRequirements !== undefined && !Array.isArray(e.securityRequirements)) p.push(`${at}.securityRequirements: must be an array`);
  });
  objArray(card, 'signatures', '$', false, false, (e, at) => {
    reqStr(e, 'protected', at);
    reqStr(e, 'signature', at);
    if (e.header !== undefined && !isObj(e.header)) p.push(`${at}.header: must be an object`);
  });
  return p;
}
