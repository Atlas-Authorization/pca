// jsonschema.ts - "I have a function signature": one JSON Schema plus a verb the caller gives, to one def.

import { ActionKitError, EFFECTS, VERB_RE, type Effect } from '../def';
import { addTodo, clip, emitDef, finish, flattenObject, isObj, newBudget, newCtx, resolveSchema, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';

export interface JsonSchemaImportOpts extends ImportOpts {
  /** The verb to give the def (`<ns>.<noun>.<action>`); must start with `ns.`. */
  verb: string;
  title?: string;
  description?: string;
  /** Default `['update']`: a function with no signal is a write. */
  effects?: Effect[];
}

export function importJsonSchema(schema: unknown, opts: JsonSchemaImportOpts): ImportReport {
  const c = newCtx('jsonschema', schema, opts);
  if (typeof opts.verb !== 'string' || !VERB_RE.test(opts.verb) || !opts.verb.startsWith(opts.ns + '.')) throw new ActionKitError('bad_verb', `verb must be a valid verb in namespace '${opts.ns}'`);
  const effects = opts.effects ?? ['update'];
  if (!Array.isArray(effects) || effects.length === 0 || !effects.every((e) => (EFFECTS as readonly string[]).includes(e))) throw new ActionKitError('bad_effects', 'effects must be 1+ known effects');
  if (!isObj(schema)) throw new ActionKitError('bad_source', 'a JSON Schema must be an object');
  const bud = newBudget(c);
  const root = resolveSchema(schema, c, bud, opts.verb);
  const params: Record<string, import('../def').ParamDef> = {};
  if (root.type === 'object' || isObj(root.properties)) flattenObject(root as JsonSchemaLike, c, bud, opts.verb, params);
  else addTodo(c, opts.verb, 'not_object', 'the schema is not an object schema: the def has no parameters');
  emitDef(c, {
    name: opts.verb.split('.').slice(1).join('_'),
    verb: opts.verb,
    title: opts.title ?? (typeof root.title === 'string' ? root.title : undefined),
    description: opts.description ?? clip(root.description, 600),
    effects,
    scope: 'one',
    params,
    bindings: {},
  });
  return finish(c);
}
