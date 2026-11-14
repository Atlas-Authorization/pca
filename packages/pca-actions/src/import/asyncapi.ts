// asyncapi.ts - AsyncAPI 2.x / 3.x -> drafts. Sending to a channel is effect `send`, receiving is `read`; the message payload
// becomes the params. A broker publish leaves the trust domain, so it stays `send` (external communication) unless the
// channel carries the allow-listed `x-pca-internal: true`.

import { compareUtf8 } from '@atlasauth/pca';
import { ActionKitError, type Effect, type ParamDef } from '../def';
import { addTodo, clip, emitDef, finish, flattenObject, isObj, newBudget, newCtx, paramSeg, pointer, resolveSchema, verbOf, type Ctx, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';

function deref(c: Ctx, x: unknown, where: string, depth = 0): Record<string, unknown> | undefined {
  if (!isObj(x)) return undefined;
  if (typeof x.$ref !== 'string') return x;
  if (depth > c.lim.max_ref_depth) { addTodo(c, where, 'ref_depth', 'a reference chain is too deep'); return undefined; }
  const t = pointer(c.root, x.$ref);
  if (t === undefined) { addTodo(c, where, 'unresolved_ref', `reference '${clip(x.$ref, 120)}' does not resolve locally`); return undefined; }
  return deref(c, t, where, depth + 1);
}

function payloadParams(c: Ctx, msgs: unknown[], where: string, params: Record<string, ParamDef>, bud: ReturnType<typeof newBudget>): void {
  const resolved = msgs.map((m) => deref(c, m, where)).filter((m): m is Record<string, unknown> => m !== undefined);
  if (resolved.length === 0) return;
  if (resolved.length > 1) addTodo(c, where, 'message_variants', `${resolved.length} message variants: only the first is declared`);
  const payload = resolved[0]!.payload;
  if (payload === undefined) return;
  const s = resolveSchema(payload, c, bud, `${where}: payload`);
  if (s.type === 'object' || isObj(s.properties)) flattenObject(s as JsonSchemaLike, c, bud, where, params);
  else addTodo(c, where, 'payload_shape', 'the message payload is not an object schema; it is not declared');
}

function channelParams(c: Ctx, ch: Record<string, unknown>, where: string, params: Record<string, ParamDef>): void {
  const ps = deref(c, ch.parameters, where);
  if (!ps) return;
  for (const name of Object.keys(ps).sort(compareUtf8)) {
    const s = paramSeg(name);
    if (Object.prototype.hasOwnProperty.call(params, s)) continue;
    params[s] = { type: 'string', max_len: 256 };
  }
}

export function importAsyncApi(source: unknown, opts: ImportOpts): ImportReport {
  const c = newCtx('asyncapi', source, opts);
  if (!isObj(source) || typeof source.asyncapi !== 'string' || !/^[23]\./.test(source.asyncapi)) throw new ActionKitError('bad_source', "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')");
  const v3 = source.asyncapi.startsWith('3');
  const channels = isObj(source.channels) ? source.channels : {};
  const internal = (ch: Record<string, unknown>): boolean => c.ext.has('x-pca-internal') && ch['x-pca-internal'] === true;
  const emit = (opName: string | undefined, chName: string, ch: Record<string, unknown>, action: 'send' | 'receive', op: Record<string, unknown>, msgs: unknown[]) => {
    const where = `${action} ${clip(chName, 100)}`;
    const bud = newBudget(c);
    c.root = source;
    const params: Record<string, ParamDef> = {};
    channelParams(c, ch, where, params);
    payloadParams(c, msgs, where, params, bud);
    const effects: Effect[] = action === 'receive' ? ['read'] : internal(ch) ? ['create'] : ['send'];
    emitDef(c, {
      name: opName ?? where,
      noAlias: opName === undefined,
      verb: opName === undefined ? verbOf(opts.ns, `${chName} ${action}`) : undefined,
      title: typeof op.summary === 'string' ? op.summary : undefined,
      description: typeof op.description === 'string' ? op.description : undefined,
      effects,
      scope: 'one',
      params,
      bindings: { asyncapi: { channel: clip(chName, 250), op: action } },
    });
  };
  if (v3) {
    const ops = isObj(source.operations) ? source.operations : {};
    for (const id of Object.keys(ops).sort(compareUtf8)) {
      const op = deref(c, ops[id], id);
      if (!op || (op.action !== 'send' && op.action !== 'receive')) { addTodo(c, id, 'skipped_op', 'an operation without action send|receive is skipped'); continue; }
      const chRef = deref(c, op.channel, id);
      if (!chRef) continue;
      const chName = typeof chRef.address === 'string' ? chRef.address : (isObj(op.channel) && typeof op.channel.$ref === 'string' ? op.channel.$ref.split('/').pop()! : id);
      const msgs = Array.isArray(op.messages) && op.messages.length > 0 ? op.messages : isObj(chRef.messages) ? Object.keys(chRef.messages).sort(compareUtf8).map((k) => (chRef.messages as Record<string, unknown>)[k]) : [];
      emit(id, chName, chRef, op.action, op, msgs);
    }
  } else {
    for (const chName of Object.keys(channels).sort(compareUtf8)) {
      const ch = deref(c, channels[chName], chName);
      if (!ch) continue;
      // 2.x: `publish` is what a client does to the channel (a send); `subscribe` is what a client receives
      for (const [key, action] of [['publish', 'send'], ['subscribe', 'receive']] as const) {
        const op = deref(c, ch[key], chName);
        if (!op) continue;
        const m = deref(c, op.message, chName);
        const msgs = m && Array.isArray(m.oneOf) ? m.oneOf : m ? [m] : [];
        emit(typeof op.operationId === 'string' && op.operationId.length > 0 ? op.operationId : undefined, chName, ch, action, op, msgs);
      }
    }
  }
  return finish(c);
}
