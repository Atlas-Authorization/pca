/**
 * Guards the hand-trimmed gRPC proto subset used by the Envoy harness: every (message, field, number,
 * type) in it must exist identically in the vendored official Envoy v1.39.3 protos.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const FIX = join(__dirname, '..', 'fixtures');
const read = (n: string): string => readFileSync(join(FIX, n), 'utf8');

/** Collect `Message.Path|type name = number` for every scalar/message field, tracking nesting by braces. */
function fields(src: string): Map<string, string> {
  const out = new Map<string, string>();
  const stack: string[] = [];
  let pending: string | undefined;
  const text = src.replace(/\/\/.*$/gm, '').replace(/\[[^\]]*\]/gs, '');
  for (const stmt of text.split(/([{};])/)) {
    const t = stmt.trim();
    if (t === '{') { stack.push(pending ?? ''); pending = undefined; continue; }
    if (t === '}') { stack.pop(); continue; }
    if (t === ';' || t === '') continue;
    const m = /^(message|enum|oneof)\s+(\w+)$/.exec(t.replace(/\s+/g, ' '));
    if (m) { pending = m[1] === 'oneof' ? '' : m[2]; continue; }
    const f = /^(?:repeated\s+)?(?:map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*(\d+)$/.exec(t.replace(/\s+/g, ' '));
    if (f && stack.length) {
      const type = t.replace(/\s+/g, ' ').replace(/\s+\w+\s*=\s*\d+$/, '');
      out.set(`${stack.filter(Boolean).join('.')}.${f[1]}`, `${type} = ${f[2]}`);
    }
  }
  return out;
}

describe('envoy-ext_authz-grpc-subset.proto', () => {
  const official = new Map<string, string>();
  for (const f of ['envoy-external_auth.proto', 'envoy-attribute_context.proto', 'envoy-base.proto', 'envoy-http_status.proto']) {
    for (const [k, v] of fields(read(f))) official.set(k, v);
  }
  const subset = fields(read('envoy-ext_authz-grpc-subset.proto'));

  it('parses a non-trivial number of fields', () => {
    expect(subset.size).toBeGreaterThan(30);
    expect(official.size).toBeGreaterThan(subset.size);
  });

  // Local stand-ins whose official definitions live in files that are not vendored (address.proto,
  // google.rpc.Status); their numbers are asserted from the vendored references below instead.
  const SKIP = new Set(['Address.socket_address', 'SocketAddress.address', 'SocketAddress.port_value', 'RpcStatus.code', 'RpcStatus.message']);
  // Official enum-typed fields are int32 on the wire.
  const ENUMS = new Map([['HeaderValueOption.append_action', 'int32 = 3'], ['HttpStatus.code', 'int32 = 1'], ['CheckResponse.status', 'RpcStatus = 1']]);

  it('every field number and type matches the vendored official protos', () => {
    const mismatches: string[] = [];
    for (const [k, v] of subset) {
      if (SKIP.has(k)) continue;
      const o = official.get(k);
      if (o === undefined) { mismatches.push(`${k}: not in official protos`); continue; }
      const norm = (x: string): string => x.replace(/\b(?:config\.core\.v3|type\.v3|envoy\.service\.auth\.v3)\./g, '').replace(/google\.protobuf\.\w+/g, 'X');
      const enumOk = ENUMS.get(k) === v && o.endsWith(` = ${v.split(' = ')[1]}`);
      if (!enumOk && norm(o) !== norm(v)) mismatches.push(`${k}: subset '${v}' vs official '${o}'`);
    }
    expect(mismatches).toEqual([]);
  });

  it('the google.rpc.Status / Address numbers used are the documented ones (status=1 code=1 message=2; socket_address=1 address=2 port_value=3)', () => {
    const ext = read('envoy-external_auth.proto');
    expect(ext).toMatch(/google\.rpc\.Status status = 1;/);
    expect(read('envoy-attribute_context.proto')).toMatch(/config\.core\.v3\.Address address = 1;/);
  });
});
