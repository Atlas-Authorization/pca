// pb.ts - a tiny protobuf encoder for building FileDescriptorSet bytes in tests (the importer only reads them).
const varint = (n: number): number[] => {
  const out: number[] = [];
  let v = n;
  while (v >= 128) { out.push((v % 128) | 128); v = Math.floor(v / 128); }
  out.push(v);
  return out;
};
const tag = (f: number, wt: number): number[] => varint(f * 8 + wt);
const bytes = (f: number, b: number[]): number[] => [...tag(f, 2), ...varint(b.length), ...b];
const str = (f: number, s: string): number[] => bytes(f, [...new TextEncoder().encode(s)]);
const int = (f: number, n: number): number[] => [...tag(f, 0), ...varint(n)];

interface F { name: string; num: number; type: number; label?: number; typeName?: string; behavior?: number[] }
interface M { name: string; input: string; output: string; http?: { method: string; path: string }; idem?: number; cs?: boolean; ss?: boolean }

export function descriptorSet(o: { pkg: string; messages: { name: string; fields: F[] }[]; services: { name: string; methods: M[] }[] }): Uint8Array {
  const msg = (m: { name: string; fields: F[] }) => bytes(4, [
    ...str(1, m.name),
    ...m.fields.flatMap((f) => bytes(2, [
      ...str(1, f.name), ...int(3, f.num), ...int(4, f.label ?? 1), ...int(5, f.type), ...(f.typeName ? str(6, f.typeName) : []),
      ...(f.behavior && f.behavior.length > 0 ? bytes(8, bytes(1052, f.behavior.flatMap((b) => varint(b)))) : []),
    ])),
  ]);
  const verbs: Record<string, number> = { get: 2, put: 3, post: 4, delete: 5, patch: 6 };
  const method = (m: M) => bytes(2, [
    ...str(1, m.name), ...str(2, m.input), ...str(3, m.output),
    ...(m.http || m.idem ? bytes(4, [...(m.idem ? int(34, m.idem) : []), ...(m.http ? bytes(72295728, str(verbs[m.http.method]!, m.http.path)) : [])]) : []),
    ...(m.cs ? int(5, 1) : []), ...(m.ss ? int(6, 1) : []),
  ]);
  const file = [...str(1, 'x.proto'), ...str(2, o.pkg), ...o.messages.flatMap(msg), ...o.services.flatMap((s) => bytes(6, [...str(1, s.name), ...s.methods.flatMap(method)]))];
  return Uint8Array.from(bytes(1, file));
}
