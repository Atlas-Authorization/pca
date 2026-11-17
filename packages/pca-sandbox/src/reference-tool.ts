/**
 * Hand-assembled core-WebAssembly modules for tests, the demo and the guide: no toolchain needed to see the sandbox work.
 * `buildTool` makes a module that calls `pca:act.invoke(handle, ptr, cap)` for each given call and returns either the
 * last call's return code or the first byte of linear memory (where the host wrote the result of the first call at ptr 0).
 */
export interface ToolSpec {
  /** Calls to `invoke`, in order. */
  calls: { handle: number; ptr: number; cap: number }[];
  returns?: 'last' | 'byte0';
  /** Extra imports the tool asks for (ambient authority); the host must refuse the module. */
  extraImports?: { module: string; name: string }[];
  /** Linear memory `[min, max]` in pages; `max: null` declares none. Default `[1, 1]`. */
  memory?: { min: number; max: number | null };
  /** Loop forever after the calls (a tool that never returns). */
  spin?: boolean;
}

const u = (n: number): number[] => {
  const o: number[] = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    o.push(b);
  } while (n > 0);
  return o;
};
const s = (x: string): number[] => [...u(x.length), ...new TextEncoder().encode(x)];
const section = (id: number, body: number[]): number[] => [id, ...u(body.length), ...body];
const vec = (items: number[][]): number[] => [...u(items.length), ...items.flat()];
const i32c = (n: number): number[] => [0x41, ...sleb(n)];
function sleb(n: number): number[] {
  const o: number[] = [];
  for (;;) {
    const b = n & 0x7f;
    n >>= 7;
    if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) return [...o, b];
    o.push(b | 0x80);
  }
}

export function buildTool(spec: ToolSpec): Uint8Array {
  const extra = spec.extraImports ?? [];
  // types: 0 = (i32,i32,i32)->i32, 1 = ()->i32, 2 = (i32,i32,i32,i32)->i32
  const types = vec([
    [0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f],
    [0x60, 0, 1, 0x7f],
    [0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f],
  ]);
  const imports = vec([[...s('pca:act'), ...s('invoke'), 0, 0], ...extra.map((e) => [...s(e.module), ...s(e.name), 0, 2])]);
  const mem = spec.memory ?? { min: 1, max: 1 };
  const memory = vec([mem.max === null ? [0, ...u(mem.min)] : [1, ...u(mem.min), ...u(mem.max)]]);
  const runIndex = 1 + extra.length;
  const body: number[] = [0]; // no locals
  spec.calls.forEach((c, i) => {
    body.push(...i32c(c.handle), ...i32c(c.ptr), ...i32c(c.cap), 0x10, 0);
    if (!(i === spec.calls.length - 1 && (spec.returns ?? 'last') === 'last')) body.push(0x1a);
  });
  if (spec.spin) body.push(0x03, 0x40, 0x0c, 0x00, 0x0b);
  if (spec.returns === 'byte0') body.push(...i32c(0), 0x2d, 0, 0);
  if (spec.calls.length === 0) body.push(...i32c(0));
  body.push(0x0b);
  return Uint8Array.from([
    0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, types),
    ...section(2, imports),
    ...section(3, vec([[1]])),
    ...section(5, memory),
    ...section(7, vec([[...s('memory'), 2, 0], [...s('run'), 0, ...u(runIndex)]])),
    ...section(10, vec([[...u(body.length), ...body]])),
  ]);
}

/** A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb` (the verb window is `cap` bytes). */
export function buildProbeTool(cap = 64): Uint8Array {
  const types = vec([
    [0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f],
    [0x60, 0, 1, 0x7f],
  ]);
  const imports = vec([
    [...s('pca:act'), ...s('invoke'), 0, 0],
    [...s('pca:act'), ...s('handle_count'), 0, 1],
    [...s('pca:act'), ...s('handle_verb'), 0, 0],
  ]);
  const body = [0, ...i32c(1), ...i32c(0), ...i32c(cap), 0x10, 2, 0x1a, 0x10, 1, ...i32c(256), 0x6c, ...i32c(0), 0x2d, 0, 0, 0x6a, 0x0b];
  return Uint8Array.from([
    0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, types),
    ...section(2, imports),
    ...section(3, vec([[1]])),
    ...section(5, vec([[1, 1, 1]])),
    ...section(7, vec([[...s('memory'), 2, 0], [...s('run'), 0, 3]])),
    ...section(10, vec([[...u(body.length), ...body]])),
  ]);
}
