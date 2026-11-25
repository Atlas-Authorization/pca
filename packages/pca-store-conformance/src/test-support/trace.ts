/**
 * Test-only call tracing. `tracing(obj, log, tag)` returns a Proxy over `obj` whose methods append one line per call
 * (at INVOCATION time, so the order is deterministic even for calls that race) of the form
 * `tag.method(arg1,arg2,...)` with each argument rendered by `show`. Nested handles are traced by `traceHandle`.
 */

/** Stable, total rendering of a value: non-finite numbers, undefined and bigint survive; object keys keep insertion order. */
export function show(v: unknown): string {
  return JSON.stringify(v, (_k, x: unknown) => {
    if (x === undefined) return '<undefined>';
    if (typeof x === 'number' && !Number.isFinite(x)) return `<${String(x)}>`;
    if (typeof x === 'bigint') return `${x.toString()}n`;
    if (x instanceof Map) return { '<Map>': [...x] };
    return x;
  });
}

/** Wrap every function-valued property of `obj` so each call appends `tag.name(args)` to `log`. Results pass through. */
export function tracing<T extends object>(obj: T, log: string[], tag: string): T {
  return new Proxy(obj, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof v !== 'function' || typeof prop !== 'string') return v;
      return (...args: unknown[]): unknown => {
        log.push(`${tag}.${prop}(${args.map(show).join(',')})`);
        return (v as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

/**
 * Trace a handle shaped `{ <clientKey>: client, reopen(): Promise<client>, crash?(): Promise<client>, close?() }`.
 * The first client is tagged `c0`; every client returned by `reopen` / `crash` gets the next tag (`c1`, `c2`, ...),
 * and the `reopen` / `crash` / `close` calls themselves are logged as `h.reopen()` etc.
 */
export function traceHandle<H extends { reopen(): Promise<unknown>; crash?(): Promise<unknown>; close?(): Promise<void> }>(h: H, clientKey: keyof H, log: string[]): H {
  let n = 0;
  const wrapClient = (c: object): object => tracing(c, log, `c${n++}`);
  const out: Record<string, unknown> = { ...h };
  out[clientKey as string] = wrapClient(h[clientKey] as object);
  out.reopen = async () => {
    log.push('h.reopen()');
    return wrapClient((await h.reopen()) as object);
  };
  if (h.crash) {
    out.crash = async () => {
      log.push('h.crash()');
      return wrapClient((await h.crash!()) as object);
    };
  }
  if (h.close) {
    out.close = async () => {
      log.push('h.close()');
      await h.close!();
    };
  }
  return out as H;
}
