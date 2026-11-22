/**
 * OpenTelemetry instrumentation for Proof-Carrying Authority.
 *
 * Wrap a verification guard so every decision emits a span (decision / tier / risk / verb / resource)
 * and two metrics (a `pca.verifications` counter and a `pca.verify.risk` histogram). Pass in your own
 * real OpenTelemetry `Tracer` / `Meter` and ours are structurally compatible — we never import the SDK,
 * so this package has no hard dependency on `@opentelemetry/api` (declare it as an optional peer).
 *
 * Generic over the result shape: we only read a small structural slice of the guard's verdict, so this
 * does NOT depend on the guard's concrete verdict type.
 *
 * HONEST: this observes — it never decides. With no tracer and no meter the wrapper is a transparent
 * pass-through (the guard's result is returned unchanged, no telemetry), so it is always safe to call.
 */

/** Minimal structural shape of an OpenTelemetry `Span` — only the methods we touch. */
export interface SpanLike {
  setAttribute(k: string, v: string | number | boolean): void;
  setStatus(s: { code: number; message?: string }): void;
  recordException(e: unknown): void;
  end(): void;
}

/** Minimal structural shape of an OpenTelemetry `Tracer`. */
export interface TracerLike {
  startSpan(name: string): SpanLike;
}

/** Minimal structural shape of an OpenTelemetry `Counter`. */
export interface CounterLike {
  add(n: number, attrs?: Record<string, string | number | boolean>): void;
}

/** Minimal structural shape of an OpenTelemetry `Histogram`. */
export interface HistogramLike {
  record(n: number, attrs?: Record<string, string | number | boolean>): void;
}

/** Minimal structural shape of an OpenTelemetry `Meter`. */
export interface MeterLike {
  createCounter(name: string): CounterLike;
  createHistogram(name: string): HistogramLike;
}

/**
 * The slice of a PCA verdict we read for telemetry. `r` is the computed risk; `requiredThreshold.t` is
 * the tier the action had to clear. Everything is optional so any verdict-shaped object fits.
 */
export interface PcaVerdictLike {
  allow: boolean;
  r?: number;
  requiredThreshold?: { t?: number };
  checks?: Record<string, string>;
  reasons?: string[];
}

/** The slice of a guard result we read: the outcome, HTTP-ish status, verdict, and the acted-on PCActn. */
export interface GuardResultLike {
  ok: boolean;
  status?: number;
  verdict?: PcaVerdictLike;
  pcactn?: { action?: { verb?: string; resource?: string } };
}

// OpenTelemetry `SpanStatusCode`: UNSET = 0, OK = 1, ERROR = 2. Mirrored here so we never import the SDK.
const STATUS_OK = 1;
const STATUS_ERROR = 2;

const MAX_TEXT = 256;

/**
 * Remove what looks like a credential from text bound for telemetry: JWTs, `Bearer` and `Basic` credentials,
 * URL userinfo (`scheme://user:pass@host`), `name=value` / `"name": "value"` pairs whose name is token, secret,
 * password, key, signature, credential or authorization, and long unbroken base64url or hex runs (32+ characters,
 * the size of a key, a digest, a signature or an API token). The result is cut to 256 characters. A pattern list
 * is a net, not a proof: keep secrets out of resources and reasons in the first place.
 */
export function redactSecrets(text: string): string {
  let t = String(text);
  t = t.replace(/\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g, '[redacted]');
  t = t.replace(/\b(authorization["']?\s*[:=]\s*)[^\n"']*/gi, '$1[redacted]');
  t = t.replace(/\b(Bearer|Basic|Token)\s+[\w.~+/=-]{6,}/gi, '$1 [redacted]');
  t = t.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]*:[^\s/@]*@/gi, '$1[redacted]@');
  t = t.replace(/\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s"'&,;]+)/gi, (_m, head: string, val: string) => {
    const q = val[0] === '"' || val[0] === "'" ? val[0] : '';
    return `${head}${q}[redacted]${q}`;
  });
  t = t.replace(/[A-Za-z0-9_-]{32,}/g, '[redacted]');
  return t.length > MAX_TEXT ? `${t.slice(0, MAX_TEXT)}...` : t;
}

/** The first deny reason, if any — used for the span's error message and the `pca.reason` attribute. */
function firstReason(result: GuardResultLike): string | undefined {
  return result?.verdict?.reasons?.[0];
}

/**
 * Map a guard result to OpenTelemetry span attributes. Undefined fields are omitted, so a span only
 * carries the dimensions the verdict actually has. `pca.reason` is added on deny only.
 */
export function pcaSpanAttributes(result: GuardResultLike, redact: (s: string) => string = redactSecrets): Record<string, string | number | boolean> {
  const attrs: Record<string, string | number | boolean> = {
    'pca.decision': result?.ok === true ? 'allow' : 'deny', // anything but an explicit allow is reported as a deny
  };
  const status = result?.status;
  if (typeof status === 'number' && Number.isFinite(status)) attrs['pca.status'] = status;

  const tier = result?.verdict?.requiredThreshold?.t;
  if (typeof tier === 'number' && Number.isFinite(tier)) attrs['pca.tier'] = tier;

  const risk = result?.verdict?.r;
  if (typeof risk === 'number' && Number.isFinite(risk)) attrs['pca.risk'] = risk;

  const verb = result?.pcactn?.action?.verb;
  if (typeof verb === 'string') attrs['pca.verb'] = redact(verb);

  const resource = result?.pcactn?.action?.resource;
  if (typeof resource === 'string') attrs['pca.resource'] = redact(resource);

  if (result?.ok !== true) {
    const reason = firstReason(result);
    if (typeof reason === 'string') attrs['pca.reason'] = redact(reason);
  }
  return attrs;
}

/** Options for {@link instrumentGuard}. Omit both `tracer` and `meter` for a pure no-op pass-through. */
export interface InstrumentGuardOptions {
  tracer?: TracerLike;
  meter?: MeterLike;
  spanName?: string;
  /**
   * Applied to every string that leaves in a span attribute, a status message or a recorded exception.
   * Default {@link redactSecrets}. Pass `(s) => s` only if you have already made those strings safe.
   */
  redact?: (s: string) => string;
}

/**
 * Wrap a verification guard so each decision emits a span + metrics. The returned function has the SAME
 * signature as the guard and returns its result unchanged, so it is a drop-in replacement.
 *
 * - A span (named `opts.spanName ?? 'pca.verify'`) is started when a tracer is given, annotated with
 *   {@link pcaSpanAttributes}, given OK status on allow and ERROR status (+ first reason) on deny, and
 *   always ended in a `finally`.
 * - When the guard throws, the exception is recorded on the span, the span is ended, and the error is
 *   re-thrown — the caller sees the original failure.
 * - When a meter is given, a `pca.verifications` counter (created once) is incremented per decision and
 *   a `pca.verify.risk` histogram records the risk, both tagged with the decision.
 */
export function instrumentGuard<Req>(
  guard: (req: Req) => Promise<GuardResultLike>,
  opts?: InstrumentGuardOptions,
): (req: Req) => Promise<GuardResultLike> {
  const tracer = opts?.tracer;
  const meter = opts?.meter;
  const spanName = opts?.spanName ?? 'pca.verify';

  // Metrics instruments are created once, up front, not per call.
  const counter = meter?.createCounter('pca.verifications');
  const histogram = meter?.createHistogram('pca.verify.risk');

  const redact = opts?.redact ?? redactSecrets;
  // Telemetry observes. A tracer or meter that throws must never change what the guard decided, so every call is isolated.
  const safe = (f: () => void): void => {
    try {
      f();
    } catch {
      /* the decision is the guard's, not the exporter's */
    }
  };

  return async (req: Req): Promise<GuardResultLike> => {
    let span: SpanLike | undefined;
    safe(() => {
      span = tracer?.startSpan(spanName);
    });
    try {
      const result = await guard(req);

      if (span) {
        const sp = span;
        safe(() => {
          for (const [k, v] of Object.entries(pcaSpanAttributes(result, redact))) sp.setAttribute(k, v);
          const reason = result?.ok === true ? undefined : firstReason(result);
          if (result?.ok === true) sp.setStatus({ code: STATUS_OK });
          else sp.setStatus(typeof reason === 'string' ? { code: STATUS_ERROR, message: redact(reason) } : { code: STATUS_ERROR });
        });
      }

      const decision = result?.ok === true ? 'allow' : 'deny';
      safe(() => counter?.add(1, { decision }));
      const risk = result?.verdict?.r;
      if (histogram && typeof risk === 'number' && Number.isFinite(risk)) safe(() => histogram.record(risk, { decision }));

      return result;
    } catch (e) {
      if (span) {
        const sp = span;
        safe(() => {
          // A fresh error: the original may carry credentials in its message, its cause or its stack.
          const clean = new Error(redact(e instanceof Error ? e.message : String(e)));
          clean.name = e instanceof Error && /^\w{1,64}$/.test(e.name) ? e.name : 'Error';
          clean.stack = undefined;
          sp.recordException(clean);
          sp.setStatus({ code: STATUS_ERROR, message: clean.message });
        });
      }
      throw e;
    } finally {
      const sp = span as SpanLike | undefined;
      if (sp) safe(() => sp.end());
    }
  };
}
