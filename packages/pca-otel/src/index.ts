/**
 * OpenTelemetry instrumentation for Proof-Carrying Authority.
 *
 * Wrap a verification guard so every decision emits a span (decision / tier / risk / verb / resource)
 * and two metrics (a `pca.verifications` counter and a `pca.verify.risk` histogram). Pass in your own
 * real OpenTelemetry `Tracer` / `Meter` and ours are structurally compatible — we never import the SDK,
 * so this package has no hard dependency on `@opentelemetry/api` (declare it as an optional peer).
 *
 * Generic over the result shape: we only read a small structural slice of the guard's verdict, so this
 * does NOT depend on `@atlasauth/backend` or any concrete verdict type.
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

/** The first deny reason, if any — used for the span's error message and the `pca.reason` attribute. */
function firstReason(result: GuardResultLike): string | undefined {
  return result.verdict?.reasons?.[0];
}

/**
 * Map a guard result to OpenTelemetry span attributes. Undefined fields are omitted, so a span only
 * carries the dimensions the verdict actually has. `pca.reason` is added on deny only.
 */
export function pcaSpanAttributes(result: GuardResultLike): Record<string, string | number | boolean> {
  const attrs: Record<string, string | number | boolean> = {
    'pca.decision': result.ok ? 'allow' : 'deny',
  };
  if (result.status !== undefined) attrs['pca.status'] = result.status;

  const tier = result.verdict?.requiredThreshold?.t;
  if (tier !== undefined) attrs['pca.tier'] = tier;

  const risk = result.verdict?.r;
  if (risk !== undefined) attrs['pca.risk'] = risk;

  const verb = result.pcactn?.action?.verb;
  if (verb !== undefined) attrs['pca.verb'] = verb;

  const resource = result.pcactn?.action?.resource;
  if (resource !== undefined) attrs['pca.resource'] = resource;

  if (!result.ok) {
    const reason = firstReason(result);
    if (reason !== undefined) attrs['pca.reason'] = reason;
  }
  return attrs;
}

/** Options for {@link instrumentGuard}. Omit both `tracer` and `meter` for a pure no-op pass-through. */
export interface InstrumentGuardOptions {
  tracer?: TracerLike;
  meter?: MeterLike;
  spanName?: string;
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

  return async (req: Req): Promise<GuardResultLike> => {
    const span = tracer?.startSpan(spanName);
    try {
      const result = await guard(req);

      if (span) {
        const attrs = pcaSpanAttributes(result);
        for (const [k, v] of Object.entries(attrs)) span.setAttribute(k, v);
        if (result.ok) {
          span.setStatus({ code: STATUS_OK });
        } else {
          const reason = firstReason(result);
          span.setStatus(reason !== undefined ? { code: STATUS_ERROR, message: reason } : { code: STATUS_ERROR });
        }
      }

      const decision = result.ok ? 'allow' : 'deny';
      counter?.add(1, { decision });
      const risk = result.verdict?.r;
      if (histogram && risk !== undefined) histogram.record(risk, { decision });

      return result;
    } catch (e) {
      if (span) {
        span.recordException(e);
        span.setStatus({ code: STATUS_ERROR, message: e instanceof Error ? e.message : String(e) });
      }
      throw e;
    } finally {
      span?.end();
    }
  };
}
