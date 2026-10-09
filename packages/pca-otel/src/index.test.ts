import { describe, expect, it } from 'vitest';

import {
  type CounterLike,
  type GuardResultLike,
  type HistogramLike,
  type MeterLike,
  type SpanLike,
  type TracerLike,
  instrumentGuard,
  pcaSpanAttributes,
} from './index';

// ── Fakes that record every call ──────────────────────────────────────────────

interface SpanCall {
  name: string;
  attrs: Record<string, string | number | boolean>;
  status?: { code: number; message?: string };
  exceptions: unknown[];
  ended: boolean;
}

class FakeSpan implements SpanLike {
  readonly call: SpanCall;
  constructor(name: string) {
    this.call = { name, attrs: {}, exceptions: [], ended: false };
  }
  setAttribute(k: string, v: string | number | boolean): void {
    this.call.attrs[k] = v;
  }
  setStatus(s: { code: number; message?: string }): void {
    this.call.status = s;
  }
  recordException(e: unknown): void {
    this.call.exceptions.push(e);
  }
  end(): void {
    this.call.ended = true;
  }
}

class FakeTracer implements TracerLike {
  readonly spans: FakeSpan[] = [];
  startSpan(name: string): SpanLike {
    const span = new FakeSpan(name);
    this.spans.push(span);
    return span;
  }
}

class FakeCounter implements CounterLike {
  readonly adds: { n: number; attrs?: Record<string, string | number | boolean> }[] = [];
  add(n: number, attrs?: Record<string, string | number | boolean>): void {
    this.adds.push({ n, ...(attrs !== undefined ? { attrs } : {}) });
  }
}

class FakeHistogram implements HistogramLike {
  readonly records: { n: number; attrs?: Record<string, string | number | boolean> }[] = [];
  record(n: number, attrs?: Record<string, string | number | boolean>): void {
    this.records.push({ n, ...(attrs !== undefined ? { attrs } : {}) });
  }
}

class FakeMeter implements MeterLike {
  readonly counters: Record<string, FakeCounter> = {};
  readonly histograms: Record<string, FakeHistogram> = {};
  createCounter(name: string): CounterLike {
    const c = new FakeCounter();
    this.counters[name] = c;
    return c;
  }
  createHistogram(name: string): HistogramLike {
    const h = new FakeHistogram();
    this.histograms[name] = h;
    return h;
  }
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ALLOW: GuardResultLike = {
  ok: true,
  status: 200,
  verdict: { allow: true, r: 0.2, requiredThreshold: { t: 1 } },
  pcactn: { action: { verb: 'stripe.refund', resource: 'c:1' } },
};

const DENY: GuardResultLike = {
  ok: false,
  status: 403,
  verdict: { allow: false, r: 0.9, requiredThreshold: { t: 3 }, reasons: ['risk too high', 'stale proof'] },
  pcactn: { action: { verb: 'stripe.refund', resource: 'c:1' } },
};

// ── Tests ───────────────────────────────────────────────────────────────────

describe('instrumentGuard with a tracer', () => {
  it('creates one allow span, ends it, and returns the same result', async () => {
    const tracer = new FakeTracer();
    const wrapped = instrumentGuard(async () => ALLOW, { tracer });

    const result = await wrapped({});

    expect(result).toBe(ALLOW);
    expect(tracer.spans).toHaveLength(1);
    const span = tracer.spans[0]!;
    expect(span.call.name).toBe('pca.verify');
    expect(span.call.attrs['pca.decision']).toBe('allow');
    expect(span.call.attrs['pca.verb']).toBe('stripe.refund');
    expect(span.call.status).toEqual({ code: 1 });
    expect(span.call.ended).toBe(true);
  });

  it('sets an error status with the first reason on a deny', async () => {
    const tracer = new FakeTracer();
    const wrapped = instrumentGuard(async () => DENY, { tracer });

    const result = await wrapped({});

    expect(result).toBe(DENY);
    const span = tracer.spans[0]!;
    expect(span.call.attrs['pca.decision']).toBe('deny');
    expect(span.call.attrs['pca.reason']).toBe('risk too high');
    expect(span.call.status).toEqual({ code: 2, message: 'risk too high' });
    expect(span.call.ended).toBe(true);
  });

  it('honours a custom span name', async () => {
    const tracer = new FakeTracer();
    const wrapped = instrumentGuard(async () => ALLOW, { tracer, spanName: 'refund.verify' });
    await wrapped({});
    expect(tracer.spans[0]!.call.name).toBe('refund.verify');
  });

  it('records the exception, ends the span, and re-throws when the guard throws', async () => {
    const tracer = new FakeTracer();
    const boom = new Error('verifier exploded');
    const wrapped = instrumentGuard(async () => {
      throw boom;
    }, { tracer });

    await expect(wrapped({})).rejects.toBe(boom);
    const span = tracer.spans[0]!;
    expect(span.call.exceptions).toEqual([boom]);
    expect(span.call.status).toEqual({ code: 2, message: 'verifier exploded' });
    expect(span.call.ended).toBe(true);
  });
});

describe('instrumentGuard with a meter', () => {
  it('increments the verifications counter and records the risk histogram', async () => {
    const meter = new FakeMeter();
    const wrapped = instrumentGuard(async () => ALLOW, { meter });

    await wrapped({});

    const counter = meter.counters['pca.verifications']!;
    expect(counter.adds).toEqual([{ n: 1, attrs: { decision: 'allow' } }]);
    const histogram = meter.histograms['pca.verify.risk']!;
    expect(histogram.records).toEqual([{ n: 0.2, attrs: { decision: 'allow' } }]);
  });

  it('tags a deny decision on the counter', async () => {
    const meter = new FakeMeter();
    const wrapped = instrumentGuard(async () => DENY, { meter });
    await wrapped({});
    expect(meter.counters['pca.verifications']!.adds).toEqual([{ n: 1, attrs: { decision: 'deny' } }]);
  });
});

describe('instrumentGuard with neither tracer nor meter', () => {
  it('is a transparent pass-through', async () => {
    const wrapped = instrumentGuard(async () => ALLOW);
    const result = await wrapped({});
    expect(result).toBe(ALLOW);
  });

  it('still re-throws without error', async () => {
    const boom = new Error('nope');
    const wrapped = instrumentGuard(async () => {
      throw boom;
    });
    await expect(wrapped({})).rejects.toBe(boom);
  });
});

describe('pcaSpanAttributes', () => {
  it('maps every present field', () => {
    expect(pcaSpanAttributes(ALLOW)).toEqual({
      'pca.decision': 'allow',
      'pca.status': 200,
      'pca.tier': 1,
      'pca.risk': 0.2,
      'pca.verb': 'stripe.refund',
      'pca.resource': 'c:1',
    });
  });

  it('adds pca.reason only on a deny', () => {
    const attrs = pcaSpanAttributes(DENY);
    expect(attrs['pca.decision']).toBe('deny');
    expect(attrs['pca.reason']).toBe('risk too high');
  });

  it('omits undefined fields', () => {
    const attrs = pcaSpanAttributes({ ok: true });
    expect(attrs).toEqual({ 'pca.decision': 'allow' });
    expect('pca.status' in attrs).toBe(false);
    expect('pca.risk' in attrs).toBe(false);
    expect('pca.reason' in attrs).toBe(false);
  });
});
