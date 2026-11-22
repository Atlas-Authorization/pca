import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CAVEAT_REMEDIATION, DEFAULT_REQUIRED, checkEnforcement, checkRootCaveats, compareVersion, loadPca, probeDecision, type LoadedPca, type PcaLike } from './caveats';

describe('compareVersion', () => {
  it('orders by major.minor.patch, ignores a fourth part and compares unparseable parts below any number', () => {
    expect(compareVersion('1.2.3.4', '1.2.3.5')).toBe(0);
    expect(compareVersion('1.2.3', '1.2.4')).toBe(-1);
    expect(compareVersion('1.2.4', '1.2.3')).toBe(1);
    expect(compareVersion('0.4.1', 'garbage')).toBe(1);
    expect(compareVersion('garbage', '0.4.1')).toBe(-1);
    expect(compareVersion('garbage', 'garbage')).toBe(0);
    expect(compareVersion('1.2', '1.2.0')).toBe(-1);
  });
});

describe('loadPca', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const tmp = (): string => {
    const d = mkdtempSync(join(tmpdir(), 'pca-doctor-kill-'));
    dirs.push(d);
    return d;
  };

  it('loads the copy installed in the nearest ancestor and not the doctor\'s own', () => {
    const root = tmp();
    const pkg = join(root, 'node_modules', '@atlasauth', 'pca');
    mkdirSync(pkg, { recursive: true });
    writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@atlasauth/pca', version: '9.9.9', main: 'index.js' }));
    writeFileSync(join(pkg, 'index.js'), 'module.exports = { marker: 7 };');
    const sub = join(root, 'a', 'b');
    mkdirSync(sub, { recursive: true });
    for (const dir of [root, sub]) {
      const l = loadPca(dir);
      expect(l.version).toBe('9.9.9');
      expect(l.module).toEqual({ marker: 7 });
      expect(l.path).toBe(realpathSync(pkg));
    }
  });

  it('throws when no ancestor installs the package', () => {
    const d = tmp();
    expect(() => loadPca(d)).toThrow(`@atlasauth/pca is not installed in ${d} or any parent node_modules`);
  });

  it('without a directory loads the doctor\'s own copy', () => {
    const l = loadPca();
    expect(l.version).not.toBe('9.9.9');
    expect(typeof l.module.decide).toBe('function');
  });
});

/** A scripted library: records the arguments and decides by the root caveat and the amount. */
function fakePca(allow: { over?: boolean; under?: boolean; unknown?: boolean }, reasons: unknown = ['r1', 2]) {
  const log: { mint?: unknown; root?: unknown; delegate?: unknown[]; decide: unknown[] } = { decide: [] };
  let keys = 0;
  const m: PcaLike = {
    DEFAULT_RISK_POLICY: 'RISK_POLICY',
    generateKeyPair: () => ({ publicKey: `pub${keys}`, secretKey: `sec${keys++}` }),
    encodeKey: (k: string) => `enc(${k})`,
    mintGrant: (a: unknown) => {
      log.mint = a;
      return { grant: { caveats: [{ type: 'base' }] } };
    },
    mintRoot: (a: { caveats: Record<string, unknown>[] }) => {
      log.root = a;
      return { rootCaveat: a.caveats[a.caveats.length - 1] };
    },
    delegate: (...a: unknown[]) => {
      log.delegate = a;
      return 'TASK';
    },
    decide: (a: { grant: { rootCaveat: { type: string } }; action: { action: { params: { amount: number } } } }) => {
      log.decide.push(a);
      const type = a.grant.rootCaveat.type;
      const ok = type === 'max_spend' ? (a.action.action.params.amount === 150 ? allow.over : allow.under) : allow.unknown;
      return { releaseGuardianShare: ok === true, reasons };
    },
  };
  return { m, log };
}
const loaded = (m: PcaLike, version = '0.4.1'): LoadedPca => ({ module: m, version, path: '/p/pca' });

describe('probeDecision', () => {
  it('mints a root with the extra caveat and decides one payment with exact inputs', () => {
    const { m, log } = fakePca({ under: true });
    const r = probeDecision(m, { type: 'max_spend', usd: 100 }, 50, 1000);
    expect(r).toEqual({ allowed: true, reasons: ['r1', '2'] });
    expect(log.mint).toEqual({
      principalSecret: 'sec0',
      principalPublic: 'enc(pub0)',
      holder: 'enc(pub0)',
      goal: 'pca-doctor root caveat probe',
      envelope: {
        predicates: [{ verb: 'pay', resource: 'invoice:*' }],
        caveats: [{ type: 'expires', at: 1000 + 3_600_000 }],
        agent_binding: {},
        risk_policy: 'RISK_POLICY',
      },
    });
    expect(log.root).toEqual({ principalSecret: 'sec0', principalPublic: 'enc(pub0)', holder: 'enc(pub0)', caveats: [{ type: 'base' }, { type: 'max_spend', usd: 100 }] });
    expect(log.delegate).toEqual([{ rootCaveat: { type: 'max_spend', usd: 100 } }, 'enc(pub1)', [], 'sec0']);
    expect(log.decide).toEqual([
      {
        grant: { rootCaveat: { type: 'max_spend', usd: 100 } },
        chain: [{ rootCaveat: { type: 'max_spend', usd: 100 } }, 'TASK'],
        action: { action: { verb: 'pay', resource: 'invoice:42', params: { amount: 50, currency: 'usd' }, reversibility_class: 'reversible' } },
        risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 },
        budget: { B: 1e9, tau: 1000, asOf: 1000 },
        now: 1000,
      },
    ]);
  });

  it('a denial and non-array reasons give allowed=false and no reasons', () => {
    const { m } = fakePca({ under: false }, 'not an array');
    expect(probeDecision(m, { type: 'max_spend', usd: 100 }, 50, 1)).toEqual({ allowed: false, reasons: [] });
  });
});

describe('checkRootCaveats', () => {
  const where = '@atlasauth/pca 0.4.1 at /p/pca';

  it('passes with exact detail when 150 is denied, 50 allowed and the unknown type denied', () => {
    const { m, log } = fakePca({ under: true }, ['x']);
    const r = checkRootCaveats({}, { loadPca: () => loaded(m) });
    expect(r).toStrictEqual({
      id: 'caveats.root',
      status: 'pass',
      detail: `${where}: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)`,
      observed: {
        version: '0.4.1',
        over: { allowed: false, reasons: ['x'] },
        under: { allowed: true, reasons: ['x'] },
        unknown: { allowed: false, reasons: ['x'] },
      },
    });
    const sent = log.decide.map((d) => (d as { grant: { rootCaveat: unknown }; action: { action: { params: { amount: number } } } }));
    expect(sent.map((d) => [d.grant.rootCaveat, d.action.action.params.amount])).toEqual([
      [{ type: 'max_spend', usd: 100 }, 150],
      [{ type: 'max_spend', usd: 100 }, 50],
      [{ type: 'pca-doctor-unknown-caveat' }, 50],
    ]);
  });

  it('passes the configured directory to the loader', () => {
    const { m } = fakePca({ under: true });
    let got: string | undefined;
    checkRootCaveats({ verifier: { pcaDir: '/app' } }, { loadPca: (d) => ((got = d), loaded(m)) });
    expect(got).toBe('/app');
  });

  it('a load failure names the directory when one is configured and omits it otherwise', () => {
    const boom = (): LoadedPca => {
      throw new Error('boom');
    };
    expect(checkRootCaveats({ verifier: { pcaDir: '/app' } }, { loadPca: boom })).toStrictEqual({
      id: 'caveats.root',
      status: 'fail',
      detail: 'cannot load @atlasauth/pca from /app: boom',
      remediation: CAVEAT_REMEDIATION,
    });
    expect(checkRootCaveats({}, { loadPca: boom })).toStrictEqual({ id: 'caveats.root', status: 'fail', detail: 'cannot load @atlasauth/pca: boom', remediation: CAVEAT_REMEDIATION });
    expect(checkRootCaveats({ verifier: {} }, { loadPca: boom }).detail).toBe('cannot load @atlasauth/pca: boom');
  });

  it('fails an old version without probing, but accepts exactly 0.4.1', () => {
    const { m, log } = fakePca({ under: true });
    expect(checkRootCaveats({}, { loadPca: () => loaded(m, '0.4.0') })).toStrictEqual({
      id: 'caveats.root',
      status: 'fail',
      detail: '@atlasauth/pca 0.4.0 at /p/pca: root caveats outside the envelope are NOT enforced before 0.4.1 (legacy behaviour)',
      remediation: CAVEAT_REMEDIATION,
    });
    expect(log.decide).toHaveLength(0);
    expect(checkRootCaveats({}, { loadPca: () => loaded(m, '0.4.1') }).status).toBe('pass');
  });

  it('a probe that throws is a fail with the message', () => {
    const { m } = fakePca({ under: true });
    m.decide = () => {
      throw new Error('kaboom');
    };
    expect(checkRootCaveats({}, { loadPca: () => loaded(m) })).toStrictEqual({
      id: 'caveats.root',
      status: 'fail',
      detail: `${where}: the enforcement probe could not run: kaboom`,
      remediation: CAVEAT_REMEDIATION,
    });
  });

  it('fails when only the over-limit payment is allowed, or only the unknown caveat is allowed', () => {
    const a = fakePca({ over: true, under: true });
    const ra = checkRootCaveats({}, { loadPca: () => loaded(a.m) });
    expect(ra).toMatchObject({ id: 'caveats.root', status: 'fail', detail: `${where}: a root caveat was NOT enforced (max_spend 100 allowed a 150 payment)`, remediation: CAVEAT_REMEDIATION });
    expect(ra.observed).toBeDefined();
    const b = fakePca({ unknown: true, under: true });
    expect(checkRootCaveats({}, { loadPca: () => loaded(b.m) })).toMatchObject({
      status: 'fail',
      detail: `${where}: a root caveat was NOT enforced (an unknown root caveat type was allowed)`,
    });
  });

  it('warns when even the control payment is denied, listing the reasons', () => {
    const { m } = fakePca({}, ['a', 'b']);
    const r = checkRootCaveats({}, { loadPca: () => loaded(m) });
    expect(r).toMatchObject({ id: 'caveats.root', status: 'warn', detail: `${where}: inconclusive: the control payment within the root max_spend was denied too (a; b)` });
    expect('remediation' in r).toBe(false);
  });
});

describe('checkEnforcement', () => {
  it('skips without configuration, exact message', () => {
    expect(checkEnforcement({})).toStrictEqual({ id: 'verifier.enforcement', status: 'skip', detail: 'no verifier configuration given (config verifier.*)' });
  });

  it('fails on insecureAllowUnenforced', () => {
    expect(checkEnforcement({ verifier: { insecureAllowUnenforced: true } })).toStrictEqual({
      id: 'verifier.enforcement',
      status: 'fail',
      detail: 'requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny',
      remediation: 'Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).',
    });
  });

  it('warns on a require list that drops defaults, naming exactly the missing ones', () => {
    expect(checkEnforcement({ verifier: { require: ['replay', 'audience', 'extra'] } })).toStrictEqual({
      id: 'verifier.enforcement',
      status: 'warn',
      detail: 'the require list drops default check(s): counter_format, revocation, plan_root_authorized, validity, grant_ref_bound',
      remediation: `Keep every default required check (${DEFAULT_REQUIRED.join(', ')}) and add to it.`,
    });
  });

  it('passes with the full defaults plus extras (listing them) and with no list', () => {
    expect(checkEnforcement({ verifier: { require: [...DEFAULT_REQUIRED, 'extra'] } })).toStrictEqual({
      id: 'verifier.enforcement',
      status: 'pass',
      detail: `require = ${DEFAULT_REQUIRED.join(', ')}, extra`,
    });
    expect(checkEnforcement({ verifier: {} })).toStrictEqual({ id: 'verifier.enforcement', status: 'pass', detail: 'default required checks; insecureAllowUnenforced off' });
  });
});
