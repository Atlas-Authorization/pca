import { describe, expect, it } from 'vitest';
import { checkArgs } from './check';
import { ConfigError, expandEnv, parseConfig, parseConfigText } from './config';

const mcp = { ns: 'gh', tools: { read_issue: { policy: 'allow', effect: 'read', pin: 'p' } } };

describe('the configuration', () => {
  it('parses yaml and json to the same thing, with defaults', () => {
    const y = parseConfigText('mcp:\n  ns: gh\n  tools:\n    read_issue: { policy: allow, effect: read, pin: p }\n', 'yaml');
    const j = parseConfigText(JSON.stringify({ mcp }), 'json');
    expect(y).toEqual(j);
    expect(y.mode).toBe('enforce');
    expect(y.limits.maxRequestBytes).toBe(262_144);
  });

  it('an effect that is not declared is a write', () => {
    expect(parseConfig({ mcp: { ns: 'gh', tools: { t: { policy: 'approve' } } } }).mcp!.tools.t!.effect).toBe('write');
  });

  it.each([
    ['an unknown key', { mcp, surprise: 1 }],
    ['an unknown key in a rule', { mcp: { ns: 'gh', tools: { t: { policy: 'allow', effect: 'read', typo: 1 } } } }],
    ['a bad policy', { mcp: { ns: 'gh', tools: { t: { policy: 'maybe' } } } }],
    ['a bad namespace', { mcp: { ns: 'Bad-Name', tools: {} } }],
    ['neither mcp nor http', {}],
    ['verify mode without grants', { http: { upstream: 'http://x', mode: 'verify', routes: [{ method: 'GET', path: '/a', policy: 'allow' }] } }],
    ['an http section that maps nothing', { http: { upstream: 'http://x' } }],
    ['a non-http upstream', { http: { upstream: 'file:///etc/passwd', routes: [{ method: 'GET', path: '/a', policy: 'allow' }] } }],
    ['a forwarded PCA header', { http: { upstream: 'http://x', forwardHeaders: ['PCA-Action'], routes: [{ method: 'GET', path: '/a', policy: 'allow' }] } }],
  ])('refuses %s', (_n, doc) => {
    expect(() => parseConfig(doc)).toThrow(ConfigError);
  });

  it('refuses a duplicate yaml key instead of taking the last', () => {
    expect(() => parseConfigText('mcp:\n  ns: a\n  ns: b\n  tools: {}\n', 'yaml')).toThrow(ConfigError);
  });

  it('never defaults a missing environment variable to an empty credential', () => {
    expect(() => expandEnv('Bearer ${NOPE}', {})).toThrow(/NOPE/);
    expect(expandEnv('Bearer ${A}', { A: 'x' })).toBe('Bearer x');
  });
});

describe('the newer sections', () => {
  const base = { mcp: { ns: 'gh', tools: {} } };
  it('resources and prompts default to the read effect, tools to write', () => {
    const c = parseConfig({ mcp: { ns: 'gh', tools: { t: { policy: 'allow' } }, resources: { 'file:///a': { policy: 'allow', pin: 'p' } }, prompts: { p: { policy: 'approve' } } } });
    expect(c.mcp!.resources['file:///a']!.effect).toBe('read');
    expect(c.mcp!.prompts.p!.effect).toBe('read');
    expect(c.mcp!.tools.t!.effect).toBe('write');
  });
  it('state is durable unless memory is asked for by name', () => {
    expect(parseConfig(base).state).toEqual({ backend: 'file', dir: './pca-proxy-state' });
    expect(parseConfig({ ...base, state: { backend: 'memory' } }).state.backend).toBe('memory');
    expect(() => parseConfig({ ...base, state: { backend: 'sqlite' } })).toThrow(ConfigError);
  });
  it.each([
    ['a count limit with no period', { policy: 'allow', limit: '10' }],
    ['a money limit with no amount field', { policy: 'allow', limit: '$10/day' }],
    ['a limit that is not a limit', { policy: 'allow', limit: 'lots' }],
  ])('refuses %s', (_n, rule) => expect(() => parseConfig({ mcp: { ns: 'gh', tools: { t: rule } } })).toThrow(ConfigError));
  it('the HTTP listener needs named clients, or loopback and an explicit opt-out', () => {
    const l = (x: Record<string, unknown>) => parseConfig({ mcp: { ns: 'gh', tools: {}, listen: x } });
    expect(() => l({})).toThrow(ConfigError);
    expect(() => l({ host: '0.0.0.0', insecureNoAuth: true })).toThrow(ConfigError);
    expect(() => l({ clients: { a: { tokenEnv: 'T' } }, insecureNoAuth: true })).toThrow(ConfigError);
    expect(() => l({ clients: { a: { tokenEnv: 'T' } }, allowedOrigins: ['*'] })).toThrow(ConfigError);
    expect(l({ insecureNoAuth: true }).mcp!.listen!.host).toBe('127.0.0.1');
    expect(l({ clients: { a: { tokenEnv: 'T' } } }).mcp!.listen).toMatchObject({ port: 8789, path: '/mcp', maxSessions: 64 });
  });
});

describe('checkArgs', () => {
  const params = { id: { type: 'integer', min: 1, max: 9 }, 'a.b': { type: 'string', values: ['x', 'y'] }, tags: { type: 'set', values: ['p', 'q'], required: false } } as never;
  it('accepts a conforming call', () => expect(checkArgs(params, { id: 3, a: { b: 'x' }, tags: ['p'] }, 1000)).toBeUndefined());
  it.each([
    [{ id: 0, a: { b: 'x' } }, /outside/],
    [{ id: 3, a: { b: 'z' } }, /allowed values/],
    [{ id: 3 }, /required/],
    [{ id: 3, a: { b: 'x', c: 1 } }, /not a declared/],
    [{ id: 3, a: 'x' }, /must be an object/],
    [{ id: 3, a: { b: 'x' }, tags: ['p', 'p'] }, /repeated/],
    [{ id: 3, 'a.b': 'x' }, /not allowed/],
    [{ id: 3, a: { b: 'x' }, ['__proto__']: 1 }, /./],
  ])('refuses %j', (args, why) => expect(checkArgs(params, args, 1000)).toMatch(why));
  it('refuses a value outside the canonical JSON profile and an oversized one', () => {
    expect(checkArgs({ n: { type: 'string', required: false } } as never, { n: 1e300 }, 1000)).toMatch(/canonical/);
    expect(checkArgs({ n: { type: 'string' } } as never, { n: 'x'.repeat(2000) }, 100)).toMatch(/exceed/);
  });
});
