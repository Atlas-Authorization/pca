import { describe, expect, it } from 'vitest';
import { USAGE, main, parseDoctorArgs } from './cli';

describe('parseDoctorArgs: check groups', () => {
  it('drops empty entries from --only and --skip', () => {
    expect(parseDoctorArgs(['--only', 'clock,,store']).only).toEqual(['clock', 'store']);
    expect(parseDoctorArgs(['--skip', ',clock,']).only).toEqual(['store', 'proxy', 'suites', 'caveats']);
  });

  it('names the unknown groups, or says none were given', () => {
    expect(() => parseDoctorArgs(['--only', 'a,b'])).toThrow('--only: unknown check group(s) a, b');
    expect(() => parseDoctorArgs(['--skip', 'clock,zzz'])).toThrow('--skip: unknown check group(s) zzz');
    expect(() => parseDoctorArgs(['--only', ''])).toThrow('--only: unknown check group(s) (none given)');
    expect(() => parseDoctorArgs(['--only'])).toThrow('--only: unknown check group(s) (none given)');
    expect(() => parseDoctorArgs(['--skip', ','])).toThrow('--skip: unknown check group(s) (none given)');
  });
});

describe('parseDoctorArgs: numbers', () => {
  it('accepts zero and rejects a missing, empty or non-finite value', () => {
    expect(parseDoctorArgs(['--max-skew-ms', '0']).flags.clock).toEqual({ maxSkewMs: 0 });
    expect(parseDoctorArgs(['--max-skew-ms', '1500.5']).flags.clock).toEqual({ maxSkewMs: 1500.5 });
    for (const argv of [['--max-skew-ms'], ['--max-skew-ms', ''], ['--max-skew-ms', 'x'], ['--max-skew-ms', 'Infinity'], ['--trusted-proxy-count', ''], ['--proxy-hops']]) {
      expect(() => parseDoctorArgs(argv)).toThrow(`${argv[0]} needs a number`);
    }
  });
});

describe('parseDoctorArgs: individual flags', () => {
  it('--config, --reference, --pca-dir', () => {
    const a = parseDoctorArgs(['--config', 'c.json', '--reference', 'local', '--pca-dir', '/app']);
    expect(a.config).toBe('c.json');
    expect(a.flags).toEqual({ clock: { referenceUrl: 'local' }, verifier: { pcaDir: '/app' } });
  });

  it('--reference keeps an earlier --max-skew-ms', () => {
    expect(parseDoctorArgs(['--max-skew-ms', '5', '--reference', 'https://r']).flags.clock).toEqual({ maxSkewMs: 5, referenceUrl: 'https://r' });
  });

  it('--store-option needs k=v with a non-empty key, and keeps everything after the first =', () => {
    const msg = '--store-option needs k=v';
    for (const argv of [['--store-option'], ['--store-option', 'novalue'], ['--store-option', '=v']]) expect(() => parseDoctorArgs(argv)).toThrow(msg);
    expect(parseDoctorArgs(['--store-option', 'k=a=b', '--store-option', 'j=']).flags.store).toEqual({ options: { k: 'a=b', j: '' } });
    expect(parseDoctorArgs(['--store', 'm.mjs', '--store-option', 'k=v']).flags.store).toEqual({ adapter: 'm.mjs', options: { k: 'v' } });
  });

  it('--proxy-header is case-insensitive, accepts exactly the three headers, and keeps the other proxy flags', () => {
    for (const h of ['x-forwarded-for', 'forwarded', 'x-real-ip']) expect(parseDoctorArgs(['--proxy-header', h]).flags.proxy).toEqual({ header: h });
    expect(parseDoctorArgs(['--trusted-proxy-count', '1', '--proxy-header', 'X-Real-IP']).flags.proxy).toEqual({ trustedProxyCount: 1, header: 'x-real-ip' });
    for (const argv of [['--proxy-header', 'x-bogus'], ['--proxy-header'], ['--proxy-header', '']]) {
      expect(() => parseDoctorArgs(argv)).toThrow('--proxy-header must be x-forwarded-for, forwarded or x-real-ip');
    }
  });

  it('-h and --help set the help flag; nothing else does', () => {
    expect(parseDoctorArgs(['-h']).help).toBe(true);
    expect(parseDoctorArgs(['--help']).help).toBe(true);
    expect(parseDoctorArgs([]).help).toBe(false);
  });

  it('an unknown argument is named', () => {
    expect(() => parseDoctorArgs(['--bogus'])).toThrow('unknown argument --bogus');
  });
});

describe('main', () => {
  it('prints the usage and exits 0 for -h and --help, running nothing', async () => {
    for (const flag of ['-h', '--help']) {
      const out: string[] = [];
      const err: string[] = [];
      expect(await main([flag], {}, (s) => out.push(s), (s) => err.push(s))).toBe(0);
      expect(out).toEqual([USAGE]);
      expect(err).toEqual([]);
    }
  });

  it('prints the scrubbed error and the usage on stderr and exits 2', async () => {
    const out: string[] = [];
    const err: string[] = [];
    expect(await main(['--bogus'], {}, (s) => out.push(s), (s) => err.push(s))).toBe(2);
    expect(out).toEqual([]);
    expect(err).toEqual([`unknown argument --bogus\n\n${USAGE}`]);
    const err2: string[] = [];
    expect(await main([], { PCA_PQ_PINS: '{broken' }, () => undefined, (s) => err2.push(s))).toBe(2);
    expect(err2).toEqual([`PCA_PQ_PINS is not valid JSON\n\n${USAGE}`]);
    const err3: string[] = [];
    expect(await main(['--config', '/nonexistent/token=abc123xyz.json'], {}, () => undefined, (s) => err3.push(s))).toBe(2);
    expect(err3[0]).toContain('token=[redacted]');
    expect(err3[0]).not.toContain('abc123xyz');
  });
});
