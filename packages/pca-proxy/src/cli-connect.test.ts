import { describe, expect, it } from 'vitest';
import { parseArgs } from './cli';
import { ConfigError } from './config';

describe('--connect and --grant on the command line', () => {
  it('takes the setup token when one follows, and nothing when it does not (resume)', () => {
    const tok = 'pcs1.abc';
    const a = parseArgs(['mcp', '--observe', '--connect', tok, '--', 'npx', 'server']);
    expect(a.flags.get('connect')).toBe(tok);
    expect(a.rest).toEqual(['npx', 'server']);
    expect(parseArgs(['mcp', '--connect', '--enforce', '--grant', 'grant.json']).flags.get('connect')).toBe(true);
    expect(parseArgs(['mcp', `--connect=${tok}`]).flags.get('connect')).toBe(tok);
  });
  it('reads --grant, --signer and --include-params as values, and refuses one without', () => {
    const a = parseArgs(['mcp', '--grant', 'g.json', '--signer', 'S', '--include-params', 'amount,qty']);
    expect([a.flags.get('grant'), a.flags.get('signer'), a.flags.get('include-params')]).toEqual(['g.json', 'S', 'amount,qty']);
    expect(() => parseArgs(['mcp', '--grant'])).toThrow(ConfigError);
  });
});
