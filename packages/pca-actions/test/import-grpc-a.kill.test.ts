// The .proto parser: a quoted "stream" in the response position is a string token, never the stream keyword.
import { describe, expect, it } from 'vitest';
import { ActionKitError, parseProto } from '../src';

describe('proto rpc response', () => {
  it('does not treat a quoted "stream" as the stream keyword', () => {
    let caught: unknown;
    try { parseProto('service S { rpc R(A) returns ("stream" B); }'); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(ActionKitError);
    expect((caught as ActionKitError).code).toBe('bad_source');
    expect((caught as Error).message).toBe("proto parse error: expected an identifier near 'stream'");
  });
});
