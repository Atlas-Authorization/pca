// gRPC importer, request-type resolution and field requiredness: cases driven by binary descriptors, whose names and
// field-behavior codes can take values the .proto text syntax cannot express.
import { describe, expect, it } from 'vitest';
import { importGrpc } from '../src';
import { descriptorSet } from './pb';

describe('importGrpc (descriptor): resolution and field behavior', () => {
  it('a bare request type with no package never resolves through a stray scope segment', () => {
    const r = importGrpc(descriptorSet({
      pkg: '',
      messages: [{ name: 'Stryker was here.X', fields: [{ name: 'v', num: 1, type: 9 }] }],
      services: [{ name: 'S', methods: [{ name: 'Call', input: 'X', output: 'X' }] }],
    }), { ns: 't' });
    expect(r.defs).toHaveLength(1);
    expect(r.defs[0]!.params).toEqual({});
    expect(r.todo).toEqual([{ where: 'S/Call', code: 'unknown_type', message: "request type 'X' is not defined in the source (no parameters)" }]);
  });

  it('a field with an unrecognised behavior code is kept and optional', () => {
    const r = importGrpc(descriptorSet({
      pkg: 'p',
      messages: [{ name: 'Req', fields: [{ name: 'u', num: 1, type: 9, behavior: [9] }] }],
      services: [{ name: 'S', methods: [{ name: 'Call', input: '.p.Req', output: '.p.Req' }] }],
    }), { ns: 't' });
    expect(r.defs[0]!.params).toEqual({ u: { type: 'string', required: false } });
    expect(r.todo).toEqual([]);
  });

  it('only a field that declares REQUIRED is required, whatever its name', () => {
    const r = importGrpc(descriptorSet({
      pkg: 'p',
      messages: [{ name: 'Req', fields: [{ name: 'Stryker was here', num: 1, type: 9 }] }],
      services: [{ name: 'S', methods: [{ name: 'Call', input: '.p.Req', output: '.p.Req' }] }],
    }), { ns: 't' });
    expect(r.defs[0]!.params).toEqual({ Stryker_was_here: { type: 'string', required: false } });
  });
});
