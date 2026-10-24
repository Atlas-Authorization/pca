import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadAdapter, pickExport } from './load';

const fx = (f: string): string => join(__dirname, '..', 'test', 'fixtures', f);

describe('pickExport', () => {
  const ad = { name: 'a', open: async () => ({}) };
  const fn = () => ad;
  it('default, adapter, createAdapter, and the same under a CommonJS default', () => {
    expect(pickExport({ default: ad })).toBe(ad);
    expect(pickExport({ default: fn })).toBe(fn);
    expect(pickExport({ adapter: ad })).toBe(ad);
    expect(pickExport({ createAdapter: fn })).toBe(fn);
    expect(pickExport({ default: { adapter: ad } })).toBe(ad);
    expect(pickExport({ default: { createAdapter: fn } })).toBe(fn);
  });
  it('prefers default, then adapter, then createAdapter; skips non-adapters', () => {
    const other = { name: 'b', open: async () => ({}) };
    expect(pickExport({ default: ad, adapter: other })).toBe(ad);
    expect(pickExport({ default: { x: 1 }, adapter: other })).toBe(other);
    expect(pickExport({ adapter: { open: 1 }, createAdapter: fn })).toBe(fn);
    expect(pickExport({ default: null, adapter: 'x' })).toBeUndefined();
    expect(pickExport({})).toBeUndefined();
  });
});

describe('loadAdapter', () => {
  it('built-ins by name, with options', async () => {
    expect((await loadAdapter('builtin:in-memory')).name).toMatch(/in-memory/);
    expect((await loadAdapter('builtin:bad-evicting', { capacity: '5' })).name).toContain('capacity 5');
    await expect(loadAdapter('builtin:nope')).rejects.toThrow(/unknown built-in adapter 'nope' \(known: in-memory, durable-file/);
    await expect(loadAdapter('builtin:toString')).rejects.toThrow(/unknown built-in/);
  });
  it('module exports: default object, factory with options, named adapter, CommonJS', async () => {
    expect((await loadAdapter(fx('default-object.mjs'))).name).toBe('fixture default object');
    expect((await loadAdapter(fx('factory.mjs'), { label: 'L' })).name).toBe('fixture factory L');
    expect((await loadAdapter(fx('factory.mjs'))).name).toBe('fixture factory none');
    expect((await loadAdapter(fx('named-adapter.mjs'))).name).toBe('fixture named');
    expect((await loadAdapter(fx('cjs-factory.cjs'))).name).toBe('fixture cjs');
  });
  it('refuses a module that exports no adapter, and an object without name', async () => {
    await expect(loadAdapter(fx('not-an-adapter.mjs'))).rejects.toThrow(/does not export a store adapter/);
    await expect(loadAdapter(fx('no-name.mjs'))).rejects.toThrow(/no-name.mjs: does not export a store adapter \(an object with a string 'name'/);
    await expect(loadAdapter(fx('factory-undefined.mjs'))).rejects.toThrow(TypeError);
    await expect(loadAdapter(fx('factory-no-open.mjs'))).rejects.toThrow(TypeError);
    await expect(loadAdapter(fx('missing.mjs'))).rejects.toThrow();
  });
});
