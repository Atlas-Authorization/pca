import { describe, expect, it } from 'vitest';
import { BlueprintRegistry, BreakGlassRegistry, LeaseRegistry, MemoryBlueprintStore, memoryLeaseKv } from './index';

describe('revocation, kill and break-glass state has no process-local default', () => {
  it('a registry without a store is refused at construction', () => {
    expect(() => new LeaseRegistry({ authorities: [] }, undefined as never)).toThrow(TypeError);
    expect(() => new LeaseRegistry({ authorities: [] }, undefined as never)).toThrow('a durable key-value store is required');
    expect(() => new LeaseRegistry({ authorities: [] }, {} as never)).toThrow(TypeError);
    expect(() => new BreakGlassRegistry({ authorities: [], reviewers: [] }, undefined as never)).toThrow('a durable key-value store is required');
    expect(() => new BreakGlassRegistry({ authorities: [], reviewers: [] }, { get: async () => undefined } as never)).toThrow(TypeError);
    expect(() => new BlueprintRegistry([], undefined as never)).toThrow('a durable BlueprintStore is required');
    expect(() => new BlueprintRegistry([], { get: async () => undefined, put: async () => {} } as never)).toThrow(TypeError);
  });
  it('a store of the right shape is accepted', () => {
    expect(() => new LeaseRegistry({ authorities: [] }, memoryLeaseKv())).not.toThrow();
    expect(() => new BreakGlassRegistry({ authorities: [], reviewers: [] }, memoryLeaseKv())).not.toThrow();
    expect(() => new BlueprintRegistry([], new MemoryBlueprintStore())).not.toThrow();
  });
});
