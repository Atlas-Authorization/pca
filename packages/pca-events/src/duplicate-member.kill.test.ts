import { describe, expect, it } from 'vitest';
import { parseEvent } from './index';

describe('a duplicate member in a webhook event is refused', () => {
  // JSON.parse keeps the last member while the signer's HMAC covered bytes whose first member read differently
  it('parseEvent', () => {
    const text = '{"id":"a","id":"b","type":"step_up.created","at":1,"grant_ref":"g","action":{"verb":"v","resource":"r"},"tier":2}';
    expect(() => parseEvent(text)).toThrow('strict JSON: duplicate key "id" (at offset 14)');
  });
});
