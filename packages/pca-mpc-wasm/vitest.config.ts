import { defineConfig } from 'vitest/config';

// The curve core runs in Node (reads the .wasm off disk and instantiates it synchronously).
export default defineConfig({
  test: { environment: 'node' },
});
