import { defineConfig } from 'vitest/config';

export default defineConfig({ test: { globalSetup: ['./scripts/vitest-circuit-setup.mjs'] } });
