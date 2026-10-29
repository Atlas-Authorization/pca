/**
 * Test doubles. Nothing here is for production: the in-memory store keeps tokens in plaintext in process
 * memory, so a `TokenVault` only accepts it with `strict: false`.
 */
export { InMemoryConnectionStore } from './store';
