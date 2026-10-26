/**
 * Test doubles. `TransparencyService` is an in-memory reference log (it recomputes the Merkle tree on every
 * registration and loses everything on restart): use it to produce receipts for tests and demos, never as a
 * production transparency service. Run a real SCITT Transparency Service in production and verify its receipts
 * with the main entry point.
 */
export { TransparencyService, registerStatement } from './index';
