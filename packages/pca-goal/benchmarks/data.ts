import { generateCases, recordFixtures, type BenchCase } from '../src/bench';
import type { Recordings } from '../src/interpret';

export const DOMAINS = ['payments', 'email', 'calendar_travel', 'code_repos', 'data_access'] as const;
export const MAIN_N = 1000;
export const HOSTILE_N = 200;
export const SEED = 7;

/** Deterministic benchmark: the main split plus the hostile corpus (every case carries an attack). */
export const mainCases = (d: string): BenchCase[] => generateCases(d, MAIN_N, SEED, { hostileEvery: 5 });
export const hostileCases = (d: string): BenchCase[] => generateCases(d, HOSTILE_N, SEED + 1000, { hostileOnly: true });
export const fixturesFor = (d: string): Recordings => recordFixtures([...mainCases(d), ...hostileCases(d)]);
