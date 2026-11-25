/** Constructor-time typing of optional policy allowlists: absent/null means "no list"; anything else must be an array of strings. */
export function assertOptionalStringList(ctor: string, key: string, v: unknown): void {
  if (v === undefined || v === null) return;
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) throw new TypeError(`${ctor}: policy.${key} must be an array of strings`);
}

/** Largest attestation JSON segment parsed at all (16 MiB): bigger input is refused before JSON.parse allocates for it. */
export const MAX_ATTEST_JSON_BYTES = 16 * 1024 * 1024;
export function assertJsonSize(len: number): void {
  if (len > MAX_ATTEST_JSON_BYTES) throw new Error('input too large');
}
