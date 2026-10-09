// Structure-aware fuzz of the UNMODIFIED reference verifier (native), for use with the ASan/UBSan build.
// Usage: node fuzz-open.mjs <binary> <n_per_class> [seedhex]
// Only sends inputs with a length-consistent trailing leaf-count byte, i.e. it deliberately AVOIDS the
// known upstream missing-length-check defect (documented separately) so that any further finding is
// attributable to the verifier's parsing of well-sized-but-malformed signatures.
// Classes (+ _masked variants, see below): random_body (all sig bytes random), random_cf (valid sig, cf_monom_actions randomized),
//          random_seeds (valid sig, seed-tree bytes randomized), random_hash (digest/salt randomized).
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
const [bin, nStr, seedHex] = process.argv.slice(2);
const n = Number(nStr);
const run = (mode, input) => spawnSync(bin, [mode], { input, maxBuffer: 1 << 30, encoding: 'utf8' });
const seed = seedHex ?? '03'.repeat(48);
const msg = Buffer.from('fuzz');
const g = run('gen', `${seed} ${msg.toString('hex')}\n`);
if (g.status !== 0) { console.log('gen failed', g.status, g.signal, g.stderr.slice(0, 2000)); process.exit(1); }
const [pk, , smHex] = g.stdout.trim().split(' ');
const sm = Buffer.from(smHex, 'hex');
const sig = sm.subarray(msg.length);
const HASH = 32, N8W = 32 * 34; // derived: sigMax 1329 = 2*32 + 32*34 + 11*16 + 1  (cat252/target45)
const classes = {
  random_body: () => { const s = randomBytes(sig.length); s[s.length - 1] = sig[sig.length - 1]; return s; },
  random_cf: () => { const s = Buffer.from(sig); randomBytes(N8W).copy(s, 2 * HASH); return s; },
  random_seeds: () => { const s = Buffer.from(sig); const o = 2 * HASH + N8W; randomBytes(s.length - 1 - o).copy(s, o); return s; },
  random_hash: () => { const s = Buffer.from(sig); randomBytes(2 * HASH).copy(s, 0); return s; },
};
// "_masked" classes clear the 4 padding bits of every cf_monom_actions row (defect #2) so that any
// FURTHER defect in parsing well-sized, padding-clean but otherwise random signatures can surface.
const mask = (s) => { for (let r = 0; r < 34; r++) s[2 * HASH + r * 32 + 31] &= 0x0f; return s; };
classes.random_body_masked = () => mask(classes.random_body());
classes.random_cf_masked = () => mask(classes.random_cf());
let total = 0, accepted = 0, crashed = 0;
for (const [name, mk] of Object.entries(classes)) {
  const lines = [];
  for (let i = 0; i < n; i++) lines.push(`${pk} ${Buffer.concat([msg, mk()]).toString('hex')}\n`);
  const r = run('open', lines.join(''));
  const rcs = r.stdout.trim().split('\n').filter(Boolean);
  const acc = rcs.filter((l) => l.startsWith('0 ')).length;
  const bad = r.status !== 0 || rcs.length !== n;
  if (bad) { crashed++; console.log(`${name}: ABNORMAL exit status=${r.status} signal=${r.signal} outputs=${rcs.length}/${n}\n${r.stderr.slice(0, 2500)}`); }
  total += rcs.length; accepted += acc;
  console.log(`${name}: ${rcs.length}/${n} verified, accepted=${acc}${bad ? ' (ABNORMAL)' : ''}`);
}
console.log(`TOTAL verified=${total} accepted=${accepted} abnormal_classes=${crashed}`);
