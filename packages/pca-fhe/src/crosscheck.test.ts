import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import {
  type EvalKeys,
  type FheKeyset,
  decryptVerdict,
  encryptRiskInputs,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
} from './index';

const TIMEOUT = 600_000;
const execFileAsync = promisify(execFile);
const here = __dirname;
const helper = join(here, '..', 'crosscheck', 'seal_xcheck.py');

interface Fixture {
  provenance: { kind: string; library: string; generatedOn: string };
  request: { inputs: number[]; weights: number[]; kappaWeights: number[]; budget: number };
  secretKey: string;
  encInputs: string;
  encRiskRaw: string;
  encSlack: string;
  expected: { riskRaw: number; slack: number };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function loadFixture(): Fixture {
  const parsed: unknown = JSON.parse(gunzipSync(readFileSync(join(here, '..', 'fixtures', 'tenseal-gate.json.gz'))).toString('utf8'));
  if (!isRecord(parsed)) throw new Error('fixture is not an object');
  return parsed as unknown as Fixture;
}

/** Policy that mirrors the integers the fixture's independent evaluator used. */
function fixturePolicy(f: Fixture) {
  const base = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
  expect(base.weightsScaled).toEqual(f.request.weights);
  expect(base.kappaWeightsScaled).toEqual(f.request.kappaWeights);
  expect(base.budgetScaled).toBe(f.request.budget);
  return base;
}

describe('cross-implementation: committed fixture produced by TenSEAL (independent SEAL build)', () => {
  const f = loadFixture();

  it('labels itself as self-generated, never as an official vector', () => {
    expect(f.provenance.kind).toMatch(/NOT an official standard test vector/);
    expect(f.provenance.library).toMatch(/^TenSEAL 0\.3\.18/);
  });

  it(
    'TenSEAL-evaluated gate ciphertexts load and decrypt in node-seal to the exact expected integers',
    async () => {
      const policy = fixturePolicy(f);
      const v = await decryptVerdict(f.secretKey, f.encRiskRaw, f.encSlack, policy);
      expect(v.rScaled).toBe(f.expected.riskRaw); // 260000
      expect(v.slack).toBe(f.expected.slack); // 340000
      expect(v.admit).toBe(true);
    },
    TIMEOUT,
  );

  it(
    'a TenSEAL ciphertext of the raw inputs decrypts (slot 0) to the first input, via the same load path',
    async () => {
      const policy = fixturePolicy(f);
      // Reuse the decrypting path on the input ciphertext: slot 0 holds inputs[0].
      const v = await decryptVerdict(f.secretKey, f.encInputs, f.encInputs, policy);
      expect(v.rScaled).toBe(f.request.inputs[0]);
      expect(v.slack).toBe(f.request.inputs[0]);
    },
    TIMEOUT,
  );

  it(
    'a different secret key does NOT reproduce the TenSEAL result',
    async () => {
      const policy = fixturePolicy(f);
      const other = await keygen();
      const v = await decryptVerdict(other.secretKey, f.encRiskRaw, f.encSlack, policy);
      expect(v.slack).not.toBe(f.expected.slack);
      expect(v.rScaled).not.toBe(f.expected.riskRaw);
    },
    TIMEOUT,
  );
});

// ---------------------------------------------------------------------------------------------
// Live two-way check. Needs a Python with TenSEAL: set PCA_FHE_TENSEAL_PYTHON to its interpreter, e.g.
//   uv venv .venv && uv pip install --python .venv/bin/python tenseal==0.3.18
//   PCA_FHE_TENSEAL_PYTHON=$PWD/.venv/bin/python pnpm test
// Without it these tests are SKIPPED (reported as skipped, not silently passed).
// ---------------------------------------------------------------------------------------------
const py = process.env['PCA_FHE_TENSEAL_PYTHON'];

async function runPy(cmd: string, input: unknown): Promise<Record<string, unknown>> {
  if (py === undefined) throw new Error('PCA_FHE_TENSEAL_PYTHON not set');
  const dir = mkdtempSync(join(tmpdir(), 'pca-fhe-x-'));
  try {
    writeFileSync(join(dir, 'in.json'), JSON.stringify(input));
    await execFileAsync(py, [helper, cmd, join(dir, 'in.json'), join(dir, 'out.json')], { maxBuffer: 1 << 20 });
    const out: unknown = JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8'));
    if (!isRecord(out)) throw new Error('helper output is not an object');
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function str(v: unknown, what: string): string {
  if (typeof v !== 'string') throw new Error(`${what} missing`);
  return v;
}

describe.skipIf(py === undefined)('cross-implementation: live two-way check against TenSEAL', () => {
  let keys: FheKeyset;
  let evalKeys: EvalKeys;
  const inputs = [123, 877, 0, 1000, 42, 500];
  const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
  const rawExpected = inputs.reduce((a, x, i) => a + x * (policy.weightsScaled[i] ?? 0), 0);
  const slackExpected = policy.budgetScaled - rawExpected;

  beforeAll(async () => {
    keys = await keygen();
    evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };
  }, TIMEOUT);

  it('parameter sets agree: same coefficient-modulus bit sizes, plain modulus, degree and slot count', async () => {
    const p = await runPy('params', {});
    expect(p['polyModulusDegree']).toBe(8192);
    expect(p['plainModulus']).toBe(1073692673);
    expect(p['slotCount']).toBe(8192);
    expect(p['coeffModulusBits']).toEqual([43, 43, 44, 44, 44]);
  });

  it(
    'TenSEAL encrypts under the node-seal public key, node-seal evaluates, TenSEAL decrypts with the node-seal secret key',
    async () => {
      const enc = str((await runPy('encrypt', { publicKey: keys.publicKey, inputs }))['enc'], 'enc');
      const gate = await evalRiskGate(evalKeys, enc, policy);
      const dec = await runPy('decrypt', { secretKey: keys.secretKey, cts: { risk: gate.encRiskRaw, slack: gate.encSlack } });
      expect(dec['risk']).toBe(rawExpected);
      expect(dec['slack']).toBe(slackExpected);
    },
    TIMEOUT,
  );

  it(
    'node-seal encrypts, TenSEAL evaluates the circuit independently (own slot-sum) with node-seal Galois keys, node-seal decrypts',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const out = await runPy('eval', {
        galoisKeys: keys.galoisKeys,
        encInputs: enc,
        weights: policy.weightsScaled,
        kappaWeights: policy.kappaWeightsScaled,
        budget: policy.budgetScaled,
      });
      const v = await decryptVerdict(keys.secretKey, str(out['encRiskRaw'], 'risk'), str(out['encSlack'], 'slack'), policy);
      expect(v.rScaled).toBe(rawExpected);
      expect(v.slack).toBe(slackExpected);
      expect(v.admit).toBe(slackExpected >= 0);
    },
    TIMEOUT,
  );

  it(
    'both implementations evaluating the same ciphertext decrypt to the same integers',
    async () => {
      const enc = await encryptRiskInputs(keys.publicKey, inputs);
      const mine = await evalRiskGate(evalKeys, enc, policy);
      const theirs = await runPy('eval', {
        galoisKeys: keys.galoisKeys,
        encInputs: enc,
        weights: policy.weightsScaled,
        kappaWeights: policy.kappaWeightsScaled,
        budget: policy.budgetScaled,
      });
      const dec = await runPy('decrypt', {
        secretKey: keys.secretKey,
        cts: {
          mineRisk: mine.encRiskRaw,
          mineSlack: mine.encSlack,
          theirRisk: str(theirs['encRiskRaw'], 'risk'),
          theirSlack: str(theirs['encSlack'], 'slack'),
        },
      });
      expect(dec['mineRisk']).toBe(dec['theirRisk']);
      expect(dec['mineSlack']).toBe(dec['theirSlack']);
      expect(dec['mineRisk']).toBe(rawExpected);
    },
    TIMEOUT,
  );
});
