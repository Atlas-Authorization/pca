/**
 * 0.4.2 mutation kills (Stryker run 39706550807): launchLocal's scratch-directory cleanup tolerates a directory that is already gone
 * (rmSync force: true). A node process that deletes the run directory must not turn a finished run into a thrown ENOENT.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { launchLocal } from './launch-local';

describe('launchLocal cleanup', () => {
  it('a run whose directory vanished mid-run still resolves with the nodes\' outputs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pca-launch-r9-'));
    try {
      const js = join(dir, 'vanish.js');
      writeFileSync(
        js,
        `const fs = require('fs'), path = require('path');
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
// every node has read its own config by now; the first one to wake removes the whole run directory under the others
setTimeout(() => {
  fs.rmSync(path.dirname(path.dirname(cfg.keyPath)), { recursive: true, force: true });
  process.stdout.write(JSON.stringify({ vanished: !fs.existsSync(cfg.keyPath) }) + '\\n');
}, 1500);
`,
      );
      const r = await launchLocal({ n: 1, vectors: [{ allow: 1, t: 1, rQuant: 2 }], mainJs: js, killAfterMs: 60_000 });
      expect(r.outputs.map((o) => o.json)).toEqual([{ vanished: true }, { vanished: true }]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
