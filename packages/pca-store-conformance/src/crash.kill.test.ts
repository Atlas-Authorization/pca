import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runCrash } from './crash';

describe('runCrash reads the per-process history files', () => {
  it('reads only h-*.jsonl files and keeps a torn tail from swallowing the next file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-crash-'));
    const worker = join(dir, 'fake-worker.js');
    writeFileSync(
      worker,
      [
        "const fs = require('node:fs');",
        'const cfg = JSON.parse(process.argv[2]);',
        'const p = cfg.proc;',
        // a valid invocation and response, then a line cut off by a kill (no trailing newline)
        'fs.writeFileSync(cfg.file, `["i","${p}",1,1,"a-${p}","advance","k",1,1]\\n["r","${p}",1,2,"true"]\\n["i","${p}",9,`);',
      ].join('\n'),
    );
    const stray = '["i","z",1,1,"stray","advance","k",1,1]\n';
    writeFileSync(join(dir, 'x-p0.jsonl'), stray);
    writeFileSync(join(dir, 'h-p7.txt'), stray);
    writeFileSync(join(dir, 'h-p8.jsonl.bak'), stray);
    const r = await runCrash('advance', { module: 'builtin:in-memory', dir, workerPath: worker, processes: 2, killEveryMs: 0, backendCrash: false, durationMs: 50, namespace: 'ns', seed: 1 });
    expect(r.ops.map((o) => o.client).sort()).toEqual(['a-p0', 'a-p1']);
    expect(r.torn).toBe(2);
    expect(r.pending).toBe(0);
    expect(r.errors).toBe(0);
    expect(r.processes).toBe(2);
    expect(r.kills).toBe(0);
  });
});
