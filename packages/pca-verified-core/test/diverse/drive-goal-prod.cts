// drive-goal-prod.cts <casefile> : the production bridge (src/goal.ts over generated/pca_goal.js) on a GoalHarness case file,
// printing one transcript line per case in exactly the format GoalHarness.dfy prints.
import { readFileSync } from 'node:fs';
import { goalCall, tapeFromText, tapeToText, type GoalOp, type Tape } from '../../src/goal';

const lines = readFileSync(process.argv[2]!, 'utf8').split('\n');
if (lines[lines.length - 1] === '') lines.pop();
const out: string[] = [];
for (const l of lines) {
  const sp = l.indexOf(' ');
  const op = (sp < 0 ? l : l.slice(0, sp)) as GoalOp;
  const groups: Tape[] = l.slice(sp + 1).split('|').map((g) => tapeFromText(g.trim()));
  while (groups.length < 4) groups.push([]);
  try { out.push(tapeToText(goalCall(op, groups[0]!, groups[1]!, groups[2]!, groups[3]!))); } catch (e) { out.push(`THROW ${(e as Error).name}`); }
}
process.stdout.write(out.join('\n') + '\n');
