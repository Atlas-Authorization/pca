#!/usr/bin/env python3
"""Aggregate the per-shard conformance JSON files (pulled from the boxes) into one summary.
Usage: summarize.py <dir-with-shard-json> > summary.json"""
import json, sys, glob, os, collections
d = sys.argv[1]
stages = collections.defaultdict(lambda: collections.Counter())
examples = []
secs = collections.Counter()
shards = collections.defaultdict(set)
empty = []
for f in sorted(glob.glob(os.path.join(d, '*.json'))):
    name = os.path.basename(f)[:-5]
    stage, _, shard = name.rpartition('-')
    txt = open(f).read().strip()
    if not txt:
        empty.append(name); continue
    j = json.loads(txt.splitlines()[-1])
    c = stages[stage]
    total = j.get('n', j.get('sequences', j.get('cases')))
    c['scenarios'] += total
    c['agree'] += j['agree']
    c['disagree'] += j['disagree']
    c['model_accepts'] += j.get('allow', j.get('allowedSteps', j.get('modelAccepted', 0)))
    c['shards'] += 1
    secs[stage] += j['seconds']
    if j['disagree']:
        examples.append({'stage': stage, 'shard': shard, 'examples': j.get('examples', [])[:3]})
    if 'singleFaultStageChecked' in j:
        c['single_fault_stage_checks'] += j['singleFaultStageChecked']; c['stage_agree'] += j['stageAgree']
        c['binding_tuples'] = j['bindingInjectivity']['tuples']; c['binding_collisions'] = j['bindingInjectivity']['collisions']
    if 'replayDeniedSteps' in j:
        c['replay_denied_steps'] += j['replayDeniedSteps']
    if 'byAttack' in j:
        for k, v in j['byAttack'].items():
            c['attack:' + k] += v['n']
out = {'stages': {k: dict(v, cpu_seconds=round(secs[k])) for k, v in stages.items()}, 'incomplete_shards': empty,
       'total_scenarios': sum(v['scenarios'] for v in stages.values()), 'total_disagreements': sum(v['disagree'] for v in stages.values()),
       'disagreement_examples': examples[:10]}
print(json.dumps(out, indent=1, sort_keys=True))
