#!/usr/bin/env python3
"""gen-corpus.py <out-dir> [nshards]: split packages/pca/conformance/vectors.json into small files so Miri never parses the 2 MB
corpus (parsing it under the interpreter alone takes tens of minutes). Contents are byte-for-byte subsets of the committed corpus."""
import json, sys, os
out = sys.argv[1]; n = int(sys.argv[2]) if len(sys.argv) > 2 else 29
here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, '../../../packages/pca/conformance')
d = json.load(open(os.path.join(src, 'vectors.json')))
os.makedirs(out, exist_ok=True)
for i in range(n):
    json.dump({'format': d['format'], 'vectors': d['vectors'][i::n]}, open(f'{out}/vec-{i}.json', 'w'), ensure_ascii=True, separators=(',', ':'))
for k in ['canonical', 'merkle', 'json_parse', 'b64u', 'threshold_share']:
    json.dump({'primitives': {k: d['primitives'][k]}}, open(f'{out}/prim-{k}.json', 'w'), ensure_ascii=True, separators=(',', ':'))
json.dump({'primitives': {'params_digest_empty': d['primitives']['params_digest_empty']}}, open(f'{out}/prim-params.json', 'w'))
import shutil; shutil.copy(os.path.join(src, 'keys.json'), out)
print('shards', n, 'vectors', len(d['vectors']))
