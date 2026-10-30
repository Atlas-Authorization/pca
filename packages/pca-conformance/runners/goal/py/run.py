#!/usr/bin/env python3
"""Python runner for the pca-goal vectors: goal digest, decision + witness for every probe, and the fn vectors.
Independent port of the reference semantics (adversarial/src/oracle.ts, itself written from formal/dafny/GoalIr.dfy). Usage: run.py <vectors-dir>"""
import base64, hashlib, json, os, sys

SHORT = {8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r'}
def canon(v):
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, int): return str(v)
    if isinstance(v, str):
        o = '"'
        for ch in v:
            c = ord(ch)
            if ch == '"': o += '\\"'
            elif ch == '\\': o += '\\\\'
            elif c in SHORT: o += SHORT[c]
            elif c < 0x20: o += '\\u%04x' % c
            else: o += ch
        return o + '"'
    if isinstance(v, list): return '[' + ','.join(canon(x) for x in v) + ']'
    ks = sorted(v.keys(), key=lambda k: k.encode('utf-8'))
    return '{' + ','.join(canon(k) + ':' + canon(v[k]) for k in ks) + '}'

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def hash_canon(v): return b64(hashlib.sha256(canon(v).encode()).digest())
def goal_digest(g): return hash_canon({'d': 'atlas-pca/goal-ir/v1', 'goal': g})
def digest(kind, v):
    return base64.urlsafe_b64encode(hashlib.sha256(('pca-goal:v1:%s:%s' % (kind, canon(v))).encode()).digest()).rstrip(b'=').decode()

def bk(s): return s.encode('utf-8')

# Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow); meet = min, join = max
def k_not(a): return 2 - a
def b2k(b): return 2 if b else 0
def same_unit(a, b): return a == b

def eq_v(x, y):
    if x['k'] == 'q': return b2k(x['q']['n'] == y['q']['n']) if y['k'] == 'q' and same_unit(x['q']['u'], y['q']['u']) else 1
    if x['k'] == 's': return b2k(x['s'] == y['s']) if y['k'] == 's' else 1
    return 1
def lt_v(x, y):
    return b2k(x['q']['n'] < y['q']['n']) if x['k'] == 'q' and y['k'] == 'q' and same_unit(x['q']['u'], y['q']['u']) else 1
def cmp_(op, x, y):
    if x is None or y is None: return 1
    if op == 'eq': return eq_v(x, y)
    if op == 'ne': return k_not(eq_v(x, y))
    if op == 'lt': return lt_v(x, y)
    if op == 'gte': return k_not(lt_v(x, y))
    if op == 'gt': return lt_v(y, x)
    if op == 'lte': return k_not(lt_v(y, x))
    t = 1
    if y['k'] == 'set':
        t = 0
        for it in y['items']: t = max(t, eq_v(x, it))
    return t if op == 'in' else k_not(t)

def term(t, a, h):
    if t['k'] == 'param': return a['params'].get(t['path'])
    if t['k'] == 'lit': return t['v']
    q = h['aggs'].get(t['bid'])
    return {'k': 'q', 'q': q} if q is not None else None
def cond(c, a, h):
    k = c['k']
    if k == 'true': return 2
    if k == 'cmp': return cmp_(c['op'], term(c['l'], a, h), term(c['r'], a, h))
    if k == 'and': return min(cond(c['a'], a, h), cond(c['b'], a, h))
    if k == 'or': return max(cond(c['a'], a, h), cond(c['b'], a, h))
    return k_not(cond(c['c'], a, h))

def part_ids(o, p):
    if p['k'] == 'exact': return [p['id']]
    if p['k'] == 'oneof': return p['ids']
    for r in o['rels']:
        if r['rel'] == p['rel'] and r['anchor'] == p['anchor']: return r['members']
    return []
def resolve(o, s):
    if s['k'] == 'any': return None
    if s['k'] != 'all_of': return part_ids(o, s)
    acc = None
    for p in reversed(s['parts']):
        ids = part_ids(o, p)
        acc = ids if acc is None else [i for i in ids if i in acc]
    return acc
def res_ok(p, r): return p is None or r in p
def verbs_of_class(o, cls): return [v['verb'] for v in o['verbs'] if v['cls'] == cls]
def proh_verbs(o, p): return [p['target']['verb']] if p['target']['k'] == 'verb' else verbs_of_class(o, p['target']['cls'])
def lsel(o, b): return (b['sel']['gids'], []) if b['sel']['k'] == 'gids' else ([], verbs_of_class(o, b['sel']['cls']))
def applies(s, gid, verb): return gid in s[0] or verb in s[1]

def in_scope(b, a, x):
    s = b['scope']
    if s['k'] == 'session': return a['sess'] == x['sess']
    if s['k'] == 'principal': return a['prin'] == x['prin']
    if s['k'] == 'org': return a['org'] == x['org']
    return a['agent'] in s['agents'] and x['agent'] in s['agents']
def in_window(w, a, x):
    if w['k'] == 'sliding': return a['t'] - w['ms'] < x['t'] <= a['t']
    if w['k'] == 'period': return w['ms'] > 0 and (a['t'] - w['t0']) // w['ms'] == (x['t'] - w['t0']) // w['ms']
    return True
def exceeded(b, s, a, h):
    items = [m['act'] for m in h['adms'] if applies(s, m['gid'], m['act']['verb']) and in_scope(b, a, m['act']) and in_window(b['window'], a, m['act'])] + [a]
    if b['agg'] == 'count': return b2k(len(items) > b['cap']['n'])
    if b['agg'] == 'distinct':
        vs = set()
        for x in items:
            if b['key'] not in x['params']: return 1
            vs.add(canon(x['params'][b['key']]))
        return b2k(len(vs) > b['cap']['n'])
    ns = []
    for x in items:
        v = term(b['value'], x, h)
        if v is None or v['k'] != 'q' or not same_unit(v['q']['u'], b['cap']['u']): return 1
        ns.append(v['q']['n'])
    return b2k((sum(ns) if b['agg'] == 'sum' else max(ns)) > b['cap']['n'])
def bound_dec(b, s, a, h):
    e = exceeded(b, s, a, h)
    return (0 if b['onExceed'] == 'deny' else 1) if e == 2 else (1 if e == 1 else 2)

def strip(g):
    return {**g, 'holes': [], 'grants': [x for x in g['grants'] if not any(h['global'] or x['gid'] in h['affects'] for h in g['holes'])]}
def grant_dec(g, o, gr, a, h):
    deleg_ok = a['depth'] == 0 or gr['gid'] in g['deleg']['mayTouch']
    m = min(b2k(a['verb'] == gr['verb'] and deleg_ok), b2k(res_ok(resolve(o, gr['res']), a['res'])), cond(gr['cond'], a, h))
    for b in g['bounds']:
        s = lsel(o, b)
        if applies(s, gr['gid'], a['verb']): m = min(m, bound_dec(b, s, a, h))
    return m
def decide(goal, o, a, h):
    g = strip(goal)
    v = g['validity']
    d = 2
    if a['t'] < v['notBefore'] or a['t'] > v['notAfter']: d = 0
    elif v['maxIdle'] > 0 and h['last'] >= 0 and a['t'] - h['last'] > v['maxIdle']: d = 0
    elif a['depth'] < 0 or a['depth'] > g['deleg']['maxDepth']: d = 0
    for p in g['prohibits']:
        m = min(b2k(a['verb'] in proh_verbs(o, p)), b2k(res_ok(resolve(o, p['res']), a['res'])), cond(p['cond'], a, h))
        d = min(d, 0 if m == 2 else (1 if m == 1 else 2))
    for c in g['escalateOn']: d = min(d, 2 if cond(c, a, h) == 0 else 1)
    per = [grant_dec(g, o, gr, a, h) for gr in g['grants']]
    d = min(d, max(per) if per else 0)
    if d != 2: return {'decision': 'escalate' if d == 1 else 'deny', 'witness': None}
    gr = g['grants'][per.index(2)]
    return {'decision': 'allow', 'witness': {'gid': gr['gid'], 'bids': [b['bid'] for b in g['bounds'] if applies(lsel(o, b), gr['gid'], a['verb'])]}}

# lowering (GoalCompile.dfy Lower) for the policy digest
NEG = {'eq': 'ne', 'ne': 'eq', 'lt': 'gte', 'gte': 'lt', 'gt': 'lte', 'lte': 'gt', 'in': 'nin', 'nin': 'in'}
def nnf(c, pos):
    k = c['k']
    if k == 'true': return {'k': 'true' if pos else 'false'}
    if k == 'cmp': return {'k': 'atom', 'op': c['op'] if pos else NEG[c['op']], 'l': c['l'], 'r': c['r']}
    if k == 'and': return {'k': 'and' if pos else 'or', 'a': nnf(c['a'], pos), 'b': nnf(c['b'], pos)}
    if k == 'or': return {'k': 'or' if pos else 'and', 'a': nnf(c['a'], pos), 'b': nnf(c['b'], pos)}
    return nnf(c['c'], not pos)
def pat(p): return {'k': 'star'} if p is None else {'k': 'set', 'ids': p}
def lower(o, goal):
    g = strip(goal)
    ceils = []
    for b in g['bounds']:
        s = lsel(o, b)
        ceils.append({'bid': b['bid'], 'selGids': s[0], 'selVerbs': s[1], 'agg': b['agg'], 'value': b['value'], 'key': b['key'], 'window': b['window'], 'scope': b['scope'], 'cap': b['cap'], 'onExceed': b['onExceed']})
    return {'preds': [{'gid': x['gid'], 'verb': x['verb'], 'res': pat(resolve(o, x['res'])), 'cond': nnf(x['cond'], True)} for x in g['grants']],
            'prohs': [{'pid': p['pid'], 'verbs': proh_verbs(o, p), 'res': pat(resolve(o, p['res'])), 'cond': nnf(p['cond'], True)} for p in g['prohibits']],
            'ceils': ceils, 'escs': [nnf(c, True) for c in g['escalateOn']], 'validity': g['validity'], 'deleg': g['deleg']}

# ---- selector expansion (pca-goal selectors.ts / formal/dafny/GoalSelect.dfy): a selector goal + pinned catalog -> an ordinary Goal
def class_verbs(cat, all_of, none_of, float_):
    # An unconfirmed verb carries pca.unreviewed (it is the top of the registry): a class ALLOW never covers it (float_ = false), a class PROHIBITION or bound over a trait selector ALWAYS covers it, whatever all_of and none_of say (float_ = true).
    out = []
    for v in cat['verbs']:
        ts = v['traits']
        unrev = 'pca.unreviewed' in ts
        in_class = all(t in ts for t in all_of) and all(t not in ts for t in none_of)
        if (unrev or in_class) if float_ else (in_class and not unrev):
            out.append(v['verb'])
    return out
def resolve_role(ont, cat, verb, role):
    info = next((v for v in cat['verbs'] if v['verb'] == verb), None)
    decl = next((v for v in ont['verbs'] if v['verb'] == verb), None)
    if info is None or decl is None: return None
    paths = info['roles'].get(role, []) if isinstance(info['roles'], dict) else []
    if len(paths) != 1: return None
    p = next((x for x in decl['params'] if x['path'] == paths[0]), None)
    return None if p is None else (p['path'], p['ty'])
def x_term(ont, cat, verb, t):
    if t['k'] == 'role':
        r = resolve_role(ont, cat, verb, t['role'])
        return None if r is None else {'k': 'param', 'path': r[0], 'ty': r[1]}
    return t
def x_cond(ont, cat, verb, c):
    k = c['k']
    if k == 'true': return {'k': 'true'}
    if k == 'cmp':
        l, r = x_term(ont, cat, verb, c['l']), x_term(ont, cat, verb, c['r'])
        return None if l is None or r is None else {'k': 'cmp', 'op': c['op'], 'l': l, 'r': r}
    if k in ('and', 'or'):
        a, b = x_cond(ont, cat, verb, c['a']), x_cond(ont, cat, verb, c['b'])
        return None if a is None or b is None else {'k': k, 'a': a, 'b': b}
    a = x_cond(ont, cat, verb, c['c'])
    return None if a is None else {'k': 'not', 'c': a}
def bound_value(ont, cat, vs, t):
    if t['k'] != 'role': return t
    rs = []
    for v in vs:
        r = resolve_role(ont, cat, v, t['role'])
        if r is None: return None
        rs.append(r)
    if not rs: return None
    if all(canon({'p': r[0], 't': r[1]}) == canon({'p': rs[0][0], 't': rs[0][1]}) for r in rs): return {'k': 'param', 'path': rs[0][0], 'ty': rs[0][1]}
    if all(canon(r[1]) == canon(rs[0][1]) for r in rs): return {'k': 'param', 'path': '@' + t['role'], 'ty': rs[0][1]}
    return None
def expand_sel(sg, ont, cat):
    es = []
    for gr in sg['grants']:
        s = gr['sel']
        verbs = [s['verb']] if s['k'] == 'verb' else class_verbs(cat, s['all_of'], s['none_of'], False)
        for v in verbs:
            c = x_cond(ont, cat, v, gr['cond'])
            if c is None: continue
            es.append((gr['gid'], {'gid': (gr['gid'] + '.' + v) if s['k'] == 'class' else gr['gid'], 'verb': v, 'res': gr['res'], 'cond': c}))
    ids_of = lambda srcs: [e[1]['gid'] for e in es if e[0] in srcs]
    gids_of_verbs = lambda vs: [e[1]['gid'] for e in es if e[1]['verb'] in vs]
    verbs_of_gids = lambda gids: [e[1]['verb'] for e in es if e[1]['gid'] in gids]
    prohibits = []
    for p in sg['prohibits']:
        t = p['target']
        verbs = [t['verb']] if t['k'] == 'verb' else verbs_of_class(ont, t['cls']) if t['k'] == 'effect' else class_verbs(cat, t['all_of'], t['none_of'], True)
        for v in verbs:
            c = x_cond(ont, cat, v, p['cond'])
            prohibits.append({'pid': p['pid'] if t['k'] == 'verb' else p['pid'] + '.' + v, 'target': {'k': 'verb', 'verb': v}, 'res': p['res'], 'cond': c if c is not None else {'k': 'true'}})
    bounds = []
    for b in sg['bounds']:
        s = b['sel']
        if s['k'] == 'gids': rv, gids = verbs_of_gids(ids_of(s['gids'])), ids_of(s['gids'])
        elif s['k'] == 'effect': rv, gids = verbs_of_class(ont, s['cls']), None
        else: gids = gids_of_verbs(class_verbs(cat, s['all_of'], s['none_of'], True)); rv = verbs_of_gids(gids)
        val = bound_value(ont, cat, rv, b['value'])
        if val is None: continue
        if gids is not None and not gids: continue
        sel = {'k': 'effect', 'cls': s['cls']} if gids is None else {'k': 'gids', 'gids': gids}
        bounds.append({'bid': b['bid'], 'sel': sel, 'agg': b['agg'], 'value': val, 'key': b['key'], 'window': b['window'], 'scope': b['scope'], 'cap': b['cap'], 'onExceed': b['onExceed']})
    return {'v': 1, 'principal': sg['principal'], 'ontDigest': sg['ontDigest'], 'nlDigest': sg['nlDigest'], 'sources': sg['sources'],
            'grants': [e[1] for e in es], 'prohibits': prohibits, 'bounds': bounds, 'validity': sg['validity'],
            'deleg': {**sg['deleg'], 'mayTouch': ids_of(sg['deleg']['mayTouch'])}, 'escalateOn': sg['escalateOn'],
            'wildcardAck': ids_of(sg['wildcardAck']), 'holes': [{**h, 'affects': ids_of(h['affects'])} for h in sg['holes']]}

RANK = {'deny': 0, 'escalate': 1, 'allow': 2}
def meet(d, s): return s if s in RANK and RANK[s] < RANK[d] else d
MODEL = ('env.class.', 'env.prov.', 'env.judge.', 'env.world.')
def polarity(ws):
    out = set()
    def walk(c):
        if c['k'] in ('and', 'or'): walk(c['a']); walk(c['b'])
        elif c['k'] == 'not': walk(c['c'])
        elif c['k'] == 'cmp':
            for t in (c['l'], c['r']):
                if t['k'] == 'param' and t['path'].startswith(MODEL): out.add(t['path'])
    for w in ws: walk(w)
    return sorted(out, key=bk)
def units(schema, terms):
    return sorted([p for p in terms if p not in schema or schema[p] != terms[p]], key=bk)
def pep(d, ctx, ans):
    if d == 'allow': return True
    if d == 'deny': return False
    return bool(ans) and ans['valid'] and all(ans[k] == ctx[k] for k in ('policy_digest', 'action_digest', 'history_head'))
def commit(g, p, s):
    return base64.urlsafe_b64encode(hashlib.sha256(('pca-goal:v3:commit:%s:%s:%s' % (g, p, s)).encode()).digest()).rstrip(b'=').decode()
def claim(base, mn, cl, rp):
    return meet(base, 'escalate') if rp is not None and rp < mn else base

def run_fn(v):
    i, f = v['input'], v['fn']
    if f == 'canon': return {'canon': canon(i), 'digest': goal_digest(i)}
    if f == 'units': return units(i['schema'], i['terms'])
    if f == 'polarity': return polarity(i)
    if f == 'meet': return meet(i['decision'], i['signal'])
    if f == 'pep': return pep(i['decision'], i['ctx'], i['answer'])
    if f == 'commit': return {'commit': commit(i['goal_digest'], i['policy_digest'], i['salt']), 'opens_other_goal': False}
    if f == 'claim': return claim(i['base'], i['min_ppm'], i['claimed_ppm'], i['replayed_ppm'])
    raise SystemExit('unknown fn ' + f)

def main(d):
    bad, n, probes = [], 0, 0
    for f in sorted(os.listdir(d)):
        if f == 'index.json' or not f.endswith('.json'): continue
        v = json.load(open(os.path.join(d, f), encoding='utf-8')); n += 1
        if v['kind'] == 'fn':
            if canon(run_fn(v)) != canon(v['expect']): bad.append(v['id'])
            continue
        if v.get('sel') and canon(expand_sel(v['sel']['goal'], v['ontology'], v['sel']['catalog'])) != canon(v['goal']): bad.append(v['id'] + ':expansion')
        if goal_digest(v['goal']) != v['goal_digest']: bad.append(v['id'] + ':goal_digest')
        if v['compile']['ok'] and hash_canon(lower(v['ontology'], v['goal'])) != v['policy_digest']: bad.append(v['id'] + ':policy_digest')
        if not v['compile']['ok']: continue
        for i, p in enumerate(v['probes']):
            probes += 1
            got = decide(v['goal'], v['ontology'], p['action'], p['history'])
            if canon(got) != canon(p['expect']): bad.append('%s#%d' % (v['id'], i))
    print('python: %d vectors, %d probes, %d disagreements' % (n, probes, len(bad)))
    for b in bad[:20]: print('  ', b)
    sys.exit(1 if bad or n == 0 else 0)

if __name__ == '__main__': main(sys.argv[1])
