<?php
declare(strict_types=1);

// PHP runner for the pca-goal vectors (goals and selector goals): goal digest, lowered policy digest, decision + witness of every
// probe, the fn vectors, and - for `sel` vectors - the native expansion of the trait selectors. Independent port of the reference
// semantics (adversarial/src/oracle.ts). JSON is decoded to arrays (objects and lists are both PHP arrays; `canon` tells a list
// from an object by array_is_list, and no vector depends on an empty object). Usage: php run.php <vectors-dir>

/** An empty JSON object (PHP arrays cannot tell {} from []). */
final class EmptyObj implements ArrayAccess
{
    public function offsetExists(mixed $o): bool { return false; }
    public function offsetGet(mixed $o): mixed { return null; }
    public function offsetSet(mixed $o, mixed $v): void {}
    public function offsetUnset(mixed $o): void {}
}

function has_key(mixed $m, string $k): bool
{
    return is_array($m) && array_key_exists($k, $m);
}

function plain(mixed $v): mixed
{
    if ($v instanceof stdClass) {
        $a = get_object_vars($v);
        if (!$a) {
            return new EmptyObj();
        }
        return array_map('plain', $a);
    }
    return is_array($v) ? array_map('plain', $v) : $v;
}

function canon(mixed $v): string
{
    if ($v instanceof EmptyObj) {
        return '{}';
    }
    if ($v === null) {
        return 'null';
    }
    if ($v === true) {
        return 'true';
    }
    if ($v === false) {
        return 'false';
    }
    if (is_int($v)) {
        return (string)$v;
    }
    if (is_string($v)) {
        $o = '"';
        $n = strlen($v);
        for ($i = 0; $i < $n; $i++) {
            $ch = $v[$i];
            $c = ord($ch);
            if ($ch === '"') {
                $o .= '\\"';
            } elseif ($ch === '\\') {
                $o .= '\\\\';
            } elseif ($c === 8) {
                $o .= '\\b';
            } elseif ($c === 9) {
                $o .= '\\t';
            } elseif ($c === 10) {
                $o .= '\\n';
            } elseif ($c === 12) {
                $o .= '\\f';
            } elseif ($c === 13) {
                $o .= '\\r';
            } elseif ($c < 0x20) {
                $o .= sprintf('\\u%04x', $c);
            } else {
                $o .= $ch;
            }
        }
        return $o . '"';
    }
    if (array_is_list($v)) {
        return '[' . implode(',', array_map('canon', $v)) . ']';
    }
    $ks = array_map('strval', array_keys($v));
    usort($ks, 'strcmp');
    $parts = [];
    foreach ($ks as $k) {
        $parts[] = canon($k) . ':' . canon($v[$k]);
    }
    return '{' . implode(',', $parts) . '}';
}

function b64u(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}
function hash_canon(mixed $v): string
{
    return b64u(hash('sha256', canon($v), true));
}
function goal_digest(mixed $g): string
{
    return hash_canon(['d' => 'atlas-pca/goal-ir/v1', 'goal' => $g]);
}
function digest(string $kind, mixed $v): string
{
    return b64u(hash('sha256', 'pca-goal:v1:' . $kind . ':' . canon($v), true));
}

// Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow); meet = min, join = max
function k_not(int $a): int { return 2 - $a; }
function b2k(bool $b): int { return $b ? 2 : 0; }
function same_unit(mixed $a, mixed $b): bool { return canon($a) === canon($b); }

function eq_v(mixed $x, mixed $y): int
{
    if ($x['k'] === 'q') {
        return $y['k'] === 'q' && same_unit($x['q']['u'], $y['q']['u']) ? b2k($x['q']['n'] === $y['q']['n']) : 1;
    }
    if ($x['k'] === 's') {
        return $y['k'] === 's' ? b2k($x['s'] === $y['s']) : 1;
    }
    return 1;
}
function lt_v(mixed $x, mixed $y): int
{
    return $x['k'] === 'q' && $y['k'] === 'q' && same_unit($x['q']['u'], $y['q']['u']) ? b2k($x['q']['n'] < $y['q']['n']) : 1;
}
function cmp_(string $op, mixed $x, mixed $y): int
{
    if ($x === null || $y === null) {
        return 1;
    }
    switch ($op) {
        case 'eq': return eq_v($x, $y);
        case 'ne': return k_not(eq_v($x, $y));
        case 'lt': return lt_v($x, $y);
        case 'gte': return k_not(lt_v($x, $y));
        case 'gt': return lt_v($y, $x);
        case 'lte': return k_not(lt_v($y, $x));
    }
    $t = 1;
    if ($y['k'] === 'set') {
        $t = 0;
        foreach ($y['items'] as $it) {
            $t = max($t, eq_v($x, $it));
        }
    }
    return $op === 'in' ? $t : k_not($t);
}

function term(array $t, array $a, array $h): mixed
{
    if ($t['k'] === 'param') {
        return $a['params'][$t['path']] ?? null;
    }
    if ($t['k'] === 'lit') {
        return $t['v'];
    }
    $q = $h['aggs'][$t['bid']] ?? null;
    return $q !== null ? ['k' => 'q', 'q' => $q] : null;
}
function cond(array $c, array $a, array $h): int
{
    switch ($c['k']) {
        case 'true': return 2;
        case 'cmp': return cmp_($c['op'], term($c['l'], $a, $h), term($c['r'], $a, $h));
        case 'and': return min(cond($c['a'], $a, $h), cond($c['b'], $a, $h));
        case 'or': return max(cond($c['a'], $a, $h), cond($c['b'], $a, $h));
    }
    return k_not(cond($c['c'], $a, $h));
}

function part_ids(array $o, array $p): array
{
    if ($p['k'] === 'exact') {
        return [$p['id']];
    }
    if ($p['k'] === 'oneof') {
        return $p['ids'];
    }
    foreach ($o['rels'] as $r) {
        if ($r['rel'] === $p['rel'] && $r['anchor'] === $p['anchor']) {
            return $r['members'];
        }
    }
    return [];
}
/** null = every resource */
function resolve_res(array $o, array $s): ?array
{
    if ($s['k'] === 'any') {
        return null;
    }
    if ($s['k'] !== 'all_of') {
        return part_ids($o, $s);
    }
    $acc = null;
    foreach (array_reverse($s['parts']) as $p) {
        $ids = part_ids($o, $p);
        $acc = $acc === null ? $ids : array_values(array_filter($ids, fn($i) => in_array($i, $acc, true)));
    }
    return $acc;
}
function res_ok(?array $p, string $r): bool { return $p === null || in_array($r, $p, true); }
function verbs_of_class(array $o, string $cls): array
{
    $out = [];
    foreach ($o['verbs'] as $v) {
        if ($v['cls'] === $cls) {
            $out[] = $v['verb'];
        }
    }
    return $out;
}
function proh_verbs(array $o, array $p): array
{
    return $p['target']['k'] === 'verb' ? [$p['target']['verb']] : verbs_of_class($o, $p['target']['cls']);
}
function lsel(array $o, array $b): array
{
    return $b['sel']['k'] === 'gids' ? [$b['sel']['gids'], []] : [[], verbs_of_class($o, $b['sel']['cls'])];
}
function applies(array $s, string $gid, string $verb): bool { return in_array($gid, $s[0], true) || in_array($verb, $s[1], true); }

function in_scope(array $b, array $a, array $x): bool
{
    $s = $b['scope'];
    switch ($s['k']) {
        case 'session': return $a['sess'] === $x['sess'];
        case 'principal': return $a['prin'] === $x['prin'];
        case 'org': return $a['org'] === $x['org'];
    }
    return in_array($a['agent'], $s['agents'], true) && in_array($x['agent'], $s['agents'], true);
}
function in_window(array $w, array $a, array $x): bool
{
    if ($w['k'] === 'sliding') {
        return $a['t'] - $w['ms'] < $x['t'] && $x['t'] <= $a['t'];
    }
    if ($w['k'] === 'period') {
        return $w['ms'] > 0 && intdiv_floor($a['t'] - $w['t0'], $w['ms']) === intdiv_floor($x['t'] - $w['t0'], $w['ms']);
    }
    return true;
}
function intdiv_floor(int $a, int $b): int { return (int)floor($a / $b); }
function exceeded(array $b, array $s, array $a, array $h): int
{
    $items = [];
    foreach ($h['adms'] as $m) {
        if (applies($s, $m['gid'], $m['act']['verb']) && in_scope($b, $a, $m['act']) && in_window($b['window'], $a, $m['act'])) {
            $items[] = $m['act'];
        }
    }
    $items[] = $a;
    if ($b['agg'] === 'count') {
        return b2k(count($items) > $b['cap']['n']);
    }
    if ($b['agg'] === 'distinct') {
        $vs = [];
        foreach ($items as $x) {
            if (!has_key($x['params'], $b['key'])) {
                return 1;
            }
            $vs[canon($x['params'][$b['key']])] = true;
        }
        return b2k(count($vs) > $b['cap']['n']);
    }
    $ns = [];
    foreach ($items as $x) {
        $v = term($b['value'], $x, $h);
        if ($v === null || $v['k'] !== 'q' || !same_unit($v['q']['u'], $b['cap']['u'])) {
            return 1;
        }
        $ns[] = $v['q']['n'];
    }
    return b2k(($b['agg'] === 'sum' ? array_sum($ns) : max($ns)) > $b['cap']['n']);
}
function bound_dec(array $b, array $s, array $a, array $h): int
{
    $e = exceeded($b, $s, $a, $h);
    return $e === 2 ? ($b['onExceed'] === 'deny' ? 0 : 1) : ($e === 1 ? 1 : 2);
}

function strip_holes(array $g): array
{
    $keep = [];
    foreach ($g['grants'] as $x) {
        $hit = false;
        foreach ($g['holes'] as $h) {
            if ($h['global'] || in_array($x['gid'], $h['affects'], true)) {
                $hit = true;
            }
        }
        if (!$hit) {
            $keep[] = $x;
        }
    }
    return array_merge($g, ['holes' => [], 'grants' => $keep]);
}
function grant_dec(array $g, array $o, array $gr, array $a, array $h): int
{
    $deleg_ok = $a['depth'] === 0 || in_array($gr['gid'], $g['deleg']['mayTouch'], true);
    $m = min(b2k($a['verb'] === $gr['verb'] && $deleg_ok), b2k(res_ok(resolve_res($o, $gr['res']), $a['res'])), cond($gr['cond'], $a, $h));
    foreach ($g['bounds'] as $b) {
        $s = lsel($o, $b);
        if (applies($s, $gr['gid'], $a['verb'])) {
            $m = min($m, bound_dec($b, $s, $a, $h));
        }
    }
    return $m;
}
function decide(array $goal, array $o, array $a, array $h): array
{
    $g = strip_holes($goal);
    $v = $g['validity'];
    $d = 2;
    if ($a['t'] < $v['notBefore'] || $a['t'] > $v['notAfter']) {
        $d = 0;
    } elseif ($v['maxIdle'] > 0 && $h['last'] >= 0 && $a['t'] - $h['last'] > $v['maxIdle']) {
        $d = 0;
    } elseif ($a['depth'] < 0 || $a['depth'] > $g['deleg']['maxDepth']) {
        $d = 0;
    }
    foreach ($g['prohibits'] as $p) {
        $m = min(b2k(in_array($a['verb'], proh_verbs($o, $p), true)), b2k(res_ok(resolve_res($o, $p['res']), $a['res'])), cond($p['cond'], $a, $h));
        $d = min($d, $m === 2 ? 0 : ($m === 1 ? 1 : 2));
    }
    foreach ($g['escalateOn'] as $c) {
        $d = min($d, cond($c, $a, $h) === 0 ? 2 : 1);
    }
    $per = [];
    foreach ($g['grants'] as $gr) {
        $per[] = grant_dec($g, $o, $gr, $a, $h);
    }
    $d = min($d, $per ? max($per) : 0);
    if ($d !== 2) {
        return ['decision' => $d === 1 ? 'escalate' : 'deny', 'witness' => null];
    }
    $gr = $g['grants'][array_search(2, $per, true)];
    $bids = [];
    foreach ($g['bounds'] as $b) {
        if (applies(lsel($o, $b), $gr['gid'], $a['verb'])) {
            $bids[] = $b['bid'];
        }
    }
    return ['decision' => 'allow', 'witness' => ['gid' => $gr['gid'], 'bids' => $bids]];
}

// lowering (GoalCompile.dfy Lower) for the policy digest
const NEG = ['eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'gte' => 'lt', 'gt' => 'lte', 'lte' => 'gt', 'in' => 'nin', 'nin' => 'in'];
function nnf(array $c, bool $pos): array
{
    switch ($c['k']) {
        case 'true': return ['k' => $pos ? 'true' : 'false'];
        case 'cmp': return ['k' => 'atom', 'op' => $pos ? $c['op'] : NEG[$c['op']], 'l' => $c['l'], 'r' => $c['r']];
        case 'and': return ['k' => $pos ? 'and' : 'or', 'a' => nnf($c['a'], $pos), 'b' => nnf($c['b'], $pos)];
        case 'or': return ['k' => $pos ? 'or' : 'and', 'a' => nnf($c['a'], $pos), 'b' => nnf($c['b'], $pos)];
    }
    return nnf($c['c'], !$pos);
}
function pat(?array $p): array { return $p === null ? ['k' => 'star'] : ['k' => 'set', 'ids' => $p]; }
function lower(array $o, array $goal): array
{
    $g = strip_holes($goal);
    $ceils = [];
    foreach ($g['bounds'] as $b) {
        $s = lsel($o, $b);
        $ceils[] = ['bid' => $b['bid'], 'selGids' => $s[0], 'selVerbs' => $s[1], 'agg' => $b['agg'], 'value' => $b['value'], 'key' => $b['key'], 'window' => $b['window'], 'scope' => $b['scope'], 'cap' => $b['cap'], 'onExceed' => $b['onExceed']];
    }
    return [
        'preds' => array_map(fn($x) => ['gid' => $x['gid'], 'verb' => $x['verb'], 'res' => pat(resolve_res($o, $x['res'])), 'cond' => nnf($x['cond'], true)], $g['grants']),
        'prohs' => array_map(fn($p) => ['pid' => $p['pid'], 'verbs' => proh_verbs($o, $p), 'res' => pat(resolve_res($o, $p['res'])), 'cond' => nnf($p['cond'], true)], $g['prohibits']),
        'ceils' => $ceils, 'escs' => array_map(fn($c) => nnf($c, true), $g['escalateOn']), 'validity' => $g['validity'], 'deleg' => $g['deleg'],
    ];
}

// ---- selector expansion (pca-goal selectors.ts / formal/dafny/GoalSelect.dfy)
/** An unconfirmed verb carries pca.unreviewed (it is the top of the registry): a class ALLOW never covers it (float = false), a class PROHIBITION or bound over a trait selector ALWAYS covers it, whatever all_of and none_of say (float = true). */
function class_verbs(array $cat, array $all, array $none, bool $float): array
{
    $out = [];
    foreach ($cat['verbs'] as $v) {
        $inClass = true;
        foreach ($all as $t) {
            $inClass = $inClass && in_array($t, $v['traits'], true);
        }
        foreach ($none as $t) {
            $inClass = $inClass && !in_array($t, $v['traits'], true);
        }
        $unrev = in_array('pca.unreviewed', $v['traits'], true);
        if ($float ? ($unrev || $inClass) : ($inClass && !$unrev)) {
            $out[] = $v['verb'];
        }
    }
    return $out;
}
/** [path, ty] or null */
function resolve_role(array $ont, array $cat, string $verb, string $role): ?array
{
    $info = null;
    $decl = null;
    foreach ($cat['verbs'] as $v) {
        if ($v['verb'] === $verb) {
            $info = $v;
            break;
        }
    }
    foreach ($ont['verbs'] as $v) {
        if ($v['verb'] === $verb) {
            $decl = $v;
            break;
        }
    }
    if ($info === null || $decl === null) {
        return null;
    }
    $paths = $info['roles'][$role] ?? [];
    if (count($paths) !== 1) {
        return null;
    }
    foreach ($decl['params'] as $p) {
        if ($p['path'] === $paths[0]) {
            return [$p['path'], $p['ty']];
        }
    }
    return null;
}
function x_term(array $ont, array $cat, string $verb, array $t): ?array
{
    if ($t['k'] === 'role') {
        $r = resolve_role($ont, $cat, $verb, $t['role']);
        return $r === null ? null : ['k' => 'param', 'path' => $r[0], 'ty' => $r[1]];
    }
    return $t;
}
function x_cond(array $ont, array $cat, string $verb, array $c): ?array
{
    switch ($c['k']) {
        case 'true':
            return ['k' => 'true'];
        case 'cmp':
            $l = x_term($ont, $cat, $verb, $c['l']);
            $r = x_term($ont, $cat, $verb, $c['r']);
            return $l === null || $r === null ? null : ['k' => 'cmp', 'op' => $c['op'], 'l' => $l, 'r' => $r];
        case 'and':
        case 'or':
            $a = x_cond($ont, $cat, $verb, $c['a']);
            $b = x_cond($ont, $cat, $verb, $c['b']);
            return $a === null || $b === null ? null : ['k' => $c['k'], 'a' => $a, 'b' => $b];
    }
    $a = x_cond($ont, $cat, $verb, $c['c']);
    return $a === null ? null : ['k' => 'not', 'c' => $a];
}
function bound_value(array $ont, array $cat, array $vs, array $t): ?array
{
    if ($t['k'] !== 'role') {
        return $t;
    }
    $rs = [];
    foreach ($vs as $v) {
        $r = resolve_role($ont, $cat, $v, $t['role']);
        if ($r === null) {
            return null;
        }
        $rs[] = $r;
    }
    if (!$rs) {
        return null;
    }
    $same = true;
    $sameTy = true;
    foreach ($rs as $r) {
        $same = $same && $r[0] === $rs[0][0] && canon($r[1]) === canon($rs[0][1]);
        $sameTy = $sameTy && canon($r[1]) === canon($rs[0][1]);
    }
    if ($same) {
        return ['k' => 'param', 'path' => $rs[0][0], 'ty' => $rs[0][1]];
    }
    if ($sameTy) {
        return ['k' => 'param', 'path' => '@' . $t['role'], 'ty' => $rs[0][1]];
    }
    return null;
}
function expand_sel(array $sg, array $ont, array $cat): array
{
    $es = [];
    foreach ($sg['grants'] as $gr) {
        $s = $gr['sel'];
        $verbs = $s['k'] === 'verb' ? [$s['verb']] : class_verbs($cat, $s['all_of'], $s['none_of'], false);
        foreach ($verbs as $v) {
            $c = x_cond($ont, $cat, $v, $gr['cond']);
            if ($c === null) {
                continue;
            }
            $es[] = [$gr['gid'], ['gid' => $s['k'] === 'class' ? $gr['gid'] . '.' . $v : $gr['gid'], 'verb' => $v, 'res' => $gr['res'], 'cond' => $c]];
        }
    }
    $ids_of = fn(array $srcs) => array_values(array_map(fn($e) => $e[1]['gid'], array_filter($es, fn($e) => in_array($e[0], $srcs, true))));
    $gids_of_verbs = fn(array $vs) => array_values(array_map(fn($e) => $e[1]['gid'], array_filter($es, fn($e) => in_array($e[1]['verb'], $vs, true))));
    $verbs_of_gids = fn(array $g) => array_values(array_map(fn($e) => $e[1]['verb'], array_filter($es, fn($e) => in_array($e[1]['gid'], $g, true))));
    $prohibits = [];
    foreach ($sg['prohibits'] as $p) {
        $t = $p['target'];
        $verbs = $t['k'] === 'verb' ? [$t['verb']] : ($t['k'] === 'effect' ? verbs_of_class($ont, $t['cls']) : class_verbs($cat, $t['all_of'], $t['none_of'], true));
        foreach ($verbs as $v) {
            $c = x_cond($ont, $cat, $v, $p['cond']) ?? ['k' => 'true'];
            $prohibits[] = ['pid' => $t['k'] === 'verb' ? $p['pid'] : $p['pid'] . '.' . $v, 'target' => ['k' => 'verb', 'verb' => $v], 'res' => $p['res'], 'cond' => $c];
        }
    }
    $bounds = [];
    foreach ($sg['bounds'] as $b) {
        $s = $b['sel'];
        if ($s['k'] === 'gids') {
            $gids = $ids_of($s['gids']);
            $rv = $verbs_of_gids($gids);
        } elseif ($s['k'] === 'effect') {
            $gids = null;
            $rv = verbs_of_class($ont, $s['cls']);
        } else {
            $gids = $gids_of_verbs(class_verbs($cat, $s['all_of'], $s['none_of'], true));
            $rv = $verbs_of_gids($gids);
        }
        $val = bound_value($ont, $cat, $rv, $b['value']);
        if ($val === null || ($gids !== null && !$gids)) {
            continue;
        }
        $sel = $gids === null ? ['k' => 'effect', 'cls' => $s['cls']] : ['k' => 'gids', 'gids' => $gids];
        $bounds[] = ['bid' => $b['bid'], 'sel' => $sel, 'agg' => $b['agg'], 'value' => $val, 'key' => $b['key'], 'window' => $b['window'], 'scope' => $b['scope'], 'cap' => $b['cap'], 'onExceed' => $b['onExceed']];
    }
    return [
        'v' => 1, 'principal' => $sg['principal'], 'ontDigest' => $sg['ontDigest'], 'nlDigest' => $sg['nlDigest'], 'sources' => $sg['sources'],
        'grants' => array_map(fn($e) => $e[1], $es), 'prohibits' => $prohibits, 'bounds' => $bounds, 'validity' => $sg['validity'],
        'deleg' => array_merge($sg['deleg'], ['mayTouch' => $ids_of($sg['deleg']['mayTouch'])]), 'escalateOn' => $sg['escalateOn'],
        'wildcardAck' => $ids_of($sg['wildcardAck']),
        'holes' => array_map(fn($h) => array_merge($h, ['affects' => $ids_of($h['affects'])]), $sg['holes']),
    ];
}

const RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];
function meet(string $d, string $s): string { return isset(RANK[$s]) && RANK[$s] < RANK[$d] ? $s : $d; }
function polarity(array $ws): array
{
    $out = [];
    $walk = function (array $c) use (&$walk, &$out): void {
        if ($c['k'] === 'and' || $c['k'] === 'or') {
            $walk($c['a']);
            $walk($c['b']);
        } elseif ($c['k'] === 'not') {
            $walk($c['c']);
        } elseif ($c['k'] === 'cmp') {
            foreach ([$c['l'], $c['r']] as $t) {
                if ($t['k'] === 'param') {
                    foreach (['env.class.', 'env.prov.', 'env.judge.', 'env.world.'] as $p) {
                        if (str_starts_with($t['path'], $p)) {
                            $out[$t['path']] = true;
                        }
                    }
                }
            }
        }
    };
    foreach ($ws as $w) {
        $walk($w);
    }
    $ks = array_map('strval', array_keys($out));
    usort($ks, 'strcmp');
    return $ks;
}
function units(mixed $schema, mixed $terms): array
{
    $bad = [];
    foreach (is_array($terms) ? $terms : [] as $p => $u) {
        if (!has_key($schema, (string)$p) || canon($schema[$p]) !== canon($u)) {
            $bad[] = (string)$p;
        }
    }
    usort($bad, 'strcmp');
    return $bad;
}
function pep(string $d, mixed $ctx, mixed $ans): bool
{
    if ($d === 'allow') {
        return true;
    }
    if ($d === 'deny') {
        return false;
    }
    if ($ans === null || $ans === false) {
        return false;
    }
    foreach (['policy_digest', 'action_digest', 'history_head'] as $k) {
        if ($ans[$k] !== $ctx[$k]) {
            return false;
        }
    }
    return $ans['valid'] === true;
}
function commit(string $g, string $p, string $s): string
{
    return b64u(hash('sha256', sprintf('pca-goal:v3:commit:%s:%s:%s', $g, $p, $s), true));
}
function run_fn(array $v): mixed
{
    $i = $v['input'];
    switch ($v['fn']) {
        case 'canon': return ['canon' => canon($i), 'digest' => goal_digest($i)];
        case 'units': return units($i['schema'], $i['terms']);
        case 'polarity': return polarity($i);
        case 'meet': return meet($i['decision'], $i['signal']);
        case 'pep': return pep($i['decision'], $i['ctx'], $i['answer']);
        case 'commit': return ['commit' => commit($i['goal_digest'], $i['policy_digest'], $i['salt']), 'opens_other_goal' => false];
        case 'claim': return $i['replayed_ppm'] !== null && $i['replayed_ppm'] < $i['min_ppm'] ? meet($i['base'], 'escalate') : $i['base'];
    }
    fwrite(STDERR, 'unknown fn ' . $v['fn'] . "\n");
    exit(2);
}

function main(string $d): void
{
    $bad = [];
    $n = 0;
    $probes = 0;
    $files = scandir($d) ?: [];
    sort($files, SORT_STRING);
    foreach ($files as $f) {
        if ($f === 'index.json' || !str_ends_with($f, '.json')) {
            continue;
        }
        $v = plain(json_decode((string)file_get_contents($d . '/' . $f), false, 512, JSON_THROW_ON_ERROR));
        $n++;
        if ($v['kind'] === 'fn') {
            if (canon(run_fn($v)) !== canon($v['expect'])) {
                $bad[] = $v['id'];
            }
            continue;
        }
        if (isset($v['sel']) && canon(expand_sel($v['sel']['goal'], $v['ontology'], $v['sel']['catalog'])) !== canon($v['goal'])) {
            $bad[] = $v['id'] . ':expansion';
        }
        if (goal_digest($v['goal']) !== $v['goal_digest']) {
            $bad[] = $v['id'] . ':goal_digest';
        }
        if ($v['compile']['ok'] !== true) {
            continue;
        }
        if (hash_canon(lower($v['ontology'], $v['goal'])) !== $v['policy_digest']) {
            $bad[] = $v['id'] . ':policy_digest';
        }
        foreach ($v['probes'] as $i => $p) {
            $probes++;
            if (canon(decide($v['goal'], $v['ontology'], $p['action'], $p['history'])) !== canon($p['expect'])) {
                $bad[] = sprintf('%s#%d', $v['id'], $i);
            }
        }
    }
    printf("php: %d vectors, %d probes, %d disagreements\n", $n, $probes, count($bad));
    foreach (array_slice($bad, 0, 20) as $b) {
        echo '   ', $b, "\n";
    }
    exit($bad !== [] || $n === 0 ? 1 : 0);
}

main($argv[1] ?? '');
