<?php
declare(strict_types=1);

// PHP runner for the pca-goal vectors: goal digest, policy digest, decision + witness for every probe, and the fn vectors.
// Independent port of the reference semantics, no SDK code. Usage: php run.php <vectors-dir>
// Logic works on associative arrays; inputs that are canonicalised verbatim are decoded to stdClass so {} and [] stay distinct.

function canon(mixed $v): string
{
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
        static $short = [8 => '\\b', 9 => '\\t', 10 => '\\n', 12 => '\\f', 13 => '\\r'];
        $o = '"';
        for ($i = 0, $n = strlen($v); $i < $n; $i++) {
            $ch = $v[$i];
            $c = ord($ch);
            if ($ch === '"') {
                $o .= '\\"';
            } elseif ($ch === '\\') {
                $o .= '\\\\';
            } elseif (isset($short[$c])) {
                $o .= $short[$c];
            } elseif ($c < 0x20) {
                $o .= sprintf('\\u%04x', $c);
            } else {
                $o .= $ch;
            }
        }
        return $o . '"';
    }
    // shortcut: an empty PHP array canonicalises as [], so empty maps must arrive as stdClass
    if (is_array($v) && array_is_list($v)) {
        return '[' . implode(',', array_map('canon', $v)) . ']';
    }
    $m = is_object($v) ? get_object_vars($v) : $v;
    $ks = array_map('strval', array_keys($m));
    usort($ks, 'strcmp');
    $parts = [];
    foreach ($ks as $k) {
        $parts[] = canon($k) . ':' . canon(array_key_exists($k, $m) ? $m[$k] : $m[(int)$k]);
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
    return hash_canon((object)['d' => 'atlas-pca/goal-ir/v1', 'goal' => $g]);
}

function digest(string $kind, mixed $v): string
{
    return b64u(hash('sha256', sprintf('pca-goal:v1:%s:%s', $kind, canon($v)), true));
}

// Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow)
function k_not(int $a): int
{
    return 2 - $a;
}

function b2k(bool $b): int
{
    return $b ? 2 : 0;
}

function eq_v(array $x, array $y): int
{
    if ($x['k'] === 'q') {
        return $y['k'] === 'q' && $x['q']['u'] === $y['q']['u'] ? b2k($x['q']['n'] === $y['q']['n']) : 1;
    }
    if ($x['k'] === 's') {
        return $y['k'] === 's' ? b2k($x['s'] === $y['s']) : 1;
    }
    return 1;
}

function lt_v(array $x, array $y): int
{
    return $x['k'] === 'q' && $y['k'] === 'q' && $x['q']['u'] === $y['q']['u'] ? b2k($x['q']['n'] < $y['q']['n']) : 1;
}

function cmp_(string $op, ?array $x, ?array $y): int
{
    if ($x === null || $y === null) {
        return 1;
    }
    switch ($op) {
        case 'eq':
            return eq_v($x, $y);
        case 'ne':
            return k_not(eq_v($x, $y));
        case 'lt':
            return lt_v($x, $y);
        case 'gte':
            return k_not(lt_v($x, $y));
        case 'gt':
            return lt_v($y, $x);
        case 'lte':
            return k_not(lt_v($y, $x));
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

function term(array $t, array $a, array $h): ?array
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
        case 'true':
            return 2;
        case 'cmp':
            return cmp_($c['op'], term($c['l'], $a, $h), term($c['r'], $a, $h));
        case 'and':
            return min(cond($c['a'], $a, $h), cond($c['b'], $a, $h));
        case 'or':
            return max(cond($c['a'], $a, $h), cond($c['b'], $a, $h));
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

/** null means "any resource" */
function resolve(array $o, array $s): ?array
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

function res_ok(?array $p, string $r): bool
{
    return $p === null || in_array($r, $p, true);
}

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

/** @return array{0: array, 1: array} selected gids, selected verbs */
function lsel(array $o, array $b): array
{
    return $b['sel']['k'] === 'gids' ? [$b['sel']['gids'], []] : [[], verbs_of_class($o, $b['sel']['cls'])];
}

function applies(array $s, string $gid, string $verb): bool
{
    return in_array($gid, $s[0], true) || in_array($verb, $s[1], true);
}

function in_scope(array $b, array $a, array $x): bool
{
    $s = $b['scope'];
    switch ($s['k']) {
        case 'session':
            return $a['sess'] === $x['sess'];
        case 'principal':
            return $a['prin'] === $x['prin'];
        case 'org':
            return $a['org'] === $x['org'];
    }
    return in_array($a['agent'], $s['agents'], true) && in_array($x['agent'], $s['agents'], true);
}

function floor_div(int $a, int $b): int
{
    $q = intdiv($a, $b);
    return $a % $b !== 0 && (($a < 0) !== ($b < 0)) ? $q - 1 : $q;
}

function in_window(array $w, array $a, array $x): bool
{
    if ($w['k'] === 'sliding') {
        return $a['t'] - $w['ms'] < $x['t'] && $x['t'] <= $a['t'];
    }
    if ($w['k'] === 'period') {
        return $w['ms'] > 0 && floor_div($a['t'] - $w['t0'], $w['ms']) === floor_div($x['t'] - $w['t0'], $w['ms']);
    }
    return true;
}

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
            if (!array_key_exists($b['key'], $x['params'])) {
                return 1;
            }
            $vs[canon($x['params'][$b['key']])] = true;
        }
        return b2k(count($vs) > $b['cap']['n']);
    }
    $ns = [];
    foreach ($items as $x) {
        $v = term($b['value'], $x, $h);
        if ($v === null || $v['k'] !== 'q' || $v['q']['u'] !== $b['cap']['u']) {
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

function strip(array $g): array
{
    $g['grants'] = array_values(array_filter($g['grants'], function ($x) use ($g) {
        foreach ($g['holes'] as $h) {
            if ($h['global'] || in_array($x['gid'], $h['affects'], true)) {
                return false;
            }
        }
        return true;
    }));
    $g['holes'] = [];
    return $g;
}

function grant_dec(array $g, array $o, array $gr, array $a, array $h): int
{
    $deleg_ok = $a['depth'] === 0 || in_array($gr['gid'], $g['deleg']['mayTouch'], true);
    $m = min(
        b2k($a['verb'] === $gr['verb'] && $deleg_ok),
        b2k(res_ok(resolve($o, $gr['res']), $a['res'])),
        cond($gr['cond'], $a, $h)
    );
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
    $g = strip($goal);
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
        $m = min(b2k(in_array($a['verb'], proh_verbs($o, $p), true)), b2k(res_ok(resolve($o, $p['res']), $a['res'])), cond($p['cond'], $a, $h));
        $d = min($d, $m === 2 ? 0 : ($m === 1 ? 1 : 2));
    }
    foreach ($g['escalateOn'] as $c) {
        $d = min($d, cond($c, $a, $h) === 0 ? 2 : 1);
    }
    $per = array_map(fn($gr) => grant_dec($g, $o, $gr, $a, $h), $g['grants']);
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

// lowering for the policy digest
const NEG = ['eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'gte' => 'lt', 'gt' => 'lte', 'lte' => 'gt', 'in' => 'nin', 'nin' => 'in'];

function nnf(array $c, bool $pos): array
{
    switch ($c['k']) {
        case 'true':
            return ['k' => $pos ? 'true' : 'false'];
        case 'cmp':
            return ['k' => 'atom', 'op' => $pos ? $c['op'] : NEG[$c['op']], 'l' => $c['l'], 'r' => $c['r']];
        case 'and':
            return ['k' => $pos ? 'and' : 'or', 'a' => nnf($c['a'], $pos), 'b' => nnf($c['b'], $pos)];
        case 'or':
            return ['k' => $pos ? 'or' : 'and', 'a' => nnf($c['a'], $pos), 'b' => nnf($c['b'], $pos)];
    }
    return nnf($c['c'], !$pos);
}

function pat(?array $p): array
{
    return $p === null ? ['k' => 'star'] : ['k' => 'set', 'ids' => $p];
}

function lower(array $o, array $goal): array
{
    $g = strip($goal);
    $ceils = [];
    foreach ($g['bounds'] as $b) {
        $s = lsel($o, $b);
        $ceils[] = ['bid' => $b['bid'], 'selGids' => $s[0], 'selVerbs' => $s[1], 'agg' => $b['agg'], 'value' => $b['value'], 'key' => $b['key'], 'window' => $b['window'], 'scope' => $b['scope'], 'cap' => $b['cap'], 'onExceed' => $b['onExceed']];
    }
    return [
        'preds' => array_map(fn($x) => ['gid' => $x['gid'], 'verb' => $x['verb'], 'res' => pat(resolve($o, $x['res'])), 'cond' => nnf($x['cond'], true)], $g['grants']),
        'prohs' => array_map(fn($p) => ['pid' => $p['pid'], 'verbs' => proh_verbs($o, $p), 'res' => pat(resolve($o, $p['res'])), 'cond' => nnf($p['cond'], true)], $g['prohibits']),
        'ceils' => $ceils,
        'escs' => array_map(fn($c) => nnf($c, true), $g['escalateOn']),
        'validity' => $g['validity'],
        'deleg' => $g['deleg'],
    ];
}

const RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];

function meet(string $d, mixed $s): string
{
    return is_string($s) && isset(RANK[$s]) && RANK[$s] < RANK[$d] ? $s : $d;
}

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

function units(array $schema, array $terms): array
{
    $bad = [];
    foreach ($terms as $p => $t) {
        $p = (string)$p;
        if (!array_key_exists($p, $schema) || canon($schema[$p]) !== canon($t)) {
            $bad[] = $p;
        }
    }
    usort($bad, 'strcmp');
    return $bad;
}

function pep(string $d, array $ctx, ?array $ans): bool
{
    if ($d === 'allow') {
        return true;
    }
    if ($d === 'deny') {
        return false;
    }
    if (!$ans || !$ans['valid']) {
        return false;
    }
    foreach (['policy_digest', 'action_digest', 'history_head'] as $k) {
        if ($ans[$k] !== $ctx[$k]) {
            return false;
        }
    }
    return true;
}

function commit(string $g, string $p, string $s): string
{
    return b64u(hash('sha256', sprintf('pca-goal:v3:commit:%s:%s:%s', $g, $p, $s), true));
}

function claim(string $base, mixed $mn, mixed $cl, mixed $rp): string
{
    return $rp !== null && $rp < $mn ? meet($base, 'escalate') : $base;
}

function run_fn(array $v, object $raw): mixed
{
    $i = $v['input'];
    switch ($v['fn']) {
        case 'canon':
            return (object)['canon' => canon($raw->input), 'digest' => goal_digest($raw->input)];
        case 'units':
            return units($i['schema'], $i['terms']);
        case 'polarity':
            return polarity($i);
        case 'meet':
            return meet($i['decision'], $i['signal']);
        case 'pep':
            return pep($i['decision'], $i['ctx'], $i['answer']);
        case 'commit':
            return (object)['commit' => commit($i['goal_digest'], $i['policy_digest'], $i['salt']), 'opens_other_goal' => false];
        case 'claim':
            return claim($i['base'], $i['min_ppm'], $i['claimed_ppm'], $i['replayed_ppm']);
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
        $txt = (string)file_get_contents($d . '/' . $f);
        $v = json_decode($txt, true, 512, JSON_THROW_ON_ERROR);
        $raw = json_decode($txt, false, 512, JSON_THROW_ON_ERROR);
        $n++;
        if ($v['kind'] === 'fn') {
            if (canon(run_fn($v, $raw)) !== canon($raw->expect)) {
                $bad[] = $v['id'];
            }
            continue;
        }
        if (goal_digest($raw->goal) !== $v['goal_digest']) {
            $bad[] = $v['id'] . ':goal_digest';
        }
        if ($v['compile']['ok'] && hash_canon(lower($v['ontology'], $v['goal'])) !== $v['policy_digest']) {
            $bad[] = $v['id'] . ':policy_digest';
        }
        if (!$v['compile']['ok']) {
            continue;
        }
        foreach ($v['probes'] as $i => $p) {
            $probes++;
            $got = decide($v['goal'], $v['ontology'], $p['action'], $p['history']);
            if (canon($got) !== canon($raw->probes[$i]->expect)) {
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
