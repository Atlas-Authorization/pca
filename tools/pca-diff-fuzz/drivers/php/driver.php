<?php
declare(strict_types=1);
require_once __DIR__ . '/../../../../sdks/php-pca/src/Pca.php';
use Atlas\Pca\Json;
use Atlas\Pca\Pca;
ini_set('memory_limit', '2G');
[$_, $inp, $outp] = $argv;
$o = fopen($outp, 'w');
foreach (file($inp, FILE_IGNORE_NEW_LINES) as $line) {
    $c = json_decode($line, true);
    $r = ['id' => $c['id']];
    try {
        if ($c['kind'] === 'verify') {
            $grant = Json::parseLax($c['grant']);
            $g = Pca::verifyJson($c['raw'], $grant, (int)$c['now'], $c['aud'], isset($c['allowed_suites']) ? $c['allowed_suites'] : null);
            $r['allow'] = (bool)$g['allow'];
            $ch = [];
            foreach ($g['checks'] as $k => $v) $ch[(string)$k] = $v === true;
            $r['checks'] = $ch;
        } elseif ($c['kind'] === 'chain') {
            // R4-01: standalone verifyChain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
            $ch_ = Json::parseLax($c['raw']);
            $eri = $ch_->has('expected_root_issuer') ? $ch_->get('expected_root_issuer') : null;
            [, $ok] = Pca::verifyChain($ch_->get('chain'), $eri, is_string($eri),
                $ch_->has('allowed_suites') ? $ch_->get('allowed_suites') : null,
                $ch_->has('pq_pins') ? $ch_->get('pq_pins') : null,
                $ch_->has('trusted_root') ? $ch_->get('trusted_root') : null);
            $r['allow'] = $ok === true;
            $r['checks'] = ['chain' => $ok === true];
        } else {
            try { $v = Json::parseStrict($c['raw']); $s = Json::canonicalizeStrict($v); } catch (\Throwable $e) { $r['error'] = 'parse'; }
            if (!isset($r['error'])) { $r['canon'] = $s; $r['hash'] = Pca::hashCanonical($v); }
        }
    } catch (\Throwable $e) {
        $r = ['id' => $c['id'], 'error' => 'exception:' . get_class($e)];
    }
    fwrite($o, json_encode($r, JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
}
fclose($o);
