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
    // The nested context objects (intent_policy, intent_v2) are re-encoded below for the library's own parser: take them
    // from an OBJECT decode, since the assoc decode above turns an empty JSON object ({} - e.g. acc.monitors) into [],
    // which re-encodes as a JSON array and the closed typed v2 policy then (rightly) refuses.
    $co = json_decode($line, false);
    $r = ['id' => $c['id']];
    try {
        if ($c['kind'] === 'suites') {
            // Suite-capability manifest (packages/pca/conformance/SUITES.md).
            $r['suites'] = Pca::supportedSuites();
        } elseif ($c['kind'] === 'verify') {
            $grant = Json::parseLax($c['grant']);
            // Intent Layer M2: optional `intent_policy` (a JSON object, parsed into an Obj tree; a JSON-encoded string is
            // also accepted). Re-parsed through the library's JSON so numbers keep their lexeme (0.5 stays non-integral).
            $ip = null;
            if (isset($c['intent_policy_json'])) { // raw JSON text (wins); parseLax keeps every number lexeme
                $ip = Json::parseLax($c['intent_policy_json']);
            } elseif (isset($c['intent_policy'])) {
                $ipText = is_string($c['intent_policy']) ? $c['intent_policy'] : json_encode($co->intent_policy, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
                $ip = Json::parseLax($ipText);
            }
            // Intent Layer v2: optional `intent_v2` verifier state (a JSON object, or its JSON text), re-parsed with the library's
            // lax loader so every number keeps its lexeme (judged by value in the v2 checks).
            $v2 = null;
            if (isset($c['intent_v2'])) {
                $v2Text = is_string($c['intent_v2']) ? $c['intent_v2'] : json_encode($co->intent_v2, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
                $v2p = Json::parseLax($v2Text);
                $v2 = $v2p instanceof \Atlas\Pca\Obj ? $v2p : null;
            }
            $g = Pca::verifyJson($c['raw'], $grant, (int)$c['now'], $c['aud'], isset($c['allowed_suites']) ? $c['allowed_suites'] : null, $ip, $v2);
            $r['allow'] = (bool)$g['allow'];
            $ch = [];
            foreach ($g['checks'] as $k => $v) $ch[(string)$k] = $v === true;
            $r['checks'] = $ch;
            if (str_contains((string)$g['reason'], Pca::UNSUPPORTED_SUITE)) {
                $r['unsupported_suite'] = $g['reason'];
            }
        } elseif ($c['kind'] === 'chain') {
            // R4-01: standalone verifyChain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
            $ch_ = Json::parseLax($c['raw']);
            $eri = $ch_->has('expected_root_issuer') ? $ch_->get('expected_root_issuer') : null;
            [$why, $ok] = Pca::verifyChain($ch_->get('chain'), $eri, is_string($eri),
                $ch_->has('allowed_suites') ? $ch_->get('allowed_suites') : null,
                $ch_->has('pq_pins') ? $ch_->get('pq_pins') : null,
                $ch_->has('trusted_root') ? $ch_->get('trusted_root') : null);
            $r['allow'] = $ok === true;
            $r['checks'] = ['chain' => $ok === true];
            if (is_string($why) && str_contains($why, Pca::UNSUPPORTED_SUITE)) {
                $r['unsupported_suite'] = $why;
            }
        } elseif ($c['kind'] === 'policy') {
            // Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
            // the agent-native evaluator (predicates + tool_schema) over policyCaveats(grant, chain), as {allow, failed}: the action
            // context is {action}, the tool call the signed verb + params (the reference's toolCallOf)
            $pv = Json::parseLax($c['raw']);
            $act = $pv->get('context') instanceof \Atlas\Pca\Obj ? $pv->get('context')->get('action') : null;
            $actObj = $act instanceof \Atlas\Pca\Obj;
            $params = $actObj ? $act->get('params') : null;
            $call = ['tool' => $actObj && is_string($act->get('verb')) ? $act->get('verb') : '',
                'args' => $params instanceof \Atlas\Pca\Obj ? $params : new \Atlas\Pca\Obj()];
            $res = \Atlas\Pca\Authorize::evaluateAgentCaveats(Pca::policyCaveats($pv->get('grant'), $pv->get('chain')), $pv->get('context'), \Atlas\Pca\Obj::of(['action' => $act]), $call);
            $r['allow'] = $res['ok'] === true;
            $r['failed'] = array_values($res['failed']);
        } elseif (str_starts_with((string)$c['kind'], 'intent_')) {
            // Intent Layer v2 primitives: raw = JSON text of the primitive's `input`; result = its conformance `expect` shape
            // (IntentV2::primitive, the entry the native runners use), written as canonical JSON.
            // README "Raw JSON text members": an `input_json` member (the whole input as raw text) wins over `raw`.
            $res = \Atlas\Pca\IntentV2::primitive($c['kind'], Json::parseLax(is_string($c['input_json'] ?? null) ? $c['input_json'] : $c['raw']));
            if ($res === null) {
                $r['error'] = 'exception:' . $c['kind'];
            } else {
                fwrite($o, '{"id":' . json_encode($c['id']) . ',"result":' . \Atlas\Pca\IntentV2::canonicalize($res[0]) . "}\n");
                continue;
            }
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
