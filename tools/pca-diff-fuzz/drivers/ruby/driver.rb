require 'json'
require_relative '../../../../sdks/ruby-pca/lib/atlas_pca'

# Intent Layer v2 primitive kinds: raw = JSON text of the primitive's `input`; the response is {id, result: <exactly the
# expect shape of that primitive>} (reasons are never part of it).
V2_PRIMITIVES = {
  'intent_schema' => lambda do |i|
    sig = AtlasPca.verify_action_schema(i['schema'], i['keys'])['ok']
    c = AtlasPca.conform_action(i['schema'], i['verb'], i['params'])
    out = { 'sig' => sig }
    out['digest'] = AtlasPca.action_schema_digest(i['schema']) if sig
    out['conform'] = c['ok'] ? { 'ok' => true } : { 'ok' => false, 'code' => c['code'] }.merge(c['path'] ? { 'path' => c['path'] } : {})
    out
  end,
  'intent_revocation' => ->(i) { { 'ok' => AtlasPca.intent_revocation_primitive(i)['ok'] } },
  'intent_world' => lambda do |i|
    g = AtlasPca.decide_intent_world(i)
    g['ok'] ? { 'ok' => true, 'world' => g['world'], 'single_source' => g['single_source'] } : { 'ok' => false }
  end,
  'intent_provenance' => lambda do |i|
    g = AtlasPca.decide_param_provenance(i)
    out = { 'outcome' => g['outcome'] }
    out.merge!('labels' => g['labels'], 'classes' => g['classes']) unless g['outcome'] == 'deny'
    out['friction'] = g['friction'] if g['outcome'] == 'question'
    out
  end,
  'intent_classifier' => lambda do |i|
    g = AtlasPca.decide_classifier_dimensions(i)
    g['ok'] ? { 'ok' => true, 'classes' => g['classes'] } : { 'ok' => false }
  end,
  'intent_wb_active' => ->(i) { AtlasPca.intent_wb_active(i).slice('facts', 'provenance', 'classes') },
  'intent_read_purpose' => ->(i) { AtlasPca.decide_read_purpose(i).slice('outcome', 'minimise', 'uncovered') },
  'intent_map_commit' => ->(i) { { 'map_commit' => AtlasPca.map_commit_of_leaves(i['leaves']) } },
  'intent_map' => lambda do |i|
    g = AtlasPca.intent_map_primitive(i)
    g['ok'] ? { 'ok' => true, 'cell' => g['cell'], 'p_ppm' => g['p_ppm'] } : { 'ok' => false }
  end
}.freeze

inp, outp = ARGV
File.open(outp, 'w') do |o|
  File.foreach(inp) do |line|
    c = JSON.parse(line)
    r = { 'id' => c['id'] }
    begin
      if c['kind'] == 'suites'
        # Suite-capability manifest (packages/pca/conformance/SUITES.md).
        r['suites'] = AtlasPca.supported_suites
      elsif c['kind'] == 'verify'
        grant = AtlasPca.parse_json(c['grant'], loose: true)
        # Intent Layer M2: optional `intent_policy_json` (raw JSON text, parsed with the platform parser; wins) or
        # `intent_policy` (a JSON object, or a JSON-encoded string).
        ip = c.key?('intent_policy_json') ? AtlasPca.parse_intent_policy_json(c['intent_policy_json']) : c['intent_policy']
        ip = AtlasPca.parse_json_text(ip) if ip.is_a?(String)
        # Intent Layer v2: optional `intent_v2` verifier state (a JSON object, or a JSON-encoded string).
        v2 = c['intent_v2']
        v2 = AtlasPca.parse_json_text(v2) if v2.is_a?(String)
        g = AtlasPca.verify_pcactn(c['raw'], grant, now: c['now'], audience: c['aud'], allowed_suites: c['allowed_suites'],
                                                    intent_policy: ip, intent_v2: v2)
        r['allow'] = g.allow ? true : false
        r['checks'] = g.checks.to_h { |k, v| [k.to_s, v ? true : false] }
        r['unsupported_suite'] = g.reason if g.reason.to_s.include?(AtlasPca::UNSUPPORTED_SUITE)
      elsif c['kind'] == 'policy'
        # Policy layer (packages/pca/conformance/LAYERS.md): raw = JSON text {grant, chain, context}; answers the caveat projection
        # the agent-native evaluator (predicates + tool_schema) over policy_caveats(grant, chain), as {allow, failed}; the action
        # context is {action}, the tool call the signed verb + params (the reference's toolCallOf)
        pv = AtlasPca.parse_json(c['raw'], loose: true)
        act = pv['context']['action']
        call = { 'tool' => act.is_a?(Hash) && act['verb'].is_a?(String) ? act['verb'] : '',
                 'args' => act.is_a?(Hash) && act['params'].is_a?(Hash) ? act['params'] : {} }
        ok, failed = AtlasPca.evaluate_agent_caveats(AtlasPca.policy_caveats(pv['grant'], pv['chain']), pv['context'], { 'action' => act }, call)
        r['allow'] = ok ? true : false
        r['failed'] = failed
      elsif V2_PRIMITIVES.key?(c['kind'])
        r['result'] = V2_PRIMITIVES[c['kind']].call(AtlasPca.parse_json_text(c['raw']))
      elsif c['kind'] == 'chain'
        # R4-01: standalone verify_chain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
        ch = AtlasPca.parse_json(c['raw'], loose: true)
        why, ok = AtlasPca.verify_chain(ch['chain'], ch['expected_root_issuer'], !ch['expected_root_issuer'].nil?, ch['allowed_suites'], ch['pq_pins'], ch['trusted_root'])
        r['allow'] = ok ? true : false
        r['checks'] = { 'chain' => ok ? true : false }
        r['unsupported_suite'] = why if why.to_s.include?(AtlasPca::UNSUPPORTED_SUITE)
      else
        begin
          v = AtlasPca.parse_json(c['raw'], any_top: true)
          s = AtlasPca.canonicalize(v)
        rescue StandardError, SystemStackError
          r['error'] = 'parse'
        end
        unless r['error']
          r['canon'] = s
          r['hash'] = AtlasPca.hash_canonical(v)
        end
      end
    rescue StandardError, SystemStackError => e
      r = { 'id' => c['id'], 'error' => "exception:#{e.class}" }
    end
    o.puts JSON.generate(r)
  end
end
