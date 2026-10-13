require 'json'
require_relative '../../../../sdks/ruby-pca/lib/atlas_pca'
inp, outp = ARGV
File.open(outp, 'w') do |o|
  File.foreach(inp) do |line|
    c = JSON.parse(line)
    r = { 'id' => c['id'] }
    begin
      if c['kind'] == 'verify'
        grant = AtlasPca.parse_json(c['grant'], loose: true)
        g = AtlasPca.verify_pcactn(c['raw'], grant, now: c['now'], audience: c['aud'], allowed_suites: c['allowed_suites'])
        r['allow'] = g.allow ? true : false
        r['checks'] = g.checks.to_h { |k, v| [k.to_s, v ? true : false] }
      elsif c['kind'] == 'chain'
        # R4-01: standalone verify_chain with verifier-side PQ authority; raw = {chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}
        ch = AtlasPca.parse_json(c['raw'], loose: true)
        _why, ok = AtlasPca.verify_chain(ch['chain'], ch['expected_root_issuer'], !ch['expected_root_issuer'].nil?, ch['allowed_suites'], ch['pq_pins'], ch['trusted_root'])
        r['allow'] = ok ? true : false
        r['checks'] = { 'chain' => ok ? true : false }
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
