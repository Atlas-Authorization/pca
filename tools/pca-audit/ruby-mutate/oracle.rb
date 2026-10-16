# frozen_string_literal: true

# Oracle for the Ruby mutation runner: unit tests + corpus + characterization snapshot. Everything is loaded once in
# the parent; each forked child re-defines the library from the mutated text and calls Oracle.run (true == all pass).
$LOAD_PATH.unshift(File.expand_path('../../../sdks/ruby-pca/lib', __dir__))
require 'atlas_pca'
require 'atlas_pca/rack_middleware'
require_relative '../../../sdks/ruby-pca/test/support/corpus'

module Oracle
  # This runtime's capability manifest, read ONCE from the unmutated library (the same rule as conformance.rb's
  # SUPPORTED_SIG_SUITES; a hard-coded Ed25519/ML-DSA-65 list went stale when 0.4.x added ML-DSA-87, SLH-DSA and LESS).
  SUPPORTED = AtlasPca.supported_suites.freeze
  ROOT = File.expand_path('../../../sdks/ruby-pca', __dir__)

  module_function

  # A mutant that edits the file header (the `require`s) is also loaded in a FRESH ruby (--disable-gems): inside this process
  # digest/base64/openssl are already loaded, so deleting a require is invisible here. The fresh process must hash and verify
  # a known Ed25519 signature exactly like the original.
  HEADER = 12
  PROBE = <<~'RUBY'
    eval($stdin.read, TOPLEVEL_BINDING) # rubocop:disable Security/Eval
    ok = AtlasPca.hash_canonical({ 'a' => 1 }) == ARGV[2] &&
         AtlasPca::Ed25519Strict.verify([ARGV[0]].pack('H*'), 'probe', [ARGV[1]].pack('H*')) == true
    exit(ok ? 0 : 1)
  RUBY

  def fresh_load_ok?
    return true if @text.lines.first(HEADER) == @orig.lines.first(HEADER)

    IO.popen([RbConfig.ruby, '--disable-gems', '-e', PROBE, *@probe_args], 'w', err: File::NULL, out: File::NULL) { |io| io.write(@text) }
    $?.success?
  end

  def prepare(_file)
    @orig = File.read(_file)
    k = OpenSSL::PKey.new_raw_private_key('ED25519', "\x05".b * 32)
    @probe_args = [k.raw_public_key.unpack1('H*'), k.sign(nil, 'probe').unpack1('H*'), AtlasPca.hash_canonical({ 'a' => 1 })]
    Corpus.core
    Corpus.adv
    Corpus.snapshot
    @tests = []
    Dir[File.join(ROOT, 'test', 'kill', '*.rb')].sort.each { |f| load f }
    # a test that `needs` a suite this runtime lacks is skipped, as run_kill.rb does (it would fail on the unmutated source)
    @tests.concat(MutationKill::TESTS.select { |_, _, needs| needs.nil? || SUPPORTED.include?(needs) }) if defined?(MutationKill::TESTS)
    # MUT_FIRST=<prefix>: run the kill tests whose name starts with <prefix> first (a scoped pass reaches its own tests without
    # sitting through every slow earlier one per mutant). Order only: every test still has to pass, so verdicts are unchanged.
    if (pre = ENV['MUT_FIRST']) && !pre.empty?
      @tests = @tests.partition { |n, _| n.start_with?(pre) }.flatten(1)
    end
    @prepared_core = Corpus.compute(Corpus.core, 'core', 0, 1)
    @adv_vectors = Corpus.adv['vectors']
  end

  # The mutant REPLACES the library: the loaded module is dropped first, so a deleted def / constant / module_function
  # is really gone (evaluating on top of the loaded module kept the original definition and every deletion "survived").
  # atlas_pca.rb ends with `require_relative` lines for the files that reopen AtlasPca (the Intent Layer v2 files:
  # safe_regex, predicates, intent_layers, intent_wb, intent_v2). Those are already in $LOADED_FEATURES, so evaluating the
  # library text again does NOT reload them: without the step below every v2 method would vanish with the dropped module
  # (and a mutant of one of those files would never be exercised). So after the library each extension is re-evaluated
  # explicitly, in the library's require order, then the Rack middleware. Whichever of these FILES is being mutated is
  # evaluated from the mutated text; every other one from disk, unmutated.
  LIB = File.join(ROOT, 'lib', 'atlas_pca.rb')
  MW = File.join(ROOT, 'lib', 'atlas_pca', 'rack_middleware.rb')
  EXTENSIONS = File.read(LIB).scan(/^require_relative '(atlas_pca\/[a-z0-9_]+)'$/).flatten
                   .map { |rel| File.join(ROOT, 'lib', "#{rel}.rb") }.freeze
  def apply(text, file)
    @text = text
    target = File.expand_path(file)
    src = ->(path) { File.expand_path(path) == target ? text : File.read(path) }
    Object.send(:remove_const, :AtlasPca) if Object.const_defined?(:AtlasPca)
    [LIB, *EXTENSIONS, MW].each { |path| eval(src.call(path), TOPLEVEL_BINDING, path) } # rubocop:disable Security/Eval
  end

  # The suite a vector needs that this runtime lacks (conformance.rb's unsupported_suite), or nil. A terminal
  # {wire:false} negative is suite-agnostic and is compared as usual.
  def unsupported(v)
    p = v['pcactn']
    return nil unless p.is_a?(Hash)

    alg = ->(o) { o.is_a?(Hash) && o['alg'].is_a?(String) ? o['alg'] : 'ed25519' }
    sus = case v['requires']
          when 'pq' then (a = alg.call(p); SUPPORTED.include?(a) ? nil : a)
          when 'pq-nonleaf' then (p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []).map { |h| alg.call(h) }.find { |a| !SUPPORTED.include?(a) }
          # 0.4.1 (same rule as conformance.rb): a vector naming one concrete suite (`requires: "ml-dsa-87"`) Ruby lacks
          when String then (r = v['requires']; r.empty? || SUPPORTED.include?(r) ? nil : r)
          end
    c = v['expect']['checks']
    sus && !(c.keys == ['wire'] && c['wire'] == false) ? sus : nil
  end

  # Intent Layer v2 `requires_suite` naming a suite this runtime lacks (fn-dsa-*): Corpus.prim_failures checks those
  # (a deny, unsupported_suite when a v2 check fails first), exactly as conformance.rb does.
  def v2_unsupported?(v)
    rs = v['requires_suite']
    rs.is_a?(String) && !SUPPORTED.include?(rs)
  end

  def skip?(v)
    !unsupported(v).nil? || v2_unsupported?(v)
  end

  def check_vectors(doc, tag)
    exp = Corpus.snapshot
    doc['vectors'].each do |v|
      next if v2_unsupported?(v)

      if unsupported(v)
        # conformance.rb: a vector needing a suite this runtime lacks must be DENIED with unsupported_suite (never skipped)
        next unless v['pcactn'].is_a?(Hash)

        ctx = v['context']
        got = AtlasPca.verify_pcactn(v['pcactn'], v['grant'], now: ctx['now'], audience: ctx['aud'])
        return false unless got.allow == false && got.reason.to_s.include?(AtlasPca::UNSUPPORTED_SUITE)

        next
      end
      key = Corpus.esc("#{tag}:v:#{v['name']}")
      got = Corpus.verify_one(v)
      return false unless got.allow == v['expect']['allow']
      return false unless got.checks == v['expect']['checks']

      want = exp[key]
      next unless want

      return false unless "#{got.allow}|#{got.checks.map { |ck, cv| "#{ck}=#{cv}" }.join(',')}|#{Corpus.esc(got.reason)}" == want
    end
    true
  rescue StandardError, SystemStackError
    false
  end

  def check_snapshot_prims(doc, tag)
    exp = Corpus.snapshot
    Corpus.compute({ 'vectors' => [], 'primitives' => doc['primitives'] }, tag, 0, 1).each do |k, v|
      want = exp[Corpus.esc(k)]
      return false if want && want != v
    end
    true
  rescue StandardError, SystemStackError
    false
  end

  def check_inputs
    exp = Corpus.snapshot
    Corpus.compute_inputs(0, 1).each do |k, v|
      want = exp[Corpus.esc(k)]
      return false if want && want != v
    end
    true
  rescue StandardError, SystemStackError
    false
  end

  # Per-stage verdicts (debugging a surprising survivor): ruby mutate.rb FILE --only ID --debug
  def stages
    t = @tests.map { |n, fn| [n, (fn.call rescue false)] }.reject { |_, ok| ok }.map(&:first)
    { 'failing_tests' => t, 'core_vectors' => check_vectors(Corpus.core, 'core'), 'prims' => Corpus.prim_failures(Corpus.core),
      'core_snapshot' => check_snapshot_prims(Corpus.core, 'core'), 'inputs' => check_inputs,
      'adv_vectors' => check_vectors(Corpus.adv, 'adv'), 'adv_snapshot' => check_snapshot_prims(Corpus.adv, 'adv') }
  end

  def run
    return false unless fresh_load_ok?

    @tests.each do |name, fn|
      begin
        return false unless fn.call
      rescue StandardError, SystemStackError
        return false
      end
    end
    # every other conformance table (merkle, params_digest, threshold_share/set, signer_set_hash, chain_pin, pq_artifact,
    # malformed, depth): conformance.rb checks them, so the oracle must too
    check_vectors(Corpus.core, 'core') && Corpus.prim_failures(Corpus.core).empty? &&
      check_snapshot_prims(Corpus.core, 'core') && check_inputs &&
      check_vectors(Corpus.adv, 'adv') && check_snapshot_prims(Corpus.adv, 'adv')
  end
end
