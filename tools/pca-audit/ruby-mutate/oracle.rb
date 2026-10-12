# frozen_string_literal: true

# Oracle for the Ruby mutation runner: unit tests + corpus + characterization snapshot. Everything is loaded once in
# the parent; each forked child re-defines the library from the mutated text and calls Oracle.run (true == all pass).
$LOAD_PATH.unshift(File.expand_path('../../../sdks/ruby-pca/lib', __dir__))
require 'atlas_pca'
require 'atlas_pca/rack_middleware'
require_relative '../../../sdks/ruby-pca/test/support/corpus'

module Oracle
  SUPPORTED = %w[ed25519 ml-dsa-65 hybrid-ed25519-ml-dsa-65].freeze
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
    @tests.concat(MutationKill::TESTS) if defined?(MutationKill::TESTS)
    @prepared_core = Corpus.compute(Corpus.core, 'core', 0, 1)
    @adv_vectors = Corpus.adv['vectors']
  end

  # The mutant REPLACES the library: the loaded module is dropped first, so a deleted def / constant / module_function
  # is really gone (evaluating on top of the loaded module kept the original definition and every deletion "survived").
  # The Rack middleware (which reopens AtlasPca) is then re-evaluated against the mutated module.
  def apply(text, file)
    @text = text
    Object.send(:remove_const, :AtlasPca) if Object.const_defined?(:AtlasPca)
    eval(text, TOPLEVEL_BINDING, file) # rubocop:disable Security/Eval
    mw = File.join(ROOT, 'lib', 'atlas_pca', 'rack_middleware.rb')
    eval(File.read(mw), TOPLEVEL_BINDING, mw) # rubocop:disable Security/Eval
  end

  def skip?(v)
    p = v['pcactn']
    return false unless p.is_a?(Hash)

    alg = ->(o) { o.is_a?(Hash) && o['alg'].is_a?(String) ? o['alg'] : 'ed25519' }
    sus = case v['requires']
          when 'pq' then (a = alg.call(p); SUPPORTED.include?(a) ? nil : a)
          when 'pq-nonleaf' then (p['cap_chain'].is_a?(Array) ? p['cap_chain'] : []).map { |h| alg.call(h) }.find { |a| !SUPPORTED.include?(a) }
          end
    c = v['expect']['checks']
    sus && !(c.keys == ['wire'] && c['wire'] == false)
  end

  def check_vectors(doc, tag)
    exp = Corpus.snapshot
    doc['vectors'].each do |v|
      next if skip?(v)

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
