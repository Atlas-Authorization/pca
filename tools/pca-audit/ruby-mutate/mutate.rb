# frozen_string_literal: true

# Small AST-based mutation tester for the Ruby PCA verifier (mutant's licence is not OSS-compatible).
#   ruby mutate.rb <file.rb> [--list] [--jobs N] [--timeout S] [--only a,b]  > results.json
# Operators (per AST node): relational/arithmetic/bitwise swaps, `!` removal, && <-> ||, && / || operand drop,
# condition negate / true / false for if/unless/ternary/while/until, integer +1/-1/0, non-empty string -> "",
# true<->false, nil->false?, return value dropped, array/hash literal emptied, statement deletion (-> nil),
# predicate call (`foo?`) -> true / false, call -> receiver / first-arg, op-assign swaps.
# Each mutant is evaluated in a forked child that re-defines the library from the mutated source and then runs the
# oracle (oracle.rb): unit tests + core/adv corpus + snapshot. Exit 0 in the child == the oracle PASSED == SURVIVED.
require 'parser/current'
require 'json'
require 'optparse'

opts = { jobs: 4, timeout: 120 }
OptionParser.new do |o|
  o.on('--list') { opts[:list] = true }
  o.on('--jobs N', Integer) { |n| opts[:jobs] = n }
  o.on('--timeout S', Integer) { |n| opts[:timeout] = n }
  o.on('--only LIST') { |l| opts[:only] = l.split(',').map(&:to_i) }
  o.on('--lines A-B') { |l| opts[:lines] = Range.new(*l.split('-').map(&:to_i)) }
  # --survivors PREV.json: re-run only the mutants (matched by op + original + replacement text, NOT by id or line, which
  # shift when the source changes) that SURVIVED in a previous results file, plus every mutant that file never saw.
  o.on('--debug') { opts[:debug] = true }
  o.on('--survivors FILE') { |f| opts[:survivors] = f }
end.parse!
FILE = File.expand_path(ARGV.fetch(0))
SRC = File.read(FILE)

Mutant = Struct.new(:id, :line, :op, :orig, :repl, :text, :fn)

def parse_src(src)
  buf = Parser::Source::Buffer.new(FILE, source: src)
  Parser::CurrentRuby.new.parse(buf)
end

SWAP = {
  :== => :!=, :!= => :==, :< => :<=, :<= => :<, :> => :>=, :>= => :>, :+ => :-, :- => :+, :* => :/, :/ => :*,
  :% => :*, :& => :|, :| => :&, :^ => :&, :<< => :>>, :>> => :<<, :** => :*, :<=> => :==, :=== => :!=, :=~ => :!~, :!~ => :=~
}.freeze
PRED_SKIP = %i[frozen? respond_to?].freeze

def mutants_for(src)
  ast = parse_src(src)
  out = []
  fns = [] # enclosing def names (the site's `fn`)
  add = lambda do |node_or_range, repl, op|
    r = node_or_range.respond_to?(:loc) ? node_or_range.loc.expression : node_or_range
    orig = r.source
    next if orig == repl
    # begin_pos / end_pos are CHARACTER offsets (parser gem), so slice by characters: byteslice put every mutant after the first
    # multi-byte character (an em dash in a comment) at the wrong place, and those misplaced mutants "survived".
    # Self-check (aborts the run): the slice we replace must BE the node's own source text, so an offset-unit bug (bytes
    # vs characters) or a stale buffer can never silently mutate the wrong place again.
    abort "splice self-check failed at line #{r.line}: #{src[r.begin_pos...r.end_pos].inspect} != #{orig.inspect}" unless src[r.begin_pos...r.end_pos] == orig
    text = src[0...r.begin_pos] + repl + src[r.end_pos..]
    out << Mutant.new(out.size, r.line, op, orig, repl, text, fns.last)
  end
  walk = lambda do |n, parent|
    next unless n.is_a?(Parser::AST::Node)

    case n.type
    when :send
      recv, meth, *args = *n
      sel = n.loc.selector
      if SWAP.key?(meth) && recv && args.size == 1 && sel
        add.call(sel, SWAP[meth].to_s, "swap-#{meth}")
      elsif meth == :! && recv
        add.call(n, recv.loc.expression.source, 'drop-!')
      elsif meth == :-@ && recv
        add.call(n, recv.loc.expression.source, 'drop-unary-minus')
      end
      if meth.to_s.end_with?('?') && !PRED_SKIP.include?(meth) && recv
        add.call(n, 'true', "pred-true-#{meth}")
        add.call(n, 'false', "pred-false-#{meth}")
      end
      if recv && args.any? && n.loc.selector && meth.to_s =~ /\A[a-z_]/ && !meth.to_s.end_with?('=')
        add.call(n, recv.loc.expression.source, "call->recv-#{meth}")
        add.call(n, args[0].loc.expression.source, "call->arg-#{meth}")
      elsif recv && args.empty? && meth.to_s =~ /\A[a-z_]/ && !meth.to_s.end_with?('=', '?', '!') && n.loc.dot
        add.call(n, recv.loc.expression.source, "call->recv-#{meth}")
      end
    when :and, :or
      l, r = *n
      op = n.type == :and ? '&&' : '||'
      oth = n.type == :and ? '||' : '&&'
      kw = n.loc.operator.source
      add.call(n.loc.operator, kw == op ? oth : (kw == 'and' ? 'or' : 'and'), "swap-#{kw}")
      add.call(n, l.loc.expression.source, "drop-right-#{kw}")
      add.call(n, r.loc.expression.source, "drop-left-#{kw}")
    when :if
      cond = n.children[0]
      unless parent&.type == :elsif_marker
        add.call(cond, "!(#{cond.loc.expression.source})", 'cond-negate')
        add.call(cond, 'true', 'cond-true')
        add.call(cond, 'false', 'cond-false')
      end
    when :while, :until, :while_post, :until_post
      cond = n.children[0]
      add.call(cond, "!(#{cond.loc.expression.source})", 'loop-cond-negate')
      add.call(cond, 'false', 'loop-cond-false') if n.type == :while
    when :int
      v = n.children[0]
      src_i = n.loc.expression.source
      add.call(n, (v + 1).to_s, 'int+1')
      add.call(n, (v - 1).to_s, 'int-1') if v != 0 && !src_i.start_with?('0x')
      add.call(n, '0', 'int->0') if v.abs > 1
    when :str
      v = n.children[0]
      if n.loc.respond_to?(:begin) && n.loc.begin && !v.empty? && parent&.type != :dstr && parent&.type != :xstr && n.loc.begin.source != '<<'
        q = n.loc.begin.source
        close = n.loc.end.source
        add.call(n, "#{q}#{close}", 'str-empty') if q =~ /\A(?:"|')\z/
      end
    when :true then add.call(n, 'false', 'true->false')
    when :false then add.call(n, 'true', 'false->true')
    when :nil then add.call(n, 'false', 'nil->false') if parent && parent.type != :send
    when :return
      add.call(n, 'return', 'return-drop') if n.children.any?
      add.call(n, 'return nil', 'return-nil') if n.children.any?
    when :array
      add.call(n, '[]', 'array-empty') if n.children.any? && n.loc.begin
    when :hash
      add.call(n, '{}', 'hash-empty') if n.children.any? && n.loc.begin
    when :op_asgn
      lhs, op, rhs = *n
      sw = { :+ => :-, :- => :+, :* => :/, :/ => :*, :| => :&, :& => :|, :<< => :>> }[op]
      add.call(n.loc.operator, "#{sw}=", "opasgn-#{op}") if sw
    when :begin, :kwbegin
      kids = n.children
      if kids.size > 1 || (n.type == :begin && kids.size == 1 && n.loc.begin.nil?)
        kids.each_with_index do |k, idx|
          next unless k.is_a?(Parser::AST::Node)
          next if k.type == :send && k.children[1] == :private
          add.call(k, 'nil', 'stmt-delete') if k.loc.expression.line == k.loc.expression.last_line || true
        end
      end
    when :def, :defs
      body = n.children.last
      add.call(body, 'nil', 'body-delete') if body.is_a?(Parser::AST::Node) && ![:begin].include?(body.type)
    end
    fns.push(n.type == :def ? n.children[0].to_s : n.children[1].to_s) if %i[def defs].include?(n.type)
    n.children.each { |c| walk.call(c, n) }
    fns.pop if %i[def defs].include?(n.type)
  end
  walk.call(ast, nil)
  out
end

mutants = mutants_for(SRC)
# de-duplicate identical (line, text)
seen = {}
mutants = mutants.select { |m| seen[[m.line, m.text]] ? false : (seen[[m.line, m.text]] = true) }
# --lines without --only: scope BEFORE the (slow: one full re-parse per mutant) syntax validation. Ids are then local to the
# scoped run; mutants are matched across runs by op + orig + repl (and the site key), never by id.
mutants = mutants.select { |m| opts[:lines].cover?(m.line) } if opts[:lines] && !opts[:only]
# validate syntax (drop mutants that no longer parse)
mutants = mutants.select do |m|
  begin
    Parser::Base.class_eval { }
    buf = Parser::Source::Buffer.new(FILE, source: m.text)
    p = Parser::CurrentRuby.new
    p.diagnostics.all_errors_are_fatal = true
    p.diagnostics.ignore_warnings = true
    p.parse(buf)
    true
  rescue Parser::SyntaxError
    false
  end
end
mutants.each_with_index { |m, i| m.id = i }
mutants = mutants.select { |m| opts[:only].include?(m.id) } if opts[:only]
mutants = mutants.select { |m| opts[:lines].cover?(m.line) } if opts[:lines]
if opts[:survivors]
  prev = JSON.parse(File.read(opts[:survivors]))
  mkey = ->(op, orig, repl) { [op, orig, repl] }
  seen_prev = prev.to_h { |x| [mkey.call(x['op'], x['orig'], x['repl']), true] }
  surv = prev.select { |x| x['status'] == 'SURVIVED' }.to_h { |x| [mkey.call(x['op'], x['orig'], x['repl']), true] }
  mutants = mutants.select { |m| k = mkey.call(m.op, m.orig, m.repl); surv[k] || !seen_prev[k] }
end

if opts[:list]
  mutants.each { |m| puts "#{m.id}\t#{m.line}\t#{m.op}\t#{m.orig.inspect[0, 60]} => #{m.repl.inspect[0, 60]}" }
  exit
end

# Site keys (tools/pca-audit/site-key.mjs): the trimmed source line, its occurrence among identical lines, the enclosing def.
SRC_LINES = SRC.split("\n", -1)
OCC = begin
  seen = Hash.new(0)
  SRC_LINES.each_with_index.to_h { |l, i| [i + 1, seen[l.strip] += 1] }
end
def mutant_label(m)
  sq = ->(s) { s.gsub(/\s+/, ' ')[0, 100] }
  "#{m.op}: #{sq.call(m.orig)} => #{sq.call(m.repl)}"
end

require_relative 'oracle'
Oracle.prepare(FILE)
$stderr.puts "mutants: #{mutants.size}"
# Baseline: the UNMUTATED source applied the same way must pass the oracle, else every mutant would be "killed".
base = fork do
  $stdout.reopen('/dev/null', 'w')
  $VERBOSE = nil
  Oracle.apply(SRC, FILE)
  exit!(Oracle.run ? 0 : 1)
rescue Exception # rubocop:disable Lint/RescueException
  exit!(2)
end
Process.wait(base)
abort "baseline oracle FAILED on the unmutated source (status #{$?.exitstatus})" unless $?.success?
if opts[:debug]
  mutants.each do |m|
    pid = fork do
      $VERBOSE = nil
      Oracle.apply(m.text, FILE)
      puts JSON.generate({ id: m.id, line: m.line, mutant: mutant_label(m), stages: Oracle.stages })
      $stdout.flush
      exit!(0)
    end
    Process.wait(pid)
  end
  exit
end

results = {}
running = {}
queue = mutants.dup
t0 = Time.now
until queue.empty? && running.empty?
  while running.size < opts[:jobs] && (m = queue.shift)
    r, w = IO.pipe
    pid = fork do
      r.close
      $stdout.reopen('/dev/null', 'w')
      $stderr.reopen('/dev/null', 'w')
      Thread.new { sleep opts[:timeout]; Process.kill('KILL', Process.pid) }
      status = begin
        $VERBOSE = nil
        Oracle.apply(m.text, FILE)
        Oracle.run ? 'SURVIVED' : 'KILLED'
      rescue Exception => e # rubocop:disable Lint/RescueException
        "KILLED"
      end
      w.write(status)
      w.close
      exit!(0)
    end
    w.close
    running[pid] = [m, r, Time.now]
  end
  pid, st = Process.wait2
  m, r, started = running.delete(pid)
  out = r.read
  r.close
  status = out.empty? ? (st.signaled? ? 'KILLED(timeout/crash)' : 'KILLED(crash)') : out
  results[m.id] = { id: m.id, line: m.line, op: m.op, orig: m.orig, repl: m.repl, status: status,
                   fn: m.fn, occurrence: OCC[m.line], line_text: SRC_LINES[m.line - 1].to_s.strip, mutant: mutant_label(m) }
  # MUT_STREAM=<file>: append each result as one JSON line the moment it completes (survives a wall-clock kill)
  File.open(ENV['MUT_STREAM'], 'a') { |f| f.puts(JSON.generate(results[m.id])) } if ENV['MUT_STREAM']
  $stderr.puts "#{results.size}/#{mutants.size} survivors=#{results.values.count { |x| x[:status] == 'SURVIVED' }} elapsed=#{(Time.now - t0).to_i}s" if (results.size % 50).zero?
end
puts JSON.pretty_generate(results.values.sort_by { |x| x[:id] })
