# frozen_string_literal: true

# Small AST-based mutation tester for the Ruby PCA verifier (mutant's licence is not OSS-compatible).
#   ruby mutate.rb <file.rb> [--list] [--jobs N] [--timeout S] [--only a,b]  > results.json
# Operators (per AST node): relational/arithmetic/bitwise swaps, `!` removal, && <-> ||, && / || operand drop,
# condition negate / true / false for if/unless/ternary/while/until, integer +1/-1/0, non-empty string -> "",
# true<->false, nil->false?, return value dropped, array/hash literal emptied, statement deletion (-> nil),
# predicate call (`foo?`) -> true / false, call -> receiver / first-arg, op-assign swaps, one-statement bodies deleted (blocks, when,
# else, rescue, ensure, loops), `when` never matching, `||=` -> `=`, `&.` -> `.`, regexp never matching, next / break value -> nil,
# logic symbols and non-message interpolated strings (the exemption rule: see MESSAGE_PROSE below).
# Each mutant is evaluated in a forked child that re-defines the library from the mutated source and then runs the
# oracle (oracle.rb): unit tests + core/adv corpus + snapshot. Exit 0 in the child == the oracle PASSED == SURVIVED.
require 'parser/current'
require 'json'
require 'optparse'

opts = { jobs: 4, timeout: 120 }
OptionParser.new do |o|
  o.on('--list') { opts[:list] = true }
  o.on('--count-exempt') { opts[:count_exempt] = true }
  o.on('--jobs N', Integer) { |n| opts[:jobs] = n }
  o.on('--timeout S', Integer) { |n| opts[:timeout] = n }
  o.on('--only LIST') { |l| opts[:only] = l.split(',').map(&:to_i) }
  o.on('--lines A-B') { |l| opts[:lines] = Range.new(*l.split('-').map(&:to_i)) }
  # --survivors PREV.json: re-run only the mutants (matched by op + original + replacement text, NOT by id or line, which
  # shift when the source changes) that SURVIVED in a previous results file, plus every mutant that file never saw.
  o.on('--debug') { opts[:debug] = true }
  o.on('--survivors FILE') { |f| opts[:survivors] = f }
  # Carry-forward (the CI's targeted mode, as PIT's history in pca-java): --carry A.json,B.json,... = the results files of an
  # earlier run of THIS file (every shard's, results carried there included), --carry-src OLD.rb = the source that run
  # mutated. Re-run only: mutants that run did not see, its non-kills (SURVIVED: new kill tests may kill them), and every
  # mutant of a def containing a line changed since (git diff OLD FILE); a change outside every def (constants, requires,
  # class bodies) re-runs everything. Every other mutant keeps its earlier KILLED* status, so the output still covers the
  # whole selection (--only). A mutant is matched by op + orig + repl + def + line text + occurrence + column, never by id.
  # Changes in OTHER files are not followed (as in PIT); a full run (no --carry) re-checks everything.
  o.on('--carry LIST') { |l| opts[:carry] = l.split(',').reject(&:empty?) }
  o.on('--carry-src FILE') { |f| opts[:carry_src] = f }
end.parse!
FILE = File.expand_path(ARGV.fetch(0))
# MUT_FILE: the basename of the file under mutation, for kill tests that only bear on some files (an expensive one can
# skip itself for the others: it still runs in full under run_kill.rb, where MUT_FILE is unset)
ENV['MUT_FILE'] = File.basename(FILE)
SRC = File.read(FILE)

Mutant = Struct.new(:id, :line, :op, :orig, :repl, :text, :fn, :col, :frange, :carried)
DEF_RANGES = [] # the line range of every def / defs (carry-forward: which def a changed line belongs to)

def parse_src(src)
  buf = Parser::Source::Buffer.new(FILE, source: src)
  Parser::CurrentRuby.new.parse(buf)
end

SWAP = {
  :== => :!=, :!= => :==, :< => :<=, :<= => :<, :> => :>=, :>= => :>, :+ => :-, :- => :+, :* => :/, :/ => :*,
  :% => :*, :& => :|, :| => :&, :^ => :&, :<< => :>>, :>> => :<<, :** => :*, :<=> => :==, :=== => :!=, :=~ => :!~, :!~ => :=~
}.freeze
PRED_SKIP = %i[frozen? respond_to?].freeze

# What is exempt from mutation, as a rule (--count-exempt prints how each side falls on a file). Floats are exempt. A symbol or
# an interpolated string gets a mutant when it can decide something; the rest is names and human-readable text.
#
# A symbol is logic when it is compared, a `when` value, a lookup key or a stored tag: an operand of LOGIC_COMPARE, an argument of
# LOOKUP_CALLS, a `when` value, an array element or an assigned value. Exempt: hash literal keys (the lookup side is mutated), and
# metaprogramming names (attr_*, Struct.new, &:to_s, respond_to?, send, ...), which have no other reading.
#
# An interpolated string is exempt only when it is a message: it reads as prose (MESSAGE_PROSE) and sits where only a person reads
# it, that is not in STRING_SINKS, not assigned to a variable (a label may be used later), and if a hash value then under a
# MESSAGE_KEYS key. Anything else (a key, a canonical form, a signed or hashed input, SQL, a header) gets a mutant. A string
# nested in another one is decided by the outer one. A reason can also carry meaning to a caller, so prose stops being exempt when
# it carries a literal that any file of lib/ looks for (looked_for): a start_with? / end_with? prefix or suffix, an include?, index,
# sub, gsub or split literal of 3+ characters, a compared literal the string can equal, a regexp that searches for a word, or a
# code of REFUSAL_TABLE (explain_refusal reads the leading word and "code:"). Shorter literals and bare character classes ("e",
# ":", /\s+/) match nearly every sentence and say nothing about it.
LOGIC_COMPARE = %i[== != === eql? equal?].freeze
LOOKUP_CALLS = %i[[] []= fetch dig key? has_key? include? member? delete values_at store].freeze
STRING_SINKS = (LOGIC_COMPARE + LOOKUP_CALLS + %i[start_with? end_with? starts_with? match? =~ !~ sha256 digest hexdigest sign verify hash
                                                  execute get_first_row b]).freeze
MESSAGE_KEYS = %w[reason error detail note message why].freeze
MESSAGE_PROSE = /[A-Za-z]{2,} /
SYMBOL_NAME_CALLS = %i[new attr_reader attr_accessor attr_writer].freeze

def logic_symbol?(parent, grandparent)
  case parent&.type
  when :send, :csend then LOGIC_COMPARE.include?(parent.children[1]) || LOOKUP_CALLS.include?(parent.children[1])
  when :when, :lvasgn, :ivasgn then true
  when :array then !(grandparent&.type == :send && SYMBOL_NAME_CALLS.include?(grandparent.children[1])) && grandparent&.type != :splat
  else false
  end
end

LOOKED_FOR_SUBSTRING = %i[include? index sub gsub split].freeze
LOOKED_FOR_EQUAL = %i[== != ===].freeze

def looked_for
  @looked_for ||= begin
    found = Hash.new { |h, k| h[k] = [] }
    scan = lambda do |n|
      next unless n.is_a?(Parser::AST::Node)

      if %i[send csend].include?(n.type) && n.children[0]
        recv, meth, *args = *n
        [recv, *args].compact.each do |x|
          if x.type == :str
            v = x.children[0]
            found[:prefix] << v if %i[start_with? starts_with?].include?(meth)
            found[:suffix] << v if meth == :end_with?
            found[:substring] << v if LOOKED_FOR_SUBSTRING.include?(meth) && v.size >= 3
            found[:equal] << v if LOOKED_FOR_EQUAL.include?(meth) && v.size >= 3
          elsif x.type == :regexp && x.children[0..-2].all? { |c| c.type == :str }
            src = x.children[0..-2].map { |c| c.children[0] }.join
            found[:regexp] << Regexp.new(src) if src.gsub(/\\./, '').gsub(/\[[^\]]*\]/, '').match?(/[A-Za-z]{3,}/)
          end
        end
      end
      if n.type == :casgn && n.children[1] == :REFUSAL_TABLE
        rows = []
        pick = ->(c) { c.is_a?(Parser::AST::Node) && (c.type == :array && c.children[0]&.type == :str ? rows << c.children[0].children[0] : c.children.each(&pick)) }
        pick.call(n)
        found[:code].concat(rows)
      end
      n.children.each(&scan)
    end
    root = FILE[%r{\A.*/lib/}] || "#{File.dirname(FILE)}/"
    Dir.glob("#{root}**/*.rb").sort.each { |f| scan.call(parse_src(File.read(f))) }
    found
  end
end

def carries_looked_for?(node)
  parts = node.children.map { |c| c.type == :str ? c.children[0] : nil }
  text = parts.map { |x| x || "\0" }.join
  head = parts.first.to_s
  tail = parts.last.to_s
  whole = Regexp.new("\\A#{parts.map { |x| x ? Regexp.escape(x) : '.*' }.join}\\z", Regexp::MULTILINE)
  word = head[/\A[a-z_]+/]
  f = looked_for
  f[:prefix].any? { |l| head.start_with?(l) } || f[:suffix].any? { |l| tail.end_with?(l) } ||
    f[:substring].any? { |l| text.include?(l) } || f[:equal].any? { |l| whole.match?(l) } ||
    f[:regexp].any? { |r| r.match?(text.tr("\0", 'x')) } || f[:code].any? { |c| c == word || text.include?("#{c}:") }
end

def message_string?(node, ancestors)
  return true if ancestors.any? { |a| a.type == :dstr }

  text = node.children.select { |c| c.type == :str }.map { |c| c.children[0] }.join
  return false unless text.match?(MESSAGE_PROSE)

  if carries_looked_for?(node)
    COUNTS[:dstr_looked_for] += 1
    return false
  end

  parent = ancestors.last
  case parent&.type
  when :send, :csend then !STRING_SINKS.include?(parent.children[1])
  when :pair
    key = parent.children[0]
    %i[str sym].include?(key.type) && MESSAGE_KEYS.include?(key.children[0].to_s)
  when :lvasgn, :ivasgn, :casgn, :op_asgn then false
  else true
  end
end

COUNTS = Hash.new(0)

def mutants_for(src)
  ast = parse_src(src)
  out = []
  ancestors = []
  fns = [] # enclosing def names (the site's `fn`)
  franges = [] # their line ranges
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
    out << Mutant.new(out.size, r.line, op, orig, repl, text, fns.last, r.column, franges.last)
  end
  # A body of one statement has no :begin, so stmt-delete never sees it: a bare `check(x)` in a block, when, else, rescue or
  # ensure had no mutant at all. Literals have their own operators.
  delete_single = lambda do |body|
    add.call(body, 'nil', 'single-body-delete') if body.is_a?(Parser::AST::Node) && !%i[begin kwbegin nil true false int str].include?(body.type)
  end
  walk = lambda do |n, parent|
    next unless n.is_a?(Parser::AST::Node)

    case n.type
    when :send, :csend
      recv, meth, *args = *n
      sel = n.loc.selector
      add.call(n.loc.dot, '.', 'csend->send') if n.type == :csend
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
    when :sym
      if logic_symbol?(parent, ancestors[-2])
        COUNTS[:symbol_logic] += 1
        add.call(n, n.loc.expression.source.start_with?(':') ? ':__mutated__' : '__mutated__', 'sym-logic')
      else
        COUNTS[:symbol_exempt] += 1
      end
    when :dstr
      if message_string?(n, ancestors)
        COUNTS[:dstr_exempt] += 1
      else
        COUNTS[:dstr_logic] += 1
        add.call(n, '""', 'dstr-empty')
      end
    when :or_asgn, :and_asgn
      add.call(n.loc.operator, '=', "#{n.type}->asgn")
    when :regexp
      add.call(n, '/(?!)/', 'regexp-never')
    when :next, :break
      add.call(n, "#{n.type} nil", "#{n.type}-nil") if n.children.any?
    when :block, :numblock
      delete_single.call(n.children[2])
    when :when
      conds = n.children[0...-1]
      add.call(conds.first.loc.expression.join(conds.last.loc.expression), '->(_) { false }', 'when-never')
      delete_single.call(n.children.last)
    when :case
      delete_single.call(n.children.last)
    when :resbody
      delete_single.call(n.children[2])
    when :rescue
      delete_single.call(n.children[0]) unless %i[def defs].include?(parent&.type) # there body-delete removes it
    when :ensure
      delete_single.call(n.children[1])
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
      delete_single.call(n.children[1])
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
    if %i[def defs].include?(n.type)
      fns.push(n.type == :def ? n.children[0].to_s : n.children[1].to_s)
      franges.push(n.loc.expression.line..n.loc.expression.last_line)
      DEF_RANGES << franges.last
    end
    ancestors.push(n)
    n.children.each { |c| walk.call(c, n) }
    ancestors.pop
    if %i[def defs].include?(n.type)
      fns.pop
      franges.pop
    end
  end
  walk.call(ast, nil)
  out
end

mutants = mutants_for(SRC)
if opts[:count_exempt]
  puts JSON.generate(COUNTS)
  exit
end
# de-duplicate identical (line, text)
seen = {}
mutants = mutants.select { |m| seen[[m.line, m.text]] ? false : (seen[[m.line, m.text]] = true) }
# --lines without --only: scope BEFORE the (slow: one full re-parse per mutant) syntax validation. Ids are then local to the
# scoped run; mutants are matched across runs by op + orig + repl (and the site key), never by id.
mutants = mutants.select { |m| opts[:lines].cover?(m.line) } if opts[:lines] && !opts[:only]
# Ids are positions in this de-duplicated list (stable for one source, validation-independent), so a slice (--only) validates
# ONLY its own mutants below: validating all ~10k mutants of a big file with the parser gem (one full re-parse each) was a ~50
# minute fixed cost in every shard.
mutants.each_with_index { |m, i| m.id = i }
def mutant_label(m)
  sq = ->(s) { s.gsub(/\s+/, ' ')[0, 100] }
  "#{m.op}: #{sq.call(m.orig)} => #{sq.call(m.repl)}"
end
mutants = mutants.select { |m| opts[:only].include?(m.id) } if opts[:only]
mutants = mutants.select { |m| opts[:lines].cover?(m.line) } if opts[:lines]
if opts[:survivors]
  prev = JSON.parse(File.read(opts[:survivors]))
  mkey = ->(op, orig, repl) { [op, orig, repl] }
  seen_prev = prev.to_h { |x| [mkey.call(x['op'], x['orig'], x['repl']), true] }
  surv = prev.select { |x| x['status'] == 'SURVIVED' }.to_h { |x| [mkey.call(x['op'], x['orig'], x['repl']), true] }
  mutants = mutants.select { |m| k = mkey.call(m.op, m.orig, m.repl); surv[k] || !seen_prev[k] }
end

# validate syntax (drop mutants that no longer parse): MRI's own compiler, the one the mutant is evaluated by (milliseconds a
# mutant; the parser gem's full re-parse was ~0.3 s)
mutants = mutants.select do |m|
  RubyVM::InstructionSequence.compile(m.text, FILE)
  true
rescue SyntaxError
  false
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

def record(m, status)
  { id: m.id, line: m.line, col: m.col, op: m.op, orig: m.orig, repl: m.repl, status: status,
    fn: m.fn, occurrence: OCC[m.line], line_text: SRC_LINES[m.line - 1].to_s.strip, mutant: mutant_label(m) }
end

carried = []
if opts[:carry]
  ckey = ->(op, orig, repl, fn, lt, occ, col) { JSON.generate([op, orig, repl, fn.to_s, lt, occ, col]) }
  prev = {}
  opts[:carry].each do |f|
    JSON.parse(File.read(f)).each { |x| prev[ckey.call(x['op'], x['orig'], x['repl'], x['fn'], x['line_text'], x['occurrence'], x['col'])] = x['status'] }
  end
  # the lines of FILE changed since the carried run: every new-side line of a hunk; a pure deletion marks both neighbours
  old = opts[:carry_src]
  abort "--carry needs --carry-src (the source the carried run mutated): #{old.inspect}" unless old && File.file?(old)
  diff = IO.popen(['git', 'diff', '--no-index', '--no-color', '-U0', '--', old, FILE], &:read)
  changed = diff.scan(/^@@ -\S+ \+(\d+)(?:,(\d+))? @@/).flat_map do |a, b|
    s0 = a.to_i
    c = (b || '1').to_i
    c.zero? ? [s0, s0 + 1] : (s0...(s0 + c)).to_a
  end
  # an added / edited blank or comment-only line is no code change (a pure deletion's neighbours always count: what was
  # deleted is unknown here)
  dels = diff.scan(/^@@ -\S+ \+(\d+),0 @@/).flat_map { |(a)| [a.to_i, a.to_i + 1] }
  changed = changed.select { |l| dels.include?(l) || !(t = SRC_LINES[l - 1].to_s.strip).empty? && !t.start_with?('#') }
  everything = changed.any? { |l| DEF_RANGES.none? { |r| r.cover?(l) } }
  touched = ->(m) { changed.any? { |l| m.frange ? m.frange.cover?(l) : l == m.line } }
  rerun, keep = mutants.partition do |m|
    st = prev[ckey.call(m.op, m.orig, m.repl, m.fn, SRC_LINES[m.line - 1].to_s.strip, OCC[m.line], m.col)]
    m.carried = st
    everything || st.nil? || !st.start_with?('KILLED') || touched.call(m)
  end
  carried = keep.map { |m| record(m, m.carried).merge(carried: true) }
  $stderr.puts "carry: #{changed.size} changed line(s)#{everything ? ' (outside any def: everything re-runs)' : ''}; " \
               "#{carried.size} result(s) carried, #{rerun.size} to run (#{rerun.count { |m| m.carried.nil? }} unseen, " \
               "#{rerun.count { |m| m.carried && !m.carried.start_with?('KILLED') }} earlier non-kills)"
  mutants = rerun
  if mutants.empty?
    puts JSON.pretty_generate(carried.sort_by { |x| x[:id] })
    exit
  end
end

require_relative 'oracle'
Oracle.prepare(FILE)
$stderr.puts "mutants: #{mutants.size}"
# Baseline: the UNMUTATED source applied the same way must pass the oracle, else every mutant would be "killed".
# Every SystemStackError raised anywhere during a run (a kill test or the library may rescue it into an ordinary `false`):
# counted by a :raise TracePoint. If the unmutated oracle raises none, a mutant decided after one is a RUN ERROR.
def stack_raises
  n = 0
  tp = TracePoint.new(:raise) { |t| n += 1 if t.raised_exception.is_a?(SystemStackError) }
  tp.enable
  r = yield
  [r, n]
ensure
  tp&.disable
end
t_base = Time.now
br, bw = IO.pipe
base = fork do
  br.close
  $stdout.reopen('/dev/null', 'w')
  $VERBOSE = nil
  Oracle.apply(SRC, FILE)
  ok, n = stack_raises { Oracle.run }
  bw.write(n.to_s)
  bw.close
  exit!(ok ? 0 : 1)
rescue Exception # rubocop:disable Lint/RescueException
  exit!(2)
end
bw.close
BASE_STACK_RAISES = br.read.to_i
br.close
Process.wait(base)
unless $?.success?
  st = $?.exitstatus
  # say WHICH oracle stage fails on the unmutated source (a bare "FAILED" cost a whole CI round)
  dbg = fork do
    $VERBOSE = nil
    Oracle.apply(SRC, FILE)
    $stderr.puts "baseline oracle stages: #{JSON.generate(Oracle.stages)}"
    $stderr.puts "baseline fresh-load probe: #{Oracle.fresh_load_ok?}"
    exit!(0)
  rescue Exception => e # rubocop:disable Lint/RescueException
    $stderr.puts "baseline oracle raised #{e.class}: #{e.message}\n  #{e.backtrace&.first(8)&.join("\n  ")}"
    exit!(1)
  end
  Process.wait(dbg)
  abort "baseline oracle FAILED on the unmutated source (status #{st})"
end
unless Oracle.fresh_baseline_ok?
  Oracle.fresh_baseline_ok?(err: $stderr)
  abort 'the fresh-load probe FAILS on the unmutated source (every mutant it judges would count as killed)'
end
# The per-mutant limit is relative to the unmutated oracle's own run time (the go-mutate / swift-mutate rule): a fixed --timeout
# near a slow oracle's duration counts SURVIVING mutants as timeout "kills" (a timeout is never an assertion). The baseline ran
# alone, the mutants run --jobs at a time: 5x + 120 s (margin for GC pauses and a loaded runner, so a behaviour-preserving
# mutant never times out), and never below --timeout. A timeout still needs a ledger entry: the merge treats it as a run error.
base_s = Time.now - t_base
LIMIT = [opts[:timeout], (5 * base_s + 120).ceil].max
$stderr.puts "baseline oracle passed in #{base_s.round(1)}s; per-mutant limit #{LIMIT}s; SystemStackErrors raised: #{BASE_STACK_RAISES}"
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

HARD_GRACE = 20 # seconds past --timeout before the parent kills a child itself
results = {}
running = {}
hints = [] # the kill tests that killed the latest mutants (see Oracle.run)
queue = mutants.dup
t0 = Time.now
until queue.empty? && running.empty?
  while running.size < opts[:jobs] && (m = queue.shift)
    Oracle.hint = hints.dup
    r, w = IO.pipe
    pid = fork do
      r.close
      # own process group: the parent's watchdog kills the whole group (a probe subprocess a mutant started included)
      Process.setpgid(0, 0)
      $stdout.reopen('/dev/null', 'w')
      $stderr.reopen('/dev/null', 'w')
      Thread.new { sleep LIMIT; Process.kill('KILL', Process.pid) }
      # A kill is a test (or corpus stage) answering wrong. A mutant decided only by a stack overflow or the memory cap (ulimit -v:
      # NoMemoryError), or whose process died by a signal (parent side, below), is a RUN ERROR: the merge requires a per-mutant
      # reason for each (mutation-run-errors.json). Any other exception is the mutated library failing to load or to answer.
      status = begin
        $VERBOSE = nil
        Oracle.apply(m.text, FILE)
        ok, sse = stack_raises { Oracle.run }
        if ok then 'SURVIVED'
        elsif Oracle.run_error then "RUN_ERROR(#{Oracle.run_error})"
        elsif BASE_STACK_RAISES.zero? && sse.positive? then 'RUN_ERROR(SystemStackError)'
        else 'KILLED'
        end
      rescue NoMemoryError, SystemStackError => e
        "RUN_ERROR(#{e.class})"
      rescue Exception # rubocop:disable Lint/RescueException
        'KILLED'
      end
      status = "#{status}\t#{Oracle.killer}" if status == 'KILLED' && Oracle.killer
      w.write(status)
      w.close
      exit!(0)
    end
    w.close
    running[pid] = [m, r, Time.now]
  end
  # Reap with a PARENT-SIDE deadline. The child's own timer thread (above) needs the interpreter lock: a mutant stuck in a long
  # C call that never yields it (catastrophic regexp backtracking, a huge bignum operation) is never killed by it, and a blocking
  # wait here then hangs the whole shard until the CI job limit (shard 25/62 of run 39706440492, 300 minutes, no result). The
  # watchdog SIGKILLs the child's process group HARD_GRACE seconds after its own deadline, whatever it is doing.
  pid = st = nil
  loop do
    pid, st = Process.wait2(-1, Process::WNOHANG)
    break if pid

    now = Time.now
    running.each do |cpid, (_m, _r, t)|
      next unless now - t > LIMIT + HARD_GRACE

      begin
        Process.kill('KILL', -cpid)
      rescue SystemCallError
        begin
          Process.kill('KILL', cpid)
        rescue SystemCallError
          nil
        end
      end
    end
    sleep 0.1
  end
  m, r, started = running.delete(pid)
  out = r.read
  r.close
  out, killer = out.split("\t", 2)
  if killer && !killer.empty?
    hints.delete(killer)
    hints.unshift(killer)
    hints.pop while hints.length > 8
  end
  # no verdict written: past the limit = timeout (counted, reported per shard); else the process died: a RUN ERROR
  status = if out.nil? || out.empty?
             if Time.now - started >= LIMIT then 'KILLED(timeout)'
             elsif st.signaled? then "RUN_ERROR(SIG#{Signal.signame(st.termsig)})"
             else "RUN_ERROR(exit #{st.exitstatus})"
             end
           else out
           end
  results[m.id] = record(m, status)
  # MUT_STREAM=<file>: append each result as one JSON line the moment it completes (survives a wall-clock kill)
  File.open(ENV['MUT_STREAM'], 'a') { |f| f.puts(JSON.generate(results[m.id])) } if ENV['MUT_STREAM']
  $stderr.puts "#{results.size}/#{mutants.size} survivors=#{results.values.count { |x| x[:status] == 'SURVIVED' }} elapsed=#{(Time.now - t0).to_i}s" if (results.size % 50).zero?
end
puts JSON.pretty_generate((results.values + carried).sort_by { |x| x[:id] })
