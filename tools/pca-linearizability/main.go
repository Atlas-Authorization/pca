// pca-linearizability: record concurrent histories against REAL replay/counter stores and check them for
// linearizability (porcupine) against the sequential specification of ReplayStore.consumeOnce / CounterStore.advance.
//
//	pcalinz run   -store pg-adjudicate -dir H -proc a -conns 100 -secs 60 [-slice 8ms -spread 3 -vals 40]
//	pcalinz check -dir H [-out violations/]
//
// A history file holds one line per event, written with a single write(2) BEFORE the operation is sent (invocation)
// and after it completes (response), so a client killed with SIGKILL leaves its in-flight operations PENDING
// (they may or may not have taken effect), exactly like a crash in production.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/anishathalye/porcupine"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pcalinz run|check ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "check":
		os.Exit(cmdCheck(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		os.Exit(2)
	}
}

// --------------------------------------------------------------------------- run

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	store := fs.String("store", "pg-adjudicate", "store under test")
	dir := fs.String("dir", "hist", "history directory")
	proc := fs.String("proc", "p0", "process id (unique per client process incarnation)")
	conns := fs.Int("conns", 100, "concurrent connections / workers")
	secs := fs.Float64("secs", 30, "run duration")
	slice := fs.Duration("slice", 8*time.Millisecond, "contention window: every worker targets the same few keys within a slice")
	spread := fs.Int("spread", 3, "keys per window")
	vals := fs.Int("vals", 40, "counter value range")
	pgdsn := fs.String("pg", "postgres://pca@127.0.0.1:5455/linz?sslmode=disable", "")
	pgr := fs.String("pgreplica", "postgres://pca@127.0.0.1:5456/linz?sslmode=disable", "")
	redisAddr := fs.String("redis", "127.0.0.1:6390", "")
	runid := fs.String("run", "", "key namespace (default: time-based)")
	revisit := fs.Int("revisit", 0, "if > 0, a key stays eligible for revisit*slice after it enters the window, so keys are touched again after a server restart")
	epoch := fs.Int64("epoch", 0, "shared window origin (unix ns) so processes target the same keys")
	fs.Parse(args)
	if *runid == "" {
		*runid = strconv.FormatInt(time.Now().UnixNano()/1e6, 36)
	}
	st, err := NewStore(*store, Cfg{PgDSN: *pgdsn, PgReplicaDSN: *pgr, RedisAddr: *redisAddr, Conns: *conns})
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 2
	}
	defer st.Close()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	f, err := os.OpenFile(filepath.Join(*dir, "h-"+*proc+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer f.Close()
	origin := time.Now().UnixNano()
	if *epoch != 0 {
		origin = *epoch
	}
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; cancel() }()
	deadline := time.Now().Add(time.Duration(*secs * float64(time.Second)))
	var nops, ntrue, nfalse, nerr atomic.Int64
	var wg sync.WaitGroup
	kind := st.Kind()
	for w := 0; w < *conns; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(w)*7919))
			buf := make([]byte, 0, 160)
			var seq int64
			for time.Now().Before(deadline) && ctx.Err() == nil {
				win := (time.Now().UnixNano() - origin) / int64(*slice)
				key := fmt.Sprintf("%s-%d-%d", *runid, win, rng.Intn(*spread))
				if *revisit > 0 {
					key = fmt.Sprintf("%s-r%d", *runid, win+int64(rng.Intn(*revisit)))
				}
				if st.Prepare(ctx, key) != nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				seq++
				var v int64
				opc := byte('c')
				if kind == KindCounter {
					opc = 'a'
					v = int64(rng.Intn(*vals))
				}
				buf = fmt.Appendf(buf[:0], "i %s %d %d %d %c %s %d\n", *proc, w, seq, time.Now().UnixNano(), opc, key, v)
				f.Write(buf) // invocation is durable (in the page cache) before the op leaves the process
				var ok bool
				var err error
				octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
				if kind == KindCounter {
					ok, err = st.Advance(octx, key, v)
				} else {
					ok, err = st.Consume(octx, key)
				}
				ocancel()
				r := 0
				switch {
				case err != nil:
					r = 2
					nerr.Add(1)
					time.Sleep(time.Duration(5+rng.Intn(20)) * time.Millisecond)
				case ok:
					r = 1
					ntrue.Add(1)
				default:
					nfalse.Add(1)
				}
				buf = fmt.Appendf(buf[:0], "r %s %d %d %d %d\n", *proc, w, seq, time.Now().UnixNano(), r)
				f.Write(buf)
				nops.Add(1)
			}
		}(w)
	}
	wg.Wait()
	fmt.Printf("run proc=%s store=%s ops=%d true=%d false=%d err=%d\n", *proc, *store, nops.Load(), ntrue.Load(), nfalse.Load(), nerr.Load())
	return 0
}

// --------------------------------------------------------------------------- check

type op struct {
	worker    int
	kind      byte
	key       string
	v         int64
	call, ret int64
	res       int // 0 false, 1 true, 2 unknown
	pending   bool
}

type in struct {
	kind byte
	v    int64
}
type out struct{ res int }

const inf = int64(1) << 62

func consumeModel() porcupine.Model {
	m := porcupine.NondeterministicModel{
		Init: func() []interface{} { return []interface{}{false} },
		Step: func(state, input, output interface{}) []interface{} {
			consumed := state.(bool)
			switch output.(out).res {
			case 1:
				if !consumed {
					return []interface{}{true}
				}
				return nil
			case 0:
				if consumed {
					return []interface{}{true}
				}
				return nil
			default: // unknown: the consume may or may not have happened
				if consumed {
					return []interface{}{true}
				}
				return []interface{}{false, true}
			}
		},
		Equal:             func(a, b interface{}) bool { return a.(bool) == b.(bool) },
		DescribeOperation: func(i, o interface{}) string { return fmt.Sprintf("consume -> %s", resName(o.(out).res)) },
		DescribeState:     func(s interface{}) string { return fmt.Sprintf("consumed=%v", s.(bool)) },
	}
	return m.ToModel()
}

func counterModel() porcupine.Model {
	m := porcupine.NondeterministicModel{
		Init: func() []interface{} { return []interface{}{int64(-1)} },
		Step: func(state, input, output interface{}) []interface{} {
			last := state.(int64)
			v := input.(in).v
			switch output.(out).res {
			case 1:
				if v > last {
					return []interface{}{v}
				}
				return nil
			case 0:
				if v <= last {
					return []interface{}{last}
				}
				return nil
			default:
				if v > last {
					return []interface{}{last, v}
				}
				return []interface{}{last}
			}
		},
		Equal:             func(a, b interface{}) bool { return a.(int64) == b.(int64) },
		DescribeOperation: func(i, o interface{}) string { return fmt.Sprintf("advance(%d) -> %s", i.(in).v, resName(o.(out).res)) },
		DescribeState:     func(s interface{}) string { return fmt.Sprintf("last=%d", s.(int64)) },
	}
	return m.ToModel()
}

func resName(r int) string {
	switch r {
	case 1:
		return "TRUE"
	case 0:
		return "false"
	}
	return "unknown"
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", "hist", "")
	outDir := fs.String("out", "violations", "")
	par := fs.Int("par", 8, "parallel checkers")
	tmo := fs.Duration("timeout", 120*time.Second, "per-key check timeout")
	onlyKeys := fs.String("keys", "", "comma-separated keys to (re)check; others are skipped")
	maxViz := fs.Int("viz", 3, "write at most this many visualisations")
	doPrune := fs.Bool("prune", true, "drop operations that are trivially linearizable (see prune); verdict-preserving")
	fs.Parse(args)
	files, _ := filepath.Glob(filepath.Join(*dir, "h-*.log"))
	sort.Strings(files)
	byKey := map[string][]*op{}
	var total, ntrue, nfalse, nunk, npend, torn int64
	for _, fn := range files {
		fh, err := os.Open(fn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		open := map[string]*op{}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			p := strings.Fields(sc.Text())
			if len(p) < 5 {
				torn++
				continue
			}
			id := p[1] + "/" + p[2] + "/" + p[3]
			switch p[0] {
			case "i":
				if len(p) != 8 {
					torn++
					continue
				}
				t, _ := strconv.ParseInt(p[4], 10, 64)
				v, _ := strconv.ParseInt(p[7], 10, 64)
				w, _ := strconv.Atoi(p[2])
				o := &op{worker: w, kind: p[5][0], key: p[6], v: v, call: t, ret: inf, res: 2, pending: true}
				open[id] = o
				byKey[o.key] = append(byKey[o.key], o)
			case "r":
				o := open[id]
				if o == nil || len(p) != 6 {
					torn++
					continue
				}
				t, _ := strconv.ParseInt(p[4], 10, 64)
				r, _ := strconv.Atoi(p[5])
				o.pending = false
				o.res = r
				if r != 2 {
					o.ret = t
				} // an errored op may still take effect later: keep it open-ended
				delete(open, id)
			}
		}
		fh.Close()
	}
	var keys []string
	for k, ops := range byKey {
		keys = append(keys, k)
		for _, o := range ops {
			total++
			switch {
			case o.pending:
				npend++
				nunk++
			case o.res == 1:
				ntrue++
			case o.res == 0:
				nfalse++
			default:
				nunk++
			}
		}
	}
	if *onlyKeys != "" {
		want := map[string]bool{}
		for _, k := range strings.Split(*onlyKeys, ",") {
			want[strings.TrimSpace(k)] = true
		}
		var kept2 []string
		for _, k := range keys {
			if want[k] {
				kept2 = append(kept2, k)
			}
		}
		keys = kept2
	}
	sort.Strings(keys)
	os.MkdirAll(*outDir, 0o755)
	var bad, timeouts, checked, pruned, kept, fastResolved atomic.Int64
	var viz atomic.Int64
	var badKeys sync.Map
	sem := make(chan struct{}, *par)
	var wg sync.WaitGroup
	for _, k := range keys {
		ops := byKey[k]
		wg.Add(1)
		sem <- struct{}{}
		go func(k string, ops []*op) {
			defer wg.Done()
			defer func() { <-sem }()
			full := ops
			if *doPrune {
				ops = prune(ops)
			}
			pruned.Add(int64(len(full) - len(ops)))
			kept.Add(int64(len(ops)))
			if obviousViolation(ops) {
				// two definite TRUE answers of a consume-once key (or of the same counter value) can never linearize;
				// deciding that directly avoids a pointless (and memory-hungry) exponential search on heavily broken histories.
				bad.Add(1)
				badKeys.Store(k, len(full))
				if viz.Add(1) <= int64(*maxViz) {
					dump(filepath.Join(*outDir, "violation-"+k+".txt"), full)
				}
				return
			}
			var model porcupine.Model
			if ops[0].kind == 'c' {
				model = consumeModel()
			} else {
				model = counterModel()
			}
			h := make([]porcupine.Operation, 0, len(ops))
			for _, o := range ops {
				ret := o.ret
				if ret <= o.call {
					ret = o.call + 1
				}
				h = append(h, porcupine.Operation{ClientId: o.worker, Input: in{kind: o.kind, v: o.v}, Call: o.call, Output: out{res: o.res}, Return: ret})
			}
			res, info := porcupine.CheckOperationsVerbose(model, h, *tmo)
			checked.Add(1)
			switch res {
			case porcupine.Illegal:
				bad.Add(1)
				badKeys.Store(k, len(ops))
				if viz.Add(1) <= int64(*maxViz) {
					if f, err := os.Create(filepath.Join(*outDir, "violation-"+k+".html")); err == nil {
						porcupine.Visualize(model, info, f)
						f.Close()
					}
					dump(filepath.Join(*outDir, "violation-"+k+".txt"), full)
				}
			case porcupine.Unknown:
				// porcupine is exponential in the number of mutually concurrent operations; for histories with no open-ended
				// (unknown / pending) operation the monotone-register spec has an exact polynomial decision procedure.
				if okFast, applicable := fastCheck(ops); applicable {
					fastResolved.Add(1)
					if !okFast {
						bad.Add(1)
						badKeys.Store(k, len(full))
						dump(filepath.Join(*outDir, "violation-"+k+".txt"), full)
					}
				} else {
					timeouts.Add(1)
					fmt.Fprintf(os.Stderr, "check timeout: key %s (%d ops)\n", k, len(ops))
				}
			}
		}(k, ops)
	}
	wg.Wait()
	var bks []string
	badKeys.Range(func(k, v interface{}) bool { bks = append(bks, fmt.Sprintf("%s(%d ops)", k, v)); return true })
	sort.Strings(bks)
	if len(bks) > 10 {
		bks = bks[:10]
	}
	fmt.Printf("CHECK files=%d ops=%d (true=%d false=%d unknown=%d of-which-pending=%d) keys=%d checked=%d NON-LINEARIZABLE=%d timeouts=%d torn-lines=%d pruned-trivial=%d searched=%d exact-fallback-resolved=%d\n",
		len(files), total, ntrue, nfalse, nunk, npend, len(keys), checked.Load(), bad.Load(), timeouts.Load(), torn, pruned.Load(), kept.Load(), fastResolved.Load())
	if len(bks) > 0 {
		fmt.Println("first violating keys:", strings.Join(bks, " "))
	}
	if bad.Load() > 0 {
		return 1
	}
	if timeouts.Load() > 0 {
		return 3
	}
	return 0
}

func dump(fn string, ops []*op) {
	sort.Slice(ops, func(i, j int) bool { return ops[i].call < ops[j].call })
	var b strings.Builder
	base := ops[0].call
	for _, o := range ops {
		r := "pending"
		if o.ret != inf {
			r = fmt.Sprintf("%.3fms", float64(o.ret-base)/1e6)
		}
		fmt.Fprintf(&b, "w%-4d %c(%d) call=%.3fms ret=%s -> %s\n", o.worker, o.kind, o.v, float64(o.call-base)/1e6, r, resName(o.res))
	}
	os.WriteFile(fn, []byte(b.String()), 0o644)
}

// prune drops every definite "false" answer that is trivially explained: some "true" (a definitely applied write of a value
// w >= v; for consume-once any "true") had already RETURNED before the false operation was invoked. State is monotone, so from
// that write's linearization point on the state is >= v and the false operation can be placed at its own invocation without
// affecting any other operation. Hence H is linearizable iff H minus these operations is: the verdict is unchanged, the search
// space is not (porcupine is exponential in the number of mutually concurrent operations).
func prune(ops []*op) []*op {
	type tv struct{ ret, v int64 }
	var ts []tv
	for _, o := range ops {
		if o.res == 1 && !o.pending && o.ret != inf {
			ts = append(ts, tv{o.ret, o.v})
		}
	}
	if len(ts) == 0 {
		return ops
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].ret < ts[j].ret })
	pm := make([]int64, len(ts))
	for i, t := range ts {
		pm[i] = t.v
		if i > 0 && pm[i-1] > pm[i] {
			pm[i] = pm[i-1]
		}
	}
	out := ops[:0:0]
	for _, o := range ops {
		if o.res == 0 && !o.pending {
			// number of trues with ret < o.call
			n := sort.Search(len(ts), func(i int) bool { return ts[i].ret >= o.call })
			if n > 0 && pm[n-1] >= o.v {
				continue
			}
		}
		out = append(out, o)
	}
	return out
}

// fastCheck decides linearizability EXACTLY for histories whose every operation has a definite answer (no unknown / pending
// operation) against the consume-once / monotone-counter specification, in O(n log n):
//   - every TRUE advances the register, so the linearization order of the TRUEs is forced: ascending value (equal values, or
//     two consume TRUEs, are impossible);
//   - the earliest-schedule t_i = max(call_i, t_{i-1}) is feasible iff every t_i <= ret_i (earliest dominates; linearization
//     points are an order, not distinct instants, so equal t_i are fine);
//   - a definite FALSE(v) needs a linearization point inside its interval at which the register is >= v, i.e. at or after the
//     TRUE with the smallest value >= v; that TRUE's earliest point must not be later than the FALSE's return.
//
// applicable=false when the key has an unknown / pending operation (porcupine's nondeterministic model handles those).
func fastCheck(ops []*op) (ok bool, applicable bool) {
	var ts []*op
	for _, o := range ops {
		if o.res == 2 || o.pending || o.ret == inf {
			return false, false
		}
		if o.res == 1 {
			ts = append(ts, o)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].v < ts[j].v })
	t := make([]int64, len(ts))
	prev := int64(-1) << 62
	for i, o := range ts {
		if i > 0 && ts[i-1].v == o.v {
			return false, true
		}
		ti := o.call
		if prev > ti {
			ti = prev
		}
		if ti > o.ret {
			return false, true
		}
		t[i], prev = ti, ti
	}
	for _, o := range ops {
		if o.res != 0 {
			continue
		}
		j := sort.Search(len(ts), func(i int) bool { return ts[i].v >= o.v })
		if j == len(ts) || t[j] > o.ret {
			return false, true
		}
	}
	return true, true
}

// obviousViolation: a consume-once key with two definite TRUEs, or a counter stream with two definite TRUEs of one value.
func obviousViolation(ops []*op) bool {
	seenV := map[int64]bool{}
	for _, o := range ops {
		if o.res == 1 && !o.pending {
			if seenV[o.v] {
				return true
			}
			seenV[o.v] = true
		}
	}
	return false
}
