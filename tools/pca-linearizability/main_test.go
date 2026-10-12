package main

import (
	"math/rand"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
)

// verdict of the porcupine check for a key's operations, with or without the prune pre-pass.
func verdict(ops []*op) porcupine.CheckResult {
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
	return porcupine.CheckOperationsTimeout(model, h, 20*time.Second)
}

// Random concurrent histories of a (sometimes lossy / sometimes unknown-outcome) monotone register; pruning must never change the verdict.
func TestPrunePreservesVerdict(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 4000; iter++ {
		kind := byte('a')
		if iter%3 == 0 {
			kind = 'c'
		}
		n := 3 + rng.Intn(9)
		var ops []*op
		last := int64(-1)
		consumed := false
		for i := 0; i < n; i++ {
			call := int64(rng.Intn(40))
			ret := call + 1 + int64(rng.Intn(12))
			o := &op{worker: i, kind: kind, call: call, ret: ret}
			if kind == 'a' {
				o.v = int64(rng.Intn(6))
			}
			// linearization point inside [call, ret): evaluate against the sequential spec, then corrupt some answers
			if kind == 'a' {
				if o.v > last {
					o.res, last = 1, o.v
				} else {
					o.res = 0
				}
			} else {
				if !consumed {
					o.res, consumed = 1, true
				} else {
					o.res = 0
				}
			}
			if rng.Intn(6) == 0 {
				o.res = 1 - o.res // may make the history illegal
			}
			if rng.Intn(10) == 0 {
				o.res, o.ret = 2, inf // unknown, open-ended
			}
			ops = append(ops, o)
		}
		a := verdict(ops)
		b := verdict(prune(ops))
		if a != b {
			t.Fatalf("iter %d: verdict changed by prune: %v -> %v", iter, a, b)
		}
	}
}

// fastCheck must agree with porcupine on every history with definite answers (distinct timestamps, as porcupine requires).
func TestFastCheckAgreesWithPorcupine(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	agree, illegal := 0, 0
	for iter := 0; iter < 6000; iter++ {
		kind := byte('a')
		if iter%4 == 0 {
			kind = 'c'
		}
		n := 3 + rng.Intn(8)
		var ops []*op
		last := int64(-1)
		consumed := false
		used := map[int64]bool{}
		next := func() int64 { // distinct timestamps (the exactness argument uses integer, strictly increasing lin points)
			for {
				x := int64(rng.Intn(400)) * 2
				if !used[x] {
					used[x] = true
					return x
				}
			}
		}
		for i := 0; i < n; i++ {
			c, r := next(), next()
			if r < c {
				c, r = r, c
			}
			o := &op{worker: i, kind: kind, call: c, ret: r}
			if kind == 'a' {
				o.v = int64(rng.Intn(6))
				if o.v > last {
					o.res, last = 1, o.v
				}
			} else if !consumed {
				o.res, consumed = 1, true
			}
			if rng.Intn(5) == 0 {
				o.res = 1 - o.res
			}
			ops = append(ops, o)
		}
		want := verdict(ops) == porcupine.Ok
		got, app := fastCheck(ops)
		if !app {
			t.Fatal("unexpectedly not applicable")
		}
		if got != want {
			t.Fatalf("iter %d: fastCheck=%v porcupine=%v on %+v", iter, got, want, dumpOps(ops))
		}
		agree++
		if !want {
			illegal++
		}
	}
	if illegal < 500 || agree-illegal < 500 {
		t.Fatalf("test not discriminating: %d illegal of %d", illegal, agree)
	}
}

func dumpOps(ops []*op) []op {
	var r []op
	for _, o := range ops {
		r = append(r, *o)
	}
	return r
}
