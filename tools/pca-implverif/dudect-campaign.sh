#!/usr/bin/env bash
# dudect-campaign.sh : runs on the exclusive idle box cloud-box-1 (8 cores). Each job is pinned to ONE core; core 0 is left for the OS.
# Component tests: N=10,000,000 samples (rref: 3,000,000, 5 ms per sample), fixed-vs-random and a random-vs-random NULL control each,
# plus the deliberately leaky 'control'. Whole-signature test: as many samples as ~6 h allow on cores 6,7 (fixed-vs-random, null).
O=/work/dudect; mkdir -p $O; cd $O
CC=/work/ivo/ct_comp; SG=/work/ivo/ct_sign45
job() { core=$1; shift; name=$1; shift; ( taskset -c $core "$@" > $O/$name.out 2> $O/$name.err; echo done >> $O/$name.out ) & }
( for c in control prikey salt mulG; do taskset -c 1 $CC $c 10000000 11 > $O/$c.out 2>&1; NULLTEST=1 taskset -c 1 $CC $c 10000000 12 > $O/$c.null.out 2>&1; done; echo ALL1 > $O/core1.done ) &
( taskset -c 2 $CC blindcf 10000000 21 > $O/blindcf.out 2>&1; NULLTEST=1 taskset -c 2 $CC blindcf 10000000 22 > $O/blindcf.null.out 2>&1; echo ALL2 > $O/core2.done ) &
( taskset -c 3 $CC cosetrep 10000000 31 > $O/cosetrep.out 2>&1; NULLTEST=1 taskset -c 3 $CC cosetrep 10000000 32 > $O/cosetrep.null.out 2>&1; echo ALL3 > $O/core3.done ) &
( taskset -c 4 $CC rref 3000000 41 > $O/rref.out 2>&1; echo ALL4 > $O/core4.done ) &
( NULLTEST=1 taskset -c 5 $CC rref 3000000 42 > $O/rref.null.out 2>&1; echo ALL5 > $O/core5.done ) &
( taskset -c 6 $SG dudect ${SIGN_N:-50000} 1 > $O/sign.out 2> $O/sign.err; echo ALL6 > $O/core6.done ) &
( taskset -c 7 $SG dudect ${SIGN_N:-50000} 2 null > $O/sign.null.out 2> $O/sign.null.err; echo ALL7 > $O/core7.done ) &
wait
