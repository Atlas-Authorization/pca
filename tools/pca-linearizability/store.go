package main

// Store implementations under test. Every implementation is an interleaving of the SQL / Redis commands the
// real PCA code issues (production = the reference server admission code + packages/db PcaCountersRepository /
// PcaAttestNoncesRepository; reference = the strategies documented in docs/pca/reference/anti-replay.md) or a
// deliberately BAD variant used as a positive control (the checker MUST flag those).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Kind int

const (
	KindConsume Kind = iota // ReplayStore.consumeOnce: exactly one TRUE per key
	KindCounter             // CounterStore.advance: TRUE iff counter > last
)

type Store interface {
	Kind() Kind
	// Prepare creates anything that must pre-exist for a key/stream (NOT recorded in the history).
	Prepare(ctx context.Context, key string) error
	Consume(ctx context.Context, key string) (bool, error)
	Advance(ctx context.Context, key string, c int64) (bool, error)
	Close()
}

type Cfg struct {
	PgDSN        string // primary
	PgReplicaDSN string // hot standby (for pg-bad-replica)
	RedisAddr    string
	Conns        int
}

var storeNames = map[string]Kind{
	// Postgres, GOOD
	"pg-attest-nonce": KindConsume, // production PcaAttestNoncesRepository.consume: UPDATE .. WHERE consumed_at IS NULL RETURNING
	"pg-onconflict":   KindConsume, // INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < now RETURNING (reference ReplayStore)
	"pg-adjudicate":   KindCounter, // production: seed; BEGIN; SELECT .. FOR UPDATE; compare; UPDATE .. WHERE counter < $n; COMMIT
	"pg-updatewhere":  KindCounter, // single statement UPDATE .. WHERE counter < $n RETURNING (PcaCountersRepository.advance alone)
	"pg-advisory":     KindCounter, // pg_advisory_xact_lock; SELECT; UPDATE; COMMIT
	"pg-fastpath":     KindCounter, // adjudicate Phase A (unlocked read, may only deny) then pg-adjudicate Phase B
	// Postgres, BAD (positive controls)
	"pg-bad-selectupsert": KindConsume, // SELECT then INSERT .. ON CONFLICT DO UPDATE (overwrite)
	"pg-bad-readwrite":    KindCounter, // SELECT, then UPDATE .. SET counter=$n (no WHERE), no transaction
	"pg-bad-nolock":       KindCounter, // SELECT .. FOR UPDATE in autocommit (lock released at once), then blind UPDATE
	"pg-bad-replica":      KindCounter, // decision on a hot-standby read, then blind UPDATE on the primary
	// Redis, GOOD
	"redis-setnx": KindConsume, // SET key 1 NX PX ttl
	"redis-lua":   KindCounter, // EVAL compare-and-advance
	// Redis, BAD
	"redis-bad-getset":         KindCounter, // GET then SET
	"redis-bad-getset-consume": KindConsume,
}

func NewStore(name string, cfg Cfg) (Store, error) {
	if _, ok := storeNames[name]; !ok {
		return nil, fmt.Errorf("unknown store %q", name)
	}
	ctx := context.Background()
	if strings.HasPrefix(name, "pg-") {
		pc, err := pgxpool.ParseConfig(cfg.PgDSN)
		if err != nil {
			return nil, err
		}
		pc.MaxConns = int32(cfg.Conns)
		pc.MinConns = 0
		pc.MaxConnLifetime = 0
		pc.HealthCheckPeriod = 2 * time.Second
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			return nil, err
		}
		s := &pg{name: name, pool: pool}
		if name == "pg-bad-replica" {
			rc, err := pgxpool.ParseConfig(cfg.PgReplicaDSN)
			if err != nil {
				return nil, err
			}
			rc.MaxConns = int32(cfg.Conns)
			s.replica, err = pgxpool.NewWithConfig(ctx, rc)
			if err != nil {
				return nil, err
			}
		}
		return s, nil
	}
	rc := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, PoolSize: cfg.Conns, MaxRetries: -1, DialTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second})
	return &rd{name: name, c: rc}, nil
}

// ------------------------------------------------------------------ Postgres

type pg struct {
	name    string
	pool    *pgxpool.Pool
	replica *pgxpool.Pool
}

func (p *pg) Kind() Kind { return storeNames[p.name] }
func (p *pg) Close() {
	p.pool.Close()
	if p.replica != nil {
		p.replica.Close()
	}
}

const (
	sqlSeed    = `insert into pca_counters (instance_id, grant_ref, holder_pub) values ($1, $2, $3) on conflict do nothing`
	sqlLock    = `select counter from pca_counters where (instance_id = $1 and grant_ref = $2 and holder_pub = $3) limit 1 for update`
	sqlPlain   = `select counter from pca_counters where (instance_id = $1 and grant_ref = $2 and holder_pub = $3) limit 1`
	sqlAdvance = `update pca_counters set counter = $4, updated_at = now() where (instance_id = $1 and grant_ref = $2 and holder_pub = $3 and counter < $4) returning holder_pub`
	sqlBlind   = `update pca_counters set counter = $4, updated_at = now() where (instance_id = $1 and grant_ref = $2 and holder_pub = $3)`
)

func ids(stream string) (string, string, string) { return "ins", stream, "holder" }

func (p *pg) Prepare(ctx context.Context, key string) error {
	switch p.name {
	case "pg-attest-nonce":
		_, err := p.pool.Exec(ctx, `insert into pca_attest_nonces (instance_id, nonce, grant_ref, holder_pub, epoch) values ('ins', $1, 'g', 'h', 0) on conflict do nothing`, key)
		return err
	case "pg-onconflict", "pg-bad-selectupsert":
		return nil
	default:
		if strings.HasPrefix(p.name, "pg-") {
			a, b, c := ids(key)
			_, err := p.pool.Exec(ctx, sqlSeed, a, b, c)
			return err
		}
	}
	return nil
}

var errAbort = errors.New("abort")

func (p *pg) Consume(ctx context.Context, key string) (bool, error) {
	switch p.name {
	case "pg-attest-nonce":
		var n string
		err := p.pool.QueryRow(ctx, `update pca_attest_nonces set consumed_at = now() where (instance_id = 'ins' and nonce = $1 and consumed_at is null) returning nonce`, key).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	case "pg-onconflict":
		now := time.Now().UnixMilli()
		var k string
		err := p.pool.QueryRow(ctx, `insert into pca_replay_keys as t (key, until) values ($1, $2) on conflict (key) do update set until = excluded.until where t.until < $3 returning key`, key, now+3_600_000, now).Scan(&k)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	case "pg-bad-selectupsert":
		var one int
		err := p.pool.QueryRow(ctx, `select 1 from pca_replay_keys where key = $1`, key).Scan(&one)
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		_, err = p.pool.Exec(ctx, `insert into pca_replay_keys (key, until) values ($1, 1) on conflict (key) do update set until = excluded.until`, key)
		return err == nil, err
	}
	return false, fmt.Errorf("%s: not a consume store", p.name)
}

func (p *pg) Advance(ctx context.Context, stream string, c int64) (bool, error) {
	a, b, h := ids(stream)
	switch p.name {
	case "pg-updatewhere":
		var x string
		err := p.pool.QueryRow(ctx, sqlAdvance, a, b, h, c).Scan(&x)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	case "pg-adjudicate", "pg-fastpath":
		if p.name == "pg-fastpath" { // Phase A: unlocked read; may only deny
			var cur int64
			if err := p.pool.QueryRow(ctx, sqlPlain, a, b, h).Scan(&cur); err == nil && !(c > cur) {
				return false, nil
			}
		}
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer tx.Rollback(context.Background())
		var cur int64
		if err := tx.QueryRow(ctx, sqlLock, a, b, h).Scan(&cur); err != nil {
			return false, err
		}
		if !(c > cur) {
			return false, tx.Commit(ctx) // adjudicate returns a deny outcome; the tx still commits
		}
		var x string
		if err := tx.QueryRow(ctx, sqlAdvance, a, b, h, c).Scan(&x); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, tx.Commit(ctx)
			}
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err // outcome unknown to the caller
		}
		return true, nil
	case "pg-advisory":
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtext($1))`, "pca-counter:"+stream); err != nil {
			return false, err
		}
		var cur int64
		if err := tx.QueryRow(ctx, sqlPlain, a, b, h).Scan(&cur); err != nil {
			return false, err
		}
		if !(c > cur) {
			return false, tx.Commit(ctx)
		}
		if _, err := tx.Exec(ctx, sqlBlind, a, b, h, c); err != nil {
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	case "pg-bad-readwrite":
		var cur int64
		if err := p.pool.QueryRow(ctx, sqlPlain, a, b, h).Scan(&cur); err != nil {
			return false, err
		}
		if !(c > cur) {
			return false, nil
		}
		_, err := p.pool.Exec(ctx, sqlBlind, a, b, h, c)
		return err == nil, err
	case "pg-bad-nolock":
		var cur int64
		if err := p.pool.QueryRow(ctx, sqlLock, a, b, h).Scan(&cur); err != nil { // autocommit: lock dropped at statement end
			return false, err
		}
		if !(c > cur) {
			return false, nil
		}
		_, err := p.pool.Exec(ctx, sqlBlind, a, b, h, c)
		return err == nil, err
	case "pg-bad-replica":
		var cur int64
		if err := p.replica.QueryRow(ctx, sqlPlain, a, b, h).Scan(&cur); err != nil {
			cur = -1 // replica has not seen the seed yet
		}
		if !(c > cur) {
			return false, nil
		}
		_, err := p.pool.Exec(ctx, sqlBlind, a, b, h, c)
		return err == nil, err
	}
	return false, fmt.Errorf("%s: not a counter store", p.name)
}

// ------------------------------------------------------------------ Redis

type rd struct {
	name string
	c    *redis.Client
	n    atomic.Int64
}

func (r *rd) Kind() Kind                                    { return storeNames[r.name] }
func (r *rd) Close()                                        { r.c.Close() }
func (r *rd) Prepare(ctx context.Context, key string) error { return nil }

var luaAdvance = redis.NewScript(`
local cur = tonumber(redis.call('GET', KEYS[1]) or '-1')
local c = tonumber(ARGV[1])
if c > cur then redis.call('SET', KEYS[1], ARGV[1]) return 1 end
return 0`)

func (r *rd) Consume(ctx context.Context, key string) (bool, error) {
	switch r.name {
	case "redis-setnx":
		ok, err := r.c.SetNX(ctx, "n:"+key, 1, time.Hour).Result()
		return ok, err
	case "redis-bad-getset-consume":
		_, err := r.c.Get(ctx, "n:"+key).Result()
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, redis.Nil) {
			return false, err
		}
		return true, r.c.Set(ctx, "n:"+key, 1, time.Hour).Err()
	}
	return false, fmt.Errorf("%s: not a consume store", r.name)
}

func (r *rd) Advance(ctx context.Context, stream string, c int64) (bool, error) {
	switch r.name {
	case "redis-lua":
		v, err := luaAdvance.Run(ctx, r.c, []string{"c:" + stream}, c).Int()
		return v == 1, err
	case "redis-bad-getset":
		s, err := r.c.Get(ctx, "c:"+stream).Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return false, err
		}
		if errors.Is(err, redis.Nil) {
			s = -1
		}
		if !(c > s) {
			return false, nil
		}
		return true, r.c.Set(ctx, "c:"+stream, c, 0).Err()
	}
	return false, fmt.Errorf("%s: not a counter store", r.name)
}
