#!/usr/bin/env bash
# Runs ON the cloud box.  Private Postgres 16 primary (:5455) + streaming hot-standby (:5456) and Redis (:6390),
# all under $ROOT (default /work/replay-linz).  Never touches any other postgres / redis on the box.
#   box-setup.sh pg-start [sync_commit=on|off]   box-setup.sh pg-stop   box-setup.sh pg-kill9   box-setup.sh redis-start <aof=always|everysec|none>
#   box-setup.sh redis-kill9   box-setup.sh status
set -uo pipefail
ROOT="${ROOT:-/work/replay-linz}"; PGBIN=/usr/lib/postgresql/16/bin
PRI="$ROOT/pg"; REP="$ROOT/pgr"; RD="$ROOT/redis"
mkdir -p "$ROOT" "$RD"
pgconf() { cat >> "$1/postgresql.conf" <<CONF
listen_addresses = '127.0.0.1'
unix_socket_directories = '$ROOT'
max_connections = 600
shared_buffers = 1GB
fsync = on
synchronous_commit = ${SYNC:-on}
wal_level = replica
max_wal_senders = 4
hot_standby = on
wal_writer_delay = 200ms
log_min_messages = warning
CONF
}
case "${1:-}" in
pg-init)
  rm -rf "$PRI" "$REP"
  "$PGBIN/initdb" -D "$PRI" -U pca -A trust >/dev/null && { echo "port = 5455"; } >> "$PRI/postgresql.conf" && SYNC="${2:-on}" pgconf "$PRI"
  echo "host replication pca 127.0.0.1/32 trust" >> "$PRI/pg_hba.conf"
  "$PGBIN/pg_ctl" -D "$PRI" -l "$ROOT/pg.log" -w start >/dev/null
  "$PGBIN/createdb" -h 127.0.0.1 -p 5455 -U pca linz
  "$PGBIN/psql" -h 127.0.0.1 -p 5455 -U pca linz -q -f "$(dirname "$0")/schema.sql"
  "$PGBIN/pg_basebackup" -h 127.0.0.1 -p 5455 -U pca -D "$REP" -R -X stream -c fast >/dev/null
  echo "port = 5456" >> "$REP/postgresql.conf"
  "$PGBIN/pg_ctl" -D "$REP" -o "-c port=5456" -l "$ROOT/pgr.log" -w start >/dev/null
  echo "pg primary :5455 + standby :5456 up";;
pg-start) "$PGBIN/pg_ctl" -D "$PRI" -l "$ROOT/pg.log" -w -t 60 start >/dev/null && echo up;;
pg-stop)  "$PGBIN/pg_ctl" -D "$PRI" -m fast -w stop >/dev/null; "$PGBIN/pg_ctl" -D "$REP" -m fast -w stop >/dev/null 2>&1;;
pg-kill9) # SIGKILL every process of THIS cluster (their cwd is the data dir), so no orphan keeps the shared-memory block alive
  for p in /proc/[0-9]*; do [ "$(readlink "$p/cwd" 2>/dev/null)" = "$PRI" ] && kill -9 "${p#/proc/}" 2>/dev/null; done; sleep 0.3; true;;
pg-set-sync) "$PGBIN/psql" -h 127.0.0.1 -p 5455 -U pca linz -qc "alter system set synchronous_commit = '$2'" -c "select pg_reload_conf()" >/dev/null;;
pg-reset) "$PGBIN/psql" -h 127.0.0.1 -p 5455 -U pca linz -qc "truncate pca_counters, pca_attest_nonces, pca_replay_keys";;
redis-start)
  mode="${2:-always}"; : > "$RD/redis.conf"
  { echo "port 6390"; echo "bind 127.0.0.1"; echo "dir $RD"; echo "save \"\""; echo "daemonize yes"; echo "logfile $RD/redis.log"; echo "pidfile $RD/redis.pid"
    case "$mode" in always) echo "appendonly yes"; echo "appendfsync always";; everysec) echo "appendonly yes"; echo "appendfsync everysec";; none) echo "appendonly no";; esac; } > "$RD/redis.conf"
  redis-server "$RD/redis.conf" && echo "redis up ($mode)";;
redis-kill9) kill -9 "$(cat "$RD/redis.pid" 2>/dev/null)" 2>/dev/null; true;;
redis-reset) rm -rf "$RD/appendonlydir" "$RD/dump.rdb"; redis-cli -p 6390 flushall >/dev/null 2>&1; true;;
redis-stop) redis-cli -p 6390 shutdown nosave 2>/dev/null; true;;
status) "$PGBIN/pg_isready" -h 127.0.0.1 -p 5455; "$PGBIN/pg_isready" -h 127.0.0.1 -p 5456; redis-cli -p 6390 ping;;
*) sed -n 2,6p "$0"; exit 2;;
esac
