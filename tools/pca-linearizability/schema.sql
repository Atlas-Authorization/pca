-- Same shapes as packages/db/src/schema/pca.ts (instance FK dropped: the harness has no instances table).
create table if not exists pca_counters (
  instance_id text not null, grant_ref text not null, holder_pub text not null,
  counter bigint not null default -1, updated_at timestamptz not null default now(),
  primary key (instance_id, grant_ref, holder_pub));
create table if not exists pca_attest_nonces (
  instance_id text not null, nonce text not null, grant_ref text not null, holder_pub text not null,
  epoch bigint not null, issued_at timestamptz not null default now(), consumed_at timestamptz,
  primary key (instance_id, nonce));
create table if not exists pca_replay_keys (key text primary key, until bigint not null);
