-- AI Control Layer — initial schema.
--
-- Trust model: the gateway (Rust/sqlx) connects as a privileged role and is the
-- only writer; RLS below therefore governs read access through the Data API,
-- which is how the admin dashboard reads. Single-tenant for the demo: any
-- authenticated user is a security-team member and may read everything. There is
-- deliberately no authenticated write path — the audit log is append-only from
-- the gateway, so the dashboard cannot rewrite its own evidence.

create extension if not exists vector with schema extensions;

-- ---------------------------------------------------------------- enums

create type verdict as enum ('allow', 'redact', 'block');

-- the four enforcement points
create type hook as enum ('prompt_in', 'response_out', 'tool_call', 'tool_result');

create type channel as enum ('llm', 'mcp', 'a2a');

-- §4.2: the hybrid split, recorded per detection so the dashboard can show
-- how much work the cheap tier absorbed before escalation.
create type control_kind as enum ('deterministic', 'semantic');

create type severity as enum ('info', 'low', 'medium', 'high', 'critical');

create type budget_scope as enum ('global', 'principal', 'model');

-- ---------------------------------------------------------------- identity

-- §4.2.1: who is calling. Agents, apps and humans all land here.
create table principals (
  id            uuid primary key default gen_random_uuid(),
  slug          text not null unique,
  display_name  text not null,
  kind          text not null default 'agent',
  allowed_models text[] not null default '{}',
  allowed_tools  text[] not null default '{}',
  enabled       bool not null default true,
  created_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------- policy

-- §4.1: the YAML control catalog stays the authored source of truth so judges
-- can edit a file and watch it hot-reload. Every version the gateway loads is
-- recorded here, so each decision in `events` can be traced to the exact policy
-- text that produced it.
create table policy_versions (
  id          bigserial primary key,
  sha256      text not null unique,
  source      text not null,
  loaded_at   timestamptz not null default now(),
  active      bool not null default true,
  note        text
);

create index policy_versions_active_idx on policy_versions (loaded_at desc) where active;

-- ---------------------------------------------------------------- audit log

-- §4.5: one row per intercepted interaction. Hash-chained (prev_hash -> hash,
-- computed by the gateway) so a deleted or edited row breaks the chain and the
-- dashboard can prove the log is intact.
create table events (
  id                bigserial primary key,
  ts                timestamptz not null default now(),
  trace_id          uuid not null,
  hook              hook not null,
  channel           channel not null,
  principal_id      uuid references principals (id) on delete set null,
  model             text,
  tool              text,
  verdict           verdict not null,
  policy_version_id bigint references policy_versions (id) on delete set null,
  -- §6 wants performance telemetry: per-stage microseconds, e.g.
  -- {"deterministic_us": 180, "semantic_us": 41200, "upstream_us": 910}
  latency           jsonb not null default '{}'::jsonb,
  payload_sha256    text,
  prev_hash         bytea,
  hash              bytea not null
);

create index events_ts_idx on events (ts desc);
create index events_trace_idx on events (trace_id);
create index events_verdict_idx on events (verdict, ts desc) where verdict <> 'allow';

-- ---------------------------------------------------------------- detections

-- One row per control that fired. `evidence` never stores the matched secret
-- itself — only its type, offsets and a redacted excerpt. A security tool whose
-- audit log is a copy of the data it was meant to protect has failed.
create table detections (
  id          bigserial primary key,
  event_id    bigint not null references events (id) on delete cascade,
  control_id  text not null,
  kind        control_kind not null,
  severity    severity not null,
  score       real,
  action      verdict not null,
  evidence    jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

create index detections_event_idx on detections (event_id);
create index detections_control_idx on detections (control_id, created_at desc);

-- ---------------------------------------------------------------- budgets

-- §4.3: token and money accounting, one row per upstream model call.
create table usage (
  id                bigserial primary key,
  ts                timestamptz not null default now(),
  event_id          bigint references events (id) on delete set null,
  principal_id      uuid references principals (id) on delete set null,
  model             text not null,
  prompt_tokens     int not null default 0,
  completion_tokens int not null default 0,
  cost_usd          numeric(12, 6) not null default 0
);

create index usage_principal_ts_idx on usage (principal_id, ts desc);
create index usage_ts_idx on usage (ts desc);

create table budgets (
  id            bigserial primary key,
  scope         budget_scope not null,
  scope_id      text,
  window_secs   int not null default 86400,
  limit_usd     numeric(12, 6),
  limit_tokens  bigint,
  hard          bool not null default true,
  enabled       bool not null default true,
  created_at    timestamptz not null default now(),
  constraint budgets_scope_id_present check (scope = 'global' or scope_id is not null),
  constraint budgets_has_a_limit check (limit_usd is not null or limit_tokens is not null)
);

create unique index budgets_scope_idx on budgets (scope, coalesce(scope_id, ''));

-- ---------------------------------------------------------------- signatures

-- §4.4: externally managed feed of known-bad patterns — malicious code
-- execution, unsafe deserialization, poisoned model repos. `pattern` carries
-- the deterministic rule; `embedding` lets the semantic tier catch variants
-- that evade the literal pattern.
create table attack_signatures (
  id          bigserial primary key,
  external_id text not null,
  source      text not null,
  kind        control_kind not null default 'deterministic',
  severity    severity not null default 'high',
  title       text not null,
  pattern     text,
  embedding   extensions.vector(384),
  cve         text,
  enabled     bool not null default true,
  synced_at   timestamptz not null default now(),
  unique (source, external_id)
);

create index attack_signatures_enabled_idx on attack_signatures (kind) where enabled;

-- ---------------------------------------------------------------- RLS
--
-- Every table in `public` is reachable through the Data API once the anon or
-- authenticated role is granted access, so RLS is mandatory, not defence in
-- depth. Read-only for authenticated; no policy grants insert/update/delete,
-- so only the gateway's privileged connection can write.

alter table principals       enable row level security;
alter table policy_versions  enable row level security;
alter table events           enable row level security;
alter table detections       enable row level security;
alter table usage            enable row level security;
alter table budgets          enable row level security;
alter table attack_signatures enable row level security;

create policy "security team reads principals"   on principals       for select to authenticated using (true);
create policy "security team reads policies"     on policy_versions  for select to authenticated using (true);
create policy "security team reads events"       on events           for select to authenticated using (true);
create policy "security team reads detections"   on detections       for select to authenticated using (true);
create policy "security team reads usage"        on usage            for select to authenticated using (true);
create policy "security team reads budgets"      on budgets          for select to authenticated using (true);
create policy "security team reads signatures"   on attack_signatures for select to authenticated using (true);

grant select on principals, policy_versions, events, detections, usage, budgets, attack_signatures to authenticated;
