-- The control catalog lives in the database for its whole life: the gateway
-- never reads it from disk, uploads are the only change path, and every
-- instance polls the one active row. Budgets and grants live here too, and the
-- console's admin actions against the gateway are recorded.

-- ---------------------------------------------------------------- policy

-- The attack-signature feed is uploaded and versioned with the catalog.
alter table public.policy_versions
  add column if not exists signatures_toml text;

-- Uploads are made by console users (Supabase Auth), not gateway principals.
alter table public.policy_versions
  drop column if exists uploaded_by,
  add column if not exists uploaded_by_user uuid references auth.users (id) on delete set null;

-- Exactly one active version. Keep the newest if several are marked active.
update public.policy_versions set active = false
where active and id <> (
  select id from public.policy_versions where active order by loaded_at desc, id desc limit 1
);
create unique index if not exists policy_versions_one_active
  on public.policy_versions (active) where active;

-- ---------------------------------------------------------------- identity

-- Admin access is a console role (team_members), not a principal property.
alter table public.principals drop column if exists role;

-- ---------------------------------------------------------------- budgets

alter table public.budgets
  add column if not exists limit_requests bigint,
  add column if not exists limit_concurrency int,
  drop constraint if exists budgets_has_a_limit,
  add constraint budgets_has_a_limit check (
    limit_usd is not null or limit_tokens is not null
    or limit_requests is not null or limit_concurrency is not null
  );

-- ---------------------------------------------------------------- history

-- A flag is a control action, not a verdict; inserting 'flag' into a verdict
-- column failed, so flagged traffic never reached the history.
alter table public.attack_history
  alter column action type control_action using action::text::control_action;

-- ---------------------------------------------------------------- admin audit

-- Every state-changing call to the gateway admin API, accepted or rejected.
create table public.admin_actions (
  id            bigserial primary key,
  ts            timestamptz not null default now(),
  actor_user_id uuid references auth.users (id) on delete set null,
  actor_email   text,
  action        text not null,
  target        text,
  outcome       text not null check (outcome in ('accepted', 'rejected')),
  detail        jsonb not null default '{}'::jsonb
);

create index admin_actions_ts_idx on public.admin_actions (ts desc);

alter table public.admin_actions enable row level security;
create policy "security team reads admin actions" on public.admin_actions
  for select to authenticated using (public.is_team_member());
grant select on public.admin_actions to authenticated;

-- ---------------------------------------------------------------- resources

-- Rows produced by the `resources__query` MCP tool. They are delivered to the
-- principal that issued the query and never to the model. Gateway-only: RLS on
-- with no policy, so the Data API exposes nothing.
create table public.resource_results (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null default now() + interval '1 hour',
  principal_id uuid not null references public.principals (id) on delete cascade,
  trace_id     uuid not null,
  tool         text not null,
  columns      text[] not null,
  row_count    int not null,
  rows         jsonb not null
);

create index resource_results_principal_idx on public.resource_results (principal_id, created_at desc);

alter table public.resource_results enable row level security;

-- The protected organisational data the resource tools query. A separate
-- schema the Data API does not expose; the gateway reaches it over
-- RESOURCES_DATABASE_URL inside a read-only transaction.
create schema if not exists resources;
revoke all on schema resources from anon, authenticated;

create table if not exists resources.customers (
  id         bigserial primary key,
  full_name  text not null,
  email      text not null,
  phone      text,
  country    text not null,
  plan       text not null,
  mrr_usd    numeric(10, 2) not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists resources.invoices (
  id          bigserial primary key,
  customer_id bigint not null references resources.customers (id) on delete cascade,
  amount_usd  numeric(10, 2) not null,
  status      text not null,
  issued_at   timestamptz not null default now()
);
