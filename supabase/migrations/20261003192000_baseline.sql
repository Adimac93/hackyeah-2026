-- Baseline: every migration up to 20261003191812, squashed in version order.
-- The live database already has this schema; the history table was repaired to
-- record only this version (see the PR), so nothing here is re-run against it.
-- A fresh database gets the whole schema from this one file.


-- ============================================================================
-- 20261003151538_init_control_layer
-- ============================================================================

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


-- ============================================================================
-- 20261003152812_add_flag_control_action
-- ============================================================================

-- A control may fire without changing the request's fate: `flag` records the
-- detection and lets the call through. That is how a cheap deterministic
-- control marks traffic as suspicious so the semantic tier knows to look,
-- which is the mechanism that keeps p50 latency low.
--
-- `events.verdict` keeps the three outcomes a caller can observe
-- (allow/redact/block); only a detection can be a flag.

create type control_action as enum ('allow', 'flag', 'redact', 'block');

alter table detections
  alter column action type control_action
  using action::text::control_action;


-- ============================================================================
-- 20261003154246_security_team_members
-- ============================================================================

-- Security team membership. Only rows in team_members get console access.
--   admin   – everything, incl. managing team roles
--   analyst – manage policies and incidents
--   viewer  – read-only
create type public.team_role as enum ('admin', 'analyst', 'viewer');

create table public.team_members (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  email      text not null,
  full_name  text,
  role       public.team_role not null default 'viewer',
  created_at timestamptz not null default now()
);

-- role helpers (security definer so RLS on team_members doesn't recurse)
create function public.current_team_role() returns public.team_role
language sql stable security definer set search_path = '' as $$
  select role from public.team_members where user_id = auth.uid()
$$;

create function public.is_team_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members where user_id = auth.uid())
$$;

create function public.can_write() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(public.current_team_role() in ('admin', 'analyst'), false)
$$;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(public.current_team_role() = 'admin', false)
$$;

alter table public.team_members enable row level security;

create policy "team: read self or as member" on public.team_members
  for select to authenticated using (user_id = auth.uid() or public.is_team_member());
create policy "team: admin insert" on public.team_members
  for insert to authenticated with check (public.is_admin());
create policy "team: admin update" on public.team_members
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "team: admin delete" on public.team_members
  for delete to authenticated using (public.is_admin() and user_id <> auth.uid());

-- bootstrap: the very first user to sign up becomes admin
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.team_members) then
    insert into public.team_members (user_id, email, role)
    values (new.id, new.email, 'admin');
  end if;
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- admins add team members by email (auth.users isn't readable from the client)
create function public.add_team_member(member_email text, member_role public.team_role)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid;
begin
  if not public.is_admin() then
    raise exception 'only admins can add team members';
  end if;
  select id into uid from auth.users where lower(email) = lower(member_email);
  if uid is null then
    raise exception 'no account with email % — ask them to sign up first', member_email;
  end if;
  insert into public.team_members (user_id, email, role)
  values (uid, member_email, member_role)
  on conflict (user_id) do update set role = excluded.role;
end $$;

revoke execute on function public.add_team_member(text, public.team_role) from public, anon;
grant execute on function public.add_team_member(text, public.team_role) to authenticated;

-- existing first user predates the bootstrap trigger
insert into public.team_members (user_id, email, role)
select id, email, 'admin' from auth.users
where id = '7bb005d8-48b3-491b-987d-6bfc130b5676'
on conflict (user_id) do nothing;


-- ============================================================================
-- 20261003163238_security_admin
-- ============================================================================

-- Security admin panel: company policies and security incidents.
-- team_members and the role helpers live in security_team_members.

create type public.policy_status as enum ('draft', 'active', 'archived');
create type public.incident_severity as enum ('low', 'medium', 'high', 'critical');
create type public.incident_status as enum ('open', 'investigating', 'contained', 'resolved');

create table public.policies (
  id          uuid primary key default gen_random_uuid(),
  title       text not null check (char_length(title) between 3 and 200),
  category    text not null,
  summary     text not null default '',
  body        text not null default '',
  status      public.policy_status not null default 'draft',
  version     integer not null default 1,
  review_due  date,
  owner_id    uuid references public.team_members (user_id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table public.incidents (
  id           uuid primary key default gen_random_uuid(),
  title        text not null check (char_length(title) between 3 and 200),
  description  text not null default '',
  severity     public.incident_severity not null default 'medium',
  status       public.incident_status not null default 'open',
  category     text not null,
  source       text not null default 'manual',
  policy_id    uuid references public.policies (id) on delete set null,
  assignee_id  uuid references public.team_members (user_id) on delete set null,
  reported_by  uuid references public.team_members (user_id) on delete set null,
  detected_at  timestamptz not null default now(),
  resolved_at  timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table public.incident_events (
  id          bigint generated always as identity primary key,
  incident_id uuid not null references public.incidents (id) on delete cascade,
  author_id   uuid references public.team_members (user_id) on delete set null,
  kind        text not null default 'note', -- note | status | severity | assignee
  message     text not null,
  created_at  timestamptz not null default now()
);

create index incidents_status_idx on public.incidents (status);
create index incidents_severity_idx on public.incidents (severity);
create index incident_events_incident_idx on public.incident_events (incident_id, created_at);

-- keep updated_at / resolved_at honest
create function public.touch_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger policies_touch before update on public.policies
  for each row execute function public.touch_updated_at();

create function public.incidents_before_update() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  if new.status = 'resolved' and old.status <> 'resolved' then
    new.resolved_at := now();
  elsif new.status <> 'resolved' then
    new.resolved_at := null;
  end if;
  return new;
end $$;

create trigger incidents_touch before update on public.incidents
  for each row execute function public.incidents_before_update();

alter table public.policies        enable row level security;
alter table public.incidents       enable row level security;
alter table public.incident_events enable row level security;

-- policies
create policy "policies: members read" on public.policies
  for select to authenticated using (public.is_team_member());
create policy "policies: writers insert" on public.policies
  for insert to authenticated with check (public.can_write());
create policy "policies: writers update" on public.policies
  for update to authenticated using (public.can_write()) with check (public.can_write());
create policy "policies: admin delete" on public.policies
  for delete to authenticated using (public.is_admin());

-- incidents
create policy "incidents: members read" on public.incidents
  for select to authenticated using (public.is_team_member());
create policy "incidents: writers insert" on public.incidents
  for insert to authenticated with check (public.can_write());
create policy "incidents: writers update" on public.incidents
  for update to authenticated using (public.can_write()) with check (public.can_write());
create policy "incidents: admin delete" on public.incidents
  for delete to authenticated using (public.is_admin());

-- incident timeline is append-only
create policy "events: members read" on public.incident_events
  for select to authenticated using (public.is_team_member());
create policy "events: writers insert" on public.incident_events
  for insert to authenticated with check (public.can_write() and author_id = auth.uid());


-- ============================================================================
-- 20261003163242_developer_role
-- ============================================================================

-- Developer role: may only use the AI security assistant, nothing else in the console.
-- Kept in its own migration: a new enum value can't be used in the transaction that adds it.
alter type public.team_role add value if not exists 'developer';


-- ============================================================================
-- 20261003163309_assistant_chat
-- ============================================================================

-- AI security assistant: per-user conversations, grounded in active company policies.
-- Developers are team_members too, but only see the assistant — the security data stays hidden.

-- "team member" now means the security team proper (admin/analyst/viewer), so every existing
-- RLS policy built on it keeps developers out of policies, incidents, events and the team list.
create or replace function public.is_team_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.team_members
    where user_id = auth.uid() and role in ('admin', 'analyst', 'viewer')
  )
$$;

-- any role, developers included: who may use the assistant
create function public.has_membership() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members where user_id = auth.uid())
$$;

create table public.chat_conversations (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references public.team_members (user_id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 80),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.chat_messages (
  id              bigint generated always as identity primary key,
  conversation_id uuid not null references public.chat_conversations (id) on delete cascade,
  role            text not null check (role in ('user', 'assistant')),
  content         text not null check (char_length(content) between 1 and 8000),
  created_at      timestamptz not null default now()
);

create index chat_conversations_user_idx on public.chat_conversations (user_id, updated_at desc);
create index chat_messages_conversation_idx on public.chat_messages (conversation_id, id);

create trigger chat_conversations_touch before update on public.chat_conversations
  for each row execute function public.touch_updated_at();

alter table public.chat_conversations enable row level security;
alter table public.chat_messages      enable row level security;

-- conversations are private to their owner (admins don't read developers' chats either)
create policy "chats: owner all" on public.chat_conversations
  for all to authenticated
  using (user_id = auth.uid() and public.has_membership())
  with check (user_id = auth.uid() and public.has_membership());

create policy "chat messages: owner read" on public.chat_messages
  for select to authenticated using (
    exists (select 1 from public.chat_conversations c where c.id = conversation_id and c.user_id = auth.uid())
  );
create policy "chat messages: owner insert" on public.chat_messages
  for insert to authenticated with check (
    public.has_membership()
    and exists (select 1 from public.chat_conversations c where c.id = conversation_id and c.user_id = auth.uid())
  );

-- the assistant's knowledge: active policies only, readable by any member (developers can't
-- select from policies directly, so this hands out just what grounding needs)
create function public.assistant_policies()
returns table (id uuid, title text, category text, summary text, body text)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.has_membership() then
    raise exception 'not a team member';
  end if;
  return query
    select p.id, p.title, p.category, p.summary, p.body
    from public.policies p
    where p.status = 'active'
    order by p.title;
end $$;

revoke execute on function public.assistant_policies() from public, anon;
grant execute on function public.assistant_policies() to authenticated;


-- ============================================================================
-- 20261003163319_chat_models
-- ============================================================================

-- Multi-model assistant: remember which model each conversation uses and which model wrote each reply.
-- Ids look like `anthropic:claude-opus-5-5`, `openai:gpt-5`, `mock:security-assistant`.

alter table public.chat_conversations
  add column model text not null default 'mock:security-assistant';

alter table public.chat_messages
  add column model text; -- null for the user's own messages

-- real models answer at length; 8000 chars was sized for the mock
alter table public.chat_messages drop constraint chat_messages_content_check;
alter table public.chat_messages
  add constraint chat_messages_content_check check (char_length(content) between 1 and 32000);


-- ============================================================================
-- 20261003164306_team_registered_users
-- ============================================================================

-- Team page: admins see every registered account (auth.users isn't readable from the client)
-- and can give any of them a role, not only existing team members.

create function public.registered_users()
returns table (
  user_id         uuid,
  email           text,
  full_name       text,
  role            public.team_role,
  registered_at   timestamptz,
  last_sign_in_at timestamptz
)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'only admins can list registered users';
  end if;
  return query
    select u.id, u.email::text, m.full_name, m.role, u.created_at, u.last_sign_in_at
    from auth.users u
    left join public.team_members m on m.user_id = u.id
    order by m.role is null, u.created_at;
end $$;

-- assign a role to any registered user, or change an existing member's role
create function public.set_user_role(target_user_id uuid, new_role public.team_role)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  target_email text;
begin
  if not public.is_admin() then
    raise exception 'only admins can change roles';
  end if;
  if target_user_id = auth.uid() then
    raise exception 'you can''t change your own role';
  end if;
  select email into target_email from auth.users where id = target_user_id;
  if target_email is null then
    raise exception 'no such user';
  end if;
  insert into public.team_members (user_id, email, role)
  values (target_user_id, target_email, new_role)
  on conflict (user_id) do update set role = excluded.role;
end $$;

revoke execute on function public.registered_users() from public, anon;
grant execute on function public.registered_users() to authenticated;
revoke execute on function public.set_user_role(uuid, public.team_role) from public, anon;
grant execute on function public.set_user_role(uuid, public.team_role) to authenticated;


-- ============================================================================
-- 20261003171118_team_invites
-- ============================================================================

-- Invite people who don't have an account yet: an admin records email + role, and the role is
-- granted automatically once that email is confirmed (never on an unconfirmed signup, or
-- anyone could claim an invite by registering the address first).

create table public.team_invites (
  email      text primary key check (email = lower(email) and email like '%@%'),
  role       public.team_role not null,
  invited_by uuid references public.team_members (user_id) on delete set null,
  created_at timestamptz not null default now()
);

alter table public.team_invites enable row level security;

create policy "invites: admin read" on public.team_invites
  for select to authenticated using (public.is_admin());
create policy "invites: admin delete" on public.team_invites
  for delete to authenticated using (public.is_admin());

-- grants the role right away if the account already exists, otherwise stores an invite
create function public.invite_team_member(member_email text, member_role public.team_role)
returns text
language plpgsql security definer set search_path = '' as $$
declare
  normalized text := lower(trim(member_email));
  uid uuid;
begin
  if not public.is_admin() then
    raise exception 'only admins can invite team members';
  end if;
  if normalized not like '%@%' then
    raise exception 'enter a valid email';
  end if;
  select id into uid from auth.users where lower(email) = normalized;
  if uid = auth.uid() then
    raise exception 'you can''t change your own role';
  end if;
  if uid is not null then
    insert into public.team_members (user_id, email, role)
    values (uid, normalized, member_role)
    on conflict (user_id) do update set role = excluded.role;
    return 'granted';
  end if;
  insert into public.team_invites (email, role, invited_by)
  values (normalized, member_role, auth.uid())
  on conflict (email) do update set role = excluded.role, invited_by = excluded.invited_by, created_at = now();
  return 'invited';
end $$;

revoke execute on function public.invite_team_member(text, public.team_role) from public, anon;
grant execute on function public.invite_team_member(text, public.team_role) to authenticated;

create function public.claim_team_invite() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  invite public.team_invites;
begin
  if new.email_confirmed_at is null
     or (tg_op = 'UPDATE' and old.email_confirmed_at is not null) then
    return new;
  end if;
  delete from public.team_invites where email = lower(new.email) returning * into invite;
  if invite.email is not null then
    insert into public.team_members (user_id, email, role)
    values (new.id, new.email, invite.role)
    on conflict (user_id) do nothing;
  end if;
  return new;
end $$;

create trigger on_auth_user_confirmed
  after insert or update of email_confirmed_at on auth.users
  for each row execute function public.claim_team_invite();


-- ============================================================================
-- 20261003171926_gateway_rls_team_only
-- ============================================================================

-- Recovered from the database: applied directly, never committed.
--
-- The gateway tables were readable by any authenticated user ("single-tenant
-- demo"). Now that sign-up does not grant access, restrict reads to the security
-- team proper (admin/analyst/viewer) — the same rule as policies and incidents.
-- Developers and accounts without a role see nothing.
--
-- docs/BACKEND.md: the dashboard reads persisted data through the Data API as
-- the security team and RLS keeps that read-only, so it can never rewrite the
-- audit log it displays. The gateway writes over its privileged connection and
-- is unaffected by any of this.

drop policy "security team reads principals" on public.principals;
drop policy "security team reads policies"   on public.policy_versions;
drop policy "security team reads events"     on public.events;
drop policy "security team reads detections" on public.detections;
drop policy "security team reads usage"      on public.usage;
drop policy "security team reads budgets"    on public.budgets;
drop policy "security team reads signatures" on public.attack_signatures;

create policy "security team reads principals" on public.principals
  for select to authenticated using (public.is_team_member());
create policy "security team reads policies" on public.policy_versions
  for select to authenticated using (public.is_team_member());
create policy "security team reads events" on public.events
  for select to authenticated using (public.is_team_member());
create policy "security team reads detections" on public.detections
  for select to authenticated using (public.is_team_member());
create policy "security team reads usage" on public.usage
  for select to authenticated using (public.is_team_member());
create policy "security team reads budgets" on public.budgets
  for select to authenticated using (public.is_team_member());
create policy "security team reads signatures" on public.attack_signatures
  for select to authenticated using (public.is_team_member());


-- ============================================================================
-- 20261003173505_invite_only_confirmed_accounts
-- ============================================================================

-- Recovered from the database: applied directly, never committed.
--
-- Invite emails create the auth user up front (unconfirmed). Only grant
-- immediately to confirmed accounts; an unconfirmed one keeps a pending invite,
-- so re-inviting resends the email and the role is still claimed on
-- confirmation (claim_team_invite).

create or replace function public.invite_team_member(member_email text, member_role public.team_role)
returns text
language plpgsql security definer set search_path = '' as $$
declare
  normalized text := lower(trim(member_email));
  uid uuid;
begin
  if not public.is_admin() then
    raise exception 'only admins can invite team members';
  end if;
  if normalized not like '%@%' then
    raise exception 'enter a valid email';
  end if;
  select id into uid from auth.users
  where lower(email) = normalized and email_confirmed_at is not null;
  if uid = auth.uid() then
    raise exception 'you can''t change your own role';
  end if;
  if uid is not null then
    insert into public.team_members (user_id, email, role)
    values (uid, normalized, member_role)
    on conflict (user_id) do update set role = excluded.role;
    return 'granted';
  end if;
  insert into public.team_invites (email, role, invited_by)
  values (normalized, member_role, auth.uid())
  on conflict (email) do update set role = excluded.role, invited_by = excluded.invited_by, created_at = now();
  return 'invited';
end $$;


-- ============================================================================
-- 20261003181217_background_semantic_analyses
-- ============================================================================

-- Results produced after the request has left the latency-sensitive path.
-- They are separate from `detections`: an event's detections are committed
-- into its audit hash, so appending to them later would break the chain.
create table public.semantic_analyses (
  id           bigserial primary key,
  event_id     bigint not null unique references public.events (id) on delete cascade,
  completed_at timestamptz not null default now(),
  verdict      public.verdict not null,
  latency_us   bigint not null check (latency_us >= 0),
  -- One entry per evaluated control, including below-threshold scores and
  -- detector errors. This proves a clean analysis actually completed.
  results      jsonb not null default '[]'::jsonb,
  constraint semantic_analyses_results_array check (jsonb_typeof(results) = 'array')
);
create index semantic_analyses_completed_idx
  on public.semantic_analyses (completed_at desc);
create index semantic_analyses_incident_idx
  on public.semantic_analyses (verdict, completed_at desc)
  where verdict <> 'allow';
alter table public.semantic_analyses enable row level security;
-- The gateway's privileged connection is the only writer. The dashboard has
-- the same read-only access as it does for events and detections.
create policy "security team reads semantic analyses"
  on public.semantic_analyses for select to authenticated
  using (public.is_team_member());


-- ============================================================================
-- 20261003190000_gateway_identity_and_policy_uploads
-- ============================================================================

-- Gateway identities authenticate with individual Bearer keys.  Only the
-- SHA-256 digest is retained, so a database read cannot be replayed as a key.
alter table public.principals
  add column if not exists api_key_hash text unique,
  add column if not exists role text not null default 'member'
    check (role in ('member', 'security_viewer', 'security_analyst', 'security_admin'));

-- The uploaded text and the change summary make a policy version portable:
-- every instance can recover the active configuration without the original
-- local file.  They are readable through the existing security-team RLS only.
alter table public.policy_versions
  add column if not exists catalog_toml text,
  add column if not exists diff_summary text,
  add column if not exists uploaded_by uuid references public.principals(id) on delete set null;

-- Risk history is intentionally metadata-only.  It links repeated attempts
-- without making the security database another copy of sensitive prompts.
create table if not exists public.attack_history (
  id bigserial primary key,
  principal_id uuid references public.principals(id) on delete set null,
  trace_id uuid not null,
  control_id text not null,
  action verdict not null,
  risk_score real not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists attack_history_principal_created_idx
  on public.attack_history(principal_id, created_at desc);

alter table public.attack_history enable row level security;
create policy "security team reads attack history" on public.attack_history
  for select to authenticated using (public.is_team_member());
grant select on public.attack_history to authenticated;


-- ============================================================================
-- 20261003190005_llm_providers
-- ============================================================================

-- LLM connections managed from the console (in addition to env-configured ones).
-- The API key is write-only for clients: column privileges hide it from every API role,
-- and only the server (service role) reads it to call the provider.

create table public.llm_providers (
  id           uuid primary key default gen_random_uuid(),
  name         text not null check (char_length(name) between 1 and 60),
  preset       text not null default 'custom',
  kind         text not null check (kind in ('anthropic', 'openai', 'compatible')),
  base_url     text check (base_url is null or base_url ~ '^https?://'),
  api_key      text,
  api_key_hint text,
  models       text[] not null default '{}' check (cardinality(models) between 1 and 50),
  enabled      boolean not null default true,
  created_by   uuid references public.team_members (user_id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create trigger llm_providers_touch before update on public.llm_providers
  for each row execute function public.touch_updated_at();

alter table public.llm_providers enable row level security;

-- anyone who may use the assistant sees which models exist (not the keys)
create policy "llm providers: members read" on public.llm_providers
  for select to authenticated using (public.has_membership());
create policy "llm providers: admin insert" on public.llm_providers
  for insert to authenticated with check (public.is_admin());
create policy "llm providers: admin update" on public.llm_providers
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "llm providers: admin delete" on public.llm_providers
  for delete to authenticated using (public.is_admin());

revoke all on public.llm_providers from anon, authenticated;
grant select (id, name, preset, kind, base_url, api_key_hint, models, enabled, created_by, created_at, updated_at)
  on public.llm_providers to authenticated;
grant insert (name, preset, kind, base_url, api_key, api_key_hint, models, enabled, created_by)
  on public.llm_providers to authenticated;
grant update (name, preset, kind, base_url, api_key, api_key_hint, models, enabled)
  on public.llm_providers to authenticated;
grant delete on public.llm_providers to authenticated;


-- ============================================================================
-- 20261003191812_llm_provider_keys_in_vault
-- ============================================================================

-- Move LLM API keys out of the table into Supabase Vault (authenticated encryption, key
-- managed outside the database tables). The table keeps only a reference, a last-4 hint and a
-- SHA-256 fingerprint. A one-way hash can't be used for the key itself: the server has to send
-- the original to the provider. Only the service role can decrypt.

alter table public.llm_providers
  add column api_key_secret_id uuid,
  add column api_key_fingerprint text;

-- carry over any keys stored in plain text so far
do $$
declare
  row record;
begin
  for row in select id, api_key from public.llm_providers where api_key is not null loop
    update public.llm_providers
    set api_key_secret_id = vault.create_secret(row.api_key, 'llm_provider_' || row.id, 'API key for a console LLM connection'),
        api_key_hint = case when length(row.api_key) >= 12 then '…' || right(row.api_key, 4) else '••••' end,
        api_key_fingerprint = left(encode(extensions.digest(row.api_key, 'sha256'), 'hex'), 16)
    where id = row.id;
  end loop;
end $$;

alter table public.llm_providers drop column api_key;

-- the hint and fingerprint are derived from the key, so only the function below sets them
revoke insert (api_key_hint), update (api_key_hint) on public.llm_providers from authenticated;
grant select (api_key_fingerprint) on public.llm_providers to authenticated;

-- admins set or rotate a connection's key; it goes straight into Vault
create function public.set_llm_provider_key(provider_id uuid, new_key text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  secret_id uuid;
  trimmed text := trim(coalesce(new_key, ''));
begin
  if not public.is_admin() then
    raise exception 'only admins can set API keys';
  end if;
  if trimmed = '' then
    raise exception 'API key is empty';
  end if;

  select api_key_secret_id into secret_id
  from public.llm_providers where id = provider_id
  for update;
  if not found then
    raise exception 'connection not found';
  end if;

  if secret_id is null then
    secret_id := vault.create_secret(trimmed, 'llm_provider_' || provider_id, 'API key for a console LLM connection');
  else
    perform vault.update_secret(secret_id, trimmed);
  end if;

  update public.llm_providers
  set api_key_secret_id = secret_id,
      api_key_hint = case when length(trimmed) >= 12 then '…' || right(trimmed, 4) else '••••' end,
      api_key_fingerprint = left(encode(extensions.digest(trimmed, 'sha256'), 'hex'), 16)
  where id = provider_id;
end $$;

revoke execute on function public.set_llm_provider_key(uuid, text) from public, anon;
grant execute on function public.set_llm_provider_key(uuid, text) to authenticated;

-- decrypt for an outgoing provider call: server (service role) only
create function public.llm_provider_key(provider_id uuid)
returns text
language sql stable security definer set search_path = '' as $$
  select s.decrypted_secret
  from public.llm_providers p
  join vault.decrypted_secrets s on s.id = p.api_key_secret_id
  where p.id = provider_id
$$;

revoke execute on function public.llm_provider_key(uuid) from public, anon, authenticated;
grant execute on function public.llm_provider_key(uuid) to service_role;

-- deleting a connection deletes its secret
create function public.delete_llm_provider_secret() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if old.api_key_secret_id is not null then
    delete from vault.secrets where id = old.api_key_secret_id;
  end if;
  return old;
end $$;

create trigger llm_providers_delete_secret after delete on public.llm_providers
  for each row execute function public.delete_llm_provider_secret();

