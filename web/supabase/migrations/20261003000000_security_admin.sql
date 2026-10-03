-- Security admin panel: team members, company policies, security incidents.
-- Access model: only rows in `team_members` can see anything.
--   admin   – everything, incl. managing team roles
--   analyst – manage policies and incidents
--   viewer  – read-only
-- Signing up does NOT grant access; an admin must add the user to team_members.

create type public.team_role as enum ('admin', 'analyst', 'viewer');
create type public.policy_status as enum ('draft', 'active', 'archived');
create type public.incident_severity as enum ('low', 'medium', 'high', 'critical');
create type public.incident_status as enum ('open', 'investigating', 'contained', 'resolved');

create table public.team_members (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  email      text not null,
  full_name  text,
  role       public.team_role not null default 'viewer',
  created_at timestamptz not null default now()
);

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

alter table public.team_members    enable row level security;
alter table public.policies        enable row level security;
alter table public.incidents       enable row level security;
alter table public.incident_events enable row level security;

-- team_members: you can always see your own row; members see the team; admins manage it
create policy "team: read self or as member" on public.team_members
  for select to authenticated using (user_id = auth.uid() or public.is_team_member());
create policy "team: admin insert" on public.team_members
  for insert to authenticated with check (public.is_admin());
create policy "team: admin update" on public.team_members
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "team: admin delete" on public.team_members
  for delete to authenticated using (public.is_admin() and user_id <> auth.uid());

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

-- bootstrap: the very first user to sign up becomes admin, everyone after waits for an invite
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
