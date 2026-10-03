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
