-- Human-approved access requests (gateway table).
--
-- An agent missing a tool calls `control__request_access`; the gateway pushes
-- the request to the SecOps console and a team member approves or denies it.
-- An approved row is a time-boxed grant (`expires_at`) that the tool gate
-- honours next to `principals.allowed_tools`.
--
-- Written only by the gateway's privileged connection. The console reads it
-- and decides through the gateway's admin API, never by writing here.

create type access_status as enum ('pending', 'approved', 'denied', 'expired');

create table access_requests (
  id            uuid primary key default gen_random_uuid(),
  principal_id  uuid not null references principals (id) on delete cascade,
  tool          text not null,
  -- The model-written reason after the tool_call controls ran; possibly redacted.
  reason        text not null,
  ttl_minutes   int not null default 15 check (ttl_minutes between 1 and 60),
  status        access_status not null default 'pending',
  requested_at  timestamptz not null default now(),
  decided_at    timestamptz,
  decided_by    text,
  note          text,
  expires_at    timestamptz,
  constraint access_requests_grant_has_expiry check (status <> 'approved' or expires_at is not null)
);

create index access_requests_grants_idx on access_requests (principal_id, tool) where status = 'approved';
create index access_requests_principal_idx on access_requests (principal_id);
create index access_requests_requested_idx on access_requests (requested_at desc);

alter table access_requests enable row level security;

create policy "security team reads access requests" on public.access_requests
  for select to authenticated using (public.is_team_member());

grant select on access_requests to authenticated;
