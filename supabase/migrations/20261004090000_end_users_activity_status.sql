-- Users, not principals, are what the console governs: one console principal
-- carries every signed-in person's chat, so budgets, risk and activity are
-- attributed to the end user it acts for (docs/BACKEND.md, "Data access
-- control"). A caller that delegates nothing is its own user.

-- ---------------------------------------------------------------- identity

-- Only a principal with this flag may name the end user it acts for
-- (`X-On-Behalf-Of`); anyone else sending the header is refused.
alter table public.principals
  add column if not exists delegates_users bool not null default false;

-- The user a row is attributed to: the delegated end user, or the calling
-- principal's slug. Outside the hash chain, like principal_id.
alter table public.events         add column if not exists end_user text;
alter table public.usage          add column if not exists end_user text;
alter table public.attack_history add column if not exists end_user text;

create index if not exists events_end_user_ts_idx
  on public.events (end_user, ts desc) where end_user is not null;
create index if not exists usage_end_user_ts_idx
  on public.usage (end_user, ts desc) where end_user is not null;
create index if not exists attack_history_end_user_created_idx
  on public.attack_history (end_user, created_at desc) where end_user is not null;

-- ---------------------------------------------------------------- budgets

-- A per-identity budget is now per user. Existing rows keep matching: an agent
-- that delegates nothing is the user named by its slug.
alter type public.budget_scope rename value 'principal' to 'user';

-- ---------------------------------------------------------------- activity

-- The console's activity feed: every event with its security status, derived
-- only from hash-chained fields (verdict, detection actions), so the status
-- cannot be edited apart from the record it describes.
create or replace view public.activity with (security_invoker = true) as
select
  e.*,
  case
    when e.verdict = 'block' then 'blocked'
    when e.verdict = 'redact' then 'redacted'
    when exists (
      select 1 from public.detections d where d.event_id = e.id and d.action = 'flag'
    ) then 'flagged'
    else 'secure'
  end as status
from public.events e;

grant select on public.activity to authenticated;

-- Live activity over websockets: Supabase Realtime streams inserts on events
-- to the console. RLS still applies, so only the security team receives them.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'events'
     ) then
    alter publication supabase_realtime add table public.events;
  end if;
end $$;
