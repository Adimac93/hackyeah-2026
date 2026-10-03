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
