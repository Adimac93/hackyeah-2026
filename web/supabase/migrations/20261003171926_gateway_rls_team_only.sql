-- The gateway tables were readable by any authenticated user ("single-tenant demo").
-- Now that sign-up doesn't grant access, restrict reads to the security team proper
-- (admin/analyst/viewer) — same rule as policies and incidents. Developers and accounts
-- without a role see nothing. The gateway writes over its privileged connection, so it's unaffected.

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
