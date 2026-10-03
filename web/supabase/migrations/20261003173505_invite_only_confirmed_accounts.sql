-- Invite emails create the auth user up front (unconfirmed). Only grant immediately to
-- confirmed accounts; an unconfirmed one keeps a pending invite, so re-inviting resends
-- the email and the role is still claimed on confirmation (claim_team_invite).
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
