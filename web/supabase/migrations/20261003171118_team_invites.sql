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
