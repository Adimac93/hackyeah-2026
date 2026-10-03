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
