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
