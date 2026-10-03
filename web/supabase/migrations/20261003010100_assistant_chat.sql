-- AI security assistant: per-user conversations, grounded in active company policies.
-- Developers are team_members too, but only see the assistant — the security data stays hidden.

-- "team member" now means the security team proper (admin/analyst/viewer), so every existing
-- RLS policy built on it keeps developers out of policies, incidents, events and the team list.
create or replace function public.is_team_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.team_members
    where user_id = auth.uid() and role in ('admin', 'analyst', 'viewer')
  )
$$;

-- any role, developers included: who may use the assistant
create function public.has_membership() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.team_members where user_id = auth.uid())
$$;

create table public.chat_conversations (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references public.team_members (user_id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 80),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.chat_messages (
  id              bigint generated always as identity primary key,
  conversation_id uuid not null references public.chat_conversations (id) on delete cascade,
  role            text not null check (role in ('user', 'assistant')),
  content         text not null check (char_length(content) between 1 and 8000),
  created_at      timestamptz not null default now()
);

create index chat_conversations_user_idx on public.chat_conversations (user_id, updated_at desc);
create index chat_messages_conversation_idx on public.chat_messages (conversation_id, id);

create trigger chat_conversations_touch before update on public.chat_conversations
  for each row execute function public.touch_updated_at();

alter table public.chat_conversations enable row level security;
alter table public.chat_messages      enable row level security;

-- conversations are private to their owner (admins don't read developers' chats either)
create policy "chats: owner all" on public.chat_conversations
  for all to authenticated
  using (user_id = auth.uid() and public.has_membership())
  with check (user_id = auth.uid() and public.has_membership());

create policy "chat messages: owner read" on public.chat_messages
  for select to authenticated using (
    exists (select 1 from public.chat_conversations c where c.id = conversation_id and c.user_id = auth.uid())
  );
create policy "chat messages: owner insert" on public.chat_messages
  for insert to authenticated with check (
    public.has_membership()
    and exists (select 1 from public.chat_conversations c where c.id = conversation_id and c.user_id = auth.uid())
  );

-- the assistant's knowledge: active policies only, readable by any member (developers can't
-- select from policies directly, so this hands out just what grounding needs)
create function public.assistant_policies()
returns table (id uuid, title text, category text, summary text, body text)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.has_membership() then
    raise exception 'not a team member';
  end if;
  return query
    select p.id, p.title, p.category, p.summary, p.body
    from public.policies p
    where p.status = 'active'
    order by p.title;
end $$;

revoke execute on function public.assistant_policies() from public, anon;
grant execute on function public.assistant_policies() to authenticated;
