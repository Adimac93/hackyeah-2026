-- Organisation-wide settings for the security assistant chat. One row.
-- `default_model` is a model option id (`anthropic:…`, `gateway:…`,
-- `db:<connection id>:<model>`, `mock:…`) chosen on the Models page; new chats
-- start on it. A conversation keeps the model it was last used with. When the
-- stored model is no longer available the chat falls back to the first one.

create table public.chat_settings (
  id boolean primary key default true check (id),
  default_model text check (default_model is null or length(default_model) between 1 and 300),
  updated_by uuid references auth.users (id) on delete set null default auth.uid(),
  updated_at timestamptz not null default now()
);

create trigger chat_settings_touch before update on public.chat_settings
  for each row execute function public.touch_updated_at();

alter table public.chat_settings enable row level security;

-- everyone who may use the assistant needs the default; only admins change it
create policy "chat settings: members read" on public.chat_settings
  for select to authenticated using (public.has_membership());
create policy "chat settings: admin insert" on public.chat_settings
  for insert to authenticated with check (public.is_admin());
create policy "chat settings: admin update" on public.chat_settings
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

revoke all on public.chat_settings from anon, authenticated;
grant select on public.chat_settings to authenticated;
grant insert (id, default_model, updated_by) on public.chat_settings to authenticated;
-- upsert re-sets every column it sends, the pk included
grant update (id, default_model, updated_by) on public.chat_settings to authenticated;
