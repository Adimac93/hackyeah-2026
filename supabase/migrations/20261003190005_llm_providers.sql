-- LLM connections managed from the console (in addition to env-configured ones).
-- The API key is write-only for clients: column privileges hide it from every API role,
-- and only the server (service role) reads it to call the provider.

create table public.llm_providers (
  id           uuid primary key default gen_random_uuid(),
  name         text not null check (char_length(name) between 1 and 60),
  preset       text not null default 'custom',
  kind         text not null check (kind in ('anthropic', 'openai', 'compatible')),
  base_url     text check (base_url is null or base_url ~ '^https?://'),
  api_key      text,
  api_key_hint text,
  models       text[] not null default '{}' check (cardinality(models) between 1 and 50),
  enabled      boolean not null default true,
  created_by   uuid references public.team_members (user_id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create trigger llm_providers_touch before update on public.llm_providers
  for each row execute function public.touch_updated_at();

alter table public.llm_providers enable row level security;

-- anyone who may use the assistant sees which models exist (not the keys)
create policy "llm providers: members read" on public.llm_providers
  for select to authenticated using (public.has_membership());
create policy "llm providers: admin insert" on public.llm_providers
  for insert to authenticated with check (public.is_admin());
create policy "llm providers: admin update" on public.llm_providers
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "llm providers: admin delete" on public.llm_providers
  for delete to authenticated using (public.is_admin());

revoke all on public.llm_providers from anon, authenticated;
grant select (id, name, preset, kind, base_url, api_key_hint, models, enabled, created_by, created_at, updated_at)
  on public.llm_providers to authenticated;
grant insert (name, preset, kind, base_url, api_key, api_key_hint, models, enabled, created_by)
  on public.llm_providers to authenticated;
grant update (name, preset, kind, base_url, api_key, api_key_hint, models, enabled)
  on public.llm_providers to authenticated;
grant delete on public.llm_providers to authenticated;
