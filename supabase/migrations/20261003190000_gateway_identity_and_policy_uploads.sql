-- Gateway identities authenticate with individual Bearer keys.  Only the
-- SHA-256 digest is retained, so a database read cannot be replayed as a key.
alter table public.principals
  add column if not exists api_key_hash text unique,
  add column if not exists role text not null default 'member'
    check (role in ('member', 'security_viewer', 'security_analyst', 'security_admin'));

-- The uploaded text and the change summary make a policy version portable:
-- every instance can recover the active configuration without the original
-- local file.  They are readable through the existing security-team RLS only.
alter table public.policy_versions
  add column if not exists catalog_toml text,
  add column if not exists diff_summary text,
  add column if not exists uploaded_by uuid references public.principals(id) on delete set null;

-- Risk history is intentionally metadata-only.  It links repeated attempts
-- without making the security database another copy of sensitive prompts.
create table if not exists public.attack_history (
  id bigserial primary key,
  principal_id uuid references public.principals(id) on delete set null,
  trace_id uuid not null,
  control_id text not null,
  action verdict not null,
  risk_score real not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists attack_history_principal_created_idx
  on public.attack_history(principal_id, created_at desc);

alter table public.attack_history enable row level security;
create policy "security team reads attack history" on public.attack_history
  for select to authenticated using (public.is_team_member());
grant select on public.attack_history to authenticated;
