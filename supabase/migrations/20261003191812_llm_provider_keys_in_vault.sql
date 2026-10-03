-- Move LLM API keys out of the table into Supabase Vault (authenticated encryption, key
-- managed outside the database tables). The table keeps only a reference, a last-4 hint and a
-- SHA-256 fingerprint. A one-way hash can't be used for the key itself: the server has to send
-- the original to the provider. Only the service role can decrypt.

alter table public.llm_providers
  add column api_key_secret_id uuid,
  add column api_key_fingerprint text;

-- carry over any keys stored in plain text so far
do $$
declare
  row record;
begin
  for row in select id, api_key from public.llm_providers where api_key is not null loop
    update public.llm_providers
    set api_key_secret_id = vault.create_secret(row.api_key, 'llm_provider_' || row.id, 'API key for a console LLM connection'),
        api_key_hint = case when length(row.api_key) >= 12 then '…' || right(row.api_key, 4) else '••••' end,
        api_key_fingerprint = left(encode(extensions.digest(row.api_key, 'sha256'), 'hex'), 16)
    where id = row.id;
  end loop;
end $$;

alter table public.llm_providers drop column api_key;

-- the hint and fingerprint are derived from the key, so only the function below sets them
revoke insert (api_key_hint), update (api_key_hint) on public.llm_providers from authenticated;
grant select (api_key_fingerprint) on public.llm_providers to authenticated;

-- admins set or rotate a connection's key; it goes straight into Vault
create function public.set_llm_provider_key(provider_id uuid, new_key text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  secret_id uuid;
  trimmed text := trim(coalesce(new_key, ''));
begin
  if not public.is_admin() then
    raise exception 'only admins can set API keys';
  end if;
  if trimmed = '' then
    raise exception 'API key is empty';
  end if;

  select api_key_secret_id into secret_id
  from public.llm_providers where id = provider_id
  for update;
  if not found then
    raise exception 'connection not found';
  end if;

  if secret_id is null then
    secret_id := vault.create_secret(trimmed, 'llm_provider_' || provider_id, 'API key for a console LLM connection');
  else
    perform vault.update_secret(secret_id, trimmed);
  end if;

  update public.llm_providers
  set api_key_secret_id = secret_id,
      api_key_hint = case when length(trimmed) >= 12 then '…' || right(trimmed, 4) else '••••' end,
      api_key_fingerprint = left(encode(extensions.digest(trimmed, 'sha256'), 'hex'), 16)
  where id = provider_id;
end $$;

revoke execute on function public.set_llm_provider_key(uuid, text) from public, anon;
grant execute on function public.set_llm_provider_key(uuid, text) to authenticated;

-- decrypt for an outgoing provider call: server (service role) only
create function public.llm_provider_key(provider_id uuid)
returns text
language sql stable security definer set search_path = '' as $$
  select s.decrypted_secret
  from public.llm_providers p
  join vault.decrypted_secrets s on s.id = p.api_key_secret_id
  where p.id = provider_id
$$;

revoke execute on function public.llm_provider_key(uuid) from public, anon, authenticated;
grant execute on function public.llm_provider_key(uuid) to service_role;

-- deleting a connection deletes its secret
create function public.delete_llm_provider_secret() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if old.api_key_secret_id is not null then
    delete from vault.secrets where id = old.api_key_secret_id;
  end if;
  return old;
end $$;

create trigger llm_providers_delete_secret after delete on public.llm_providers
  for each row execute function public.delete_llm_provider_secret();
