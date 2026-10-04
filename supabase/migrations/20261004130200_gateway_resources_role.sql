-- The role behind the gateway's RESOURCES_DATABASE_URL: the connection the
-- `resources__*` MCP tools query through. It can read schema `resources` and
-- nothing else, so even a query that slipped past the gateway's own SQL
-- checks could not reach the gateway's tables, auth, or anything writable.
--
-- Created without a login. Turning it on is a deploy step, out of band, so no
-- password lands in git (docs/DEPLOY.md):
--   alter role gateway_resources with login password '<generated>';
-- then put its pooler URL in Secret Manager as `gateway-resources-url`.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'gateway_resources') then
    create role gateway_resources nologin;
  end if;
end $$;

grant usage on schema resources to gateway_resources;
grant select on all tables in schema resources to gateway_resources;
alter default privileges in schema resources grant select on tables to gateway_resources;
