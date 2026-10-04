-- Resources through MCP (docs/superpowers/specs/2026-10-04-resources-mcp-design.md).
--
-- 1. Least privilege: the gateway reaches the protected data over its main
--    connection and switches to `resources_reader` (`set local role`) inside
--    every query transaction. That role can read schema `resources` and
--    nothing else.
-- 2. A small-SaaS business dataset in `resources`, generated from a fixed
--    seed so every environment holds identical rows.
-- 3. Per-end-user access grants (tools and tables) and results.
-- 4. Tool steps stored with console chat messages.

-- ---------------------------------------------------------------- reader role

do $$
begin
  if not exists (select from pg_roles where rolname = 'resources_reader') then
    create role resources_reader nologin;
  end if;
end
$$;

grant usage on schema resources to resources_reader;
alter default privileges in schema resources grant select on tables to resources_reader;
-- The gateway logs in as `postgres` (DATABASE_URL); `set role` needs membership.
grant resources_reader to postgres;

-- ---------------------------------------------------------------- tables

create table resources.products (
  id        bigint generated always as identity primary key,
  name      text not null unique,
  tier      text not null check (tier in ('starter', 'team', 'enterprise')),
  price_usd numeric(10, 2) not null
);

create table resources.subscriptions (
  id           bigint generated always as identity primary key,
  customer_id  bigint not null references resources.customers (id) on delete cascade,
  product_id   bigint not null references resources.products (id),
  status       text not null check (status in ('active', 'cancelled', 'trial')),
  started_at   timestamptz not null,
  cancelled_at timestamptz,
  constraint subscriptions_cancelled_has_date check (status <> 'cancelled' or cancelled_at is not null)
);

create table resources.support_tickets (
  id          bigint generated always as identity primary key,
  customer_id bigint not null references resources.customers (id) on delete cascade,
  subject     text not null,
  priority    text not null check (priority in ('low', 'medium', 'high', 'urgent')),
  status      text not null check (status in ('open', 'pending', 'closed')),
  opened_at   timestamptz not null,
  closed_at   timestamptz
);

create index subscriptions_customer_idx on resources.subscriptions (customer_id);
create index subscriptions_product_idx on resources.subscriptions (product_id);
create index support_tickets_customer_idx on resources.support_tickets (customer_id);
create index invoices_customer_idx on resources.invoices (customer_id);

-- Tables created before the default privileges above need the grant spelled out.
grant select on all tables in schema resources to resources_reader;

-- RLS everywhere, one read policy for the reader. anon and authenticated keep
-- no access at all, and the Data API does not expose the schema.
alter table resources.customers       enable row level security;
alter table resources.invoices        enable row level security;
alter table resources.products        enable row level security;
alter table resources.subscriptions   enable row level security;
alter table resources.support_tickets enable row level security;

create policy "resources reader" on resources.customers       for select to resources_reader using (true);
create policy "resources reader" on resources.invoices        for select to resources_reader using (true);
create policy "resources reader" on resources.products        for select to resources_reader using (true);
create policy "resources reader" on resources.subscriptions   for select to resources_reader using (true);
create policy "resources reader" on resources.support_tickets for select to resources_reader using (true);

-- ---------------------------------------------------------------- data

-- Replaces the five hand-written rows the old seed loaded. Dates hang off a
-- fixed day, not now(), so a re-applied migration produces the same rows.
truncate resources.invoices, resources.customers restart identity cascade;

select setseed(0.42);

insert into resources.products (name, tier, price_usd)
values
  ('Starter monthly',     'starter',      49.00),
  ('Starter yearly',      'starter',     490.00),
  ('Team monthly',        'team',        290.00),
  ('Team yearly',         'team',       2900.00),
  ('Enterprise monthly',  'enterprise', 1900.00),
  ('Enterprise yearly',   'enterprise',19000.00),
  ('Audit log add-on',    'team',        120.00),
  ('Premium support',     'enterprise',  800.00);

with names as (
  select
    array['Anna', 'Jan', 'Maria', 'Tom', 'Ola', 'Piotr', 'Lena', 'Lukas', 'Emma', 'Noah',
          'Chloe', 'Louis', 'Olivia', 'James', 'Sofia', 'Marek', 'Hanna', 'Felix', 'Camille', 'Jack'] as first,
    array['Nowak', 'Kowalski', 'Garcia', 'Fischer', 'Wisniewska', 'Muller', 'Schmidt', 'Martin', 'Bernard', 'Smith',
          'Jones', 'Taylor', 'Brown', 'Dubois', 'Lefebvre', 'Wojcik', 'Becker', 'Johnson', 'Williams', 'Kaminska'] as last,
    array['PL', 'DE', 'US', 'UK', 'FR'] as country,
    array['+48', '+49', '+1', '+44', '+33'] as dial,
    array['starter', 'team', 'enterprise'] as plan
),
picks as (
  select
    n,
    1 + floor(random() * 20)::int as f,
    1 + floor(random() * 20)::int as l,
    1 + floor(random() * 5)::int as c,
    1 + floor(random() * 3)::int as p,
    random() as r
  from generate_series(1, 300) as n
)
insert into resources.customers (full_name, email, phone, country, plan, mrr_usd, created_at)
select
  names.first[f] || ' ' || names.last[l],
  lower(names.first[f] || '.' || names.last[l] || n || '@example.com'),
  names.dial[c] || ' ' || (500 + floor(r * 400))::int || ' ' || lpad((n * 37 % 1000)::text, 3, '0')
    || ' ' || lpad((n * 91 % 1000)::text, 3, '0'),
  names.country[c],
  names.plan[p],
  round((case p when 1 then 49 when 2 then 290 + r * 900 else 1900 + r * 4000 end)::numeric, 2),
  timestamptz '2025-01-01' + (n * interval '1 day')
from picks, names;

insert into resources.subscriptions (customer_id, product_id, status, started_at, cancelled_at)
select customer_id, product_id, status, started_at,
       case when status = 'cancelled' then started_at + interval '1 day' * (30 + floor(r * 200)) end
from (
  select
    1 + (n - 1) % 300 as customer_id,
    1 + floor(random() * 8)::int as product_id,
    (array['active', 'active', 'active', 'cancelled', 'trial'])[1 + floor(random() * 5)::int] as status,
    timestamptz '2025-01-15' + interval '1 day' * floor(random() * 600) as started_at,
    random() as r
  from generate_series(1, 400) as n
) s;

insert into resources.invoices (customer_id, amount_usd, status, issued_at)
select
  1 + floor(random() * 300)::int,
  round((49 + random() * 4951)::numeric, 2),
  (array['paid', 'paid', 'paid', 'paid', 'overdue', 'void'])[1 + floor(random() * 6)::int],
  timestamptz '2025-04-01' + interval '1 hour' * floor(random() * 13140)
from generate_series(1, 1200);

insert into resources.support_tickets (customer_id, subject, priority, status, opened_at, closed_at)
select customer_id, subject, priority, status, opened_at,
       case when status = 'closed' then opened_at + interval '1 hour' * (1 + floor(r * 120)) end
from (
  select
    1 + floor(random() * 300)::int as customer_id,
    (array['Cannot log in', 'Invoice looks wrong', 'Export to CSV fails', 'SSO setup help',
           'Slow dashboard', 'Request a refund', 'API rate limit questions', 'Add a team member'])
      [1 + floor(random() * 8)::int] as subject,
    (array['low', 'medium', 'medium', 'high', 'urgent'])[1 + floor(random() * 5)::int] as priority,
    (array['open', 'pending', 'closed', 'closed'])[1 + floor(random() * 4)::int] as status,
    timestamptz '2025-06-01' + interval '1 hour' * floor(random() * 11000) as opened_at,
    random() as r
  from generate_series(1, 250)
) t;

-- ---------------------------------------------------------------- grants per end user

-- A request is for exactly one tool or one table (`resource`), and for one end
-- user: a delegating principal's grant covers only the person it was asked for.
alter table public.access_requests alter column tool drop not null;
alter table public.access_requests
  add column resource text,
  add column end_user text;
update public.access_requests a set end_user = p.slug
from public.principals p where p.id = a.principal_id;
alter table public.access_requests alter column end_user set not null;
alter table public.access_requests
  add constraint access_requests_one_target check (num_nonnulls(tool, resource) = 1);

drop index if exists public.access_requests_grants_idx;
create index access_requests_grants_idx on public.access_requests (principal_id, end_user)
  where status = 'approved';

-- Rows go back only to the end user who asked.
delete from public.resource_results where expires_at <= now();
alter table public.resource_results add column end_user text;
update public.resource_results r set end_user = p.slug
from public.principals p where p.id = r.principal_id;
alter table public.resource_results alter column end_user set not null;

-- ---------------------------------------------------------------- console chat

-- The tool steps of an assistant reply (calls, SQL, the redacted rows the
-- gateway delivered). Covered by the existing chat_messages RLS.
alter table public.chat_messages add column tool_calls jsonb;

-- Console chat may use the resource tools; which tables is the catalog's call.
update public.principals
set allowed_tools = (
  select array_agg(distinct tool order by tool)
  from unnest(allowed_tools || array['resources__describe', 'resources__query']) as tool
)
where slug = 'console-chat';
