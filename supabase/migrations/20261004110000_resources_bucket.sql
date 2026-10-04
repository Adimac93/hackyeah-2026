-- Resources: files the security team shares in the console (runbooks, reports,
-- evidence). A private Storage bucket — objects are served only through
-- short-lived signed URLs, never a public link.
--
-- Same split as the rest of the console: the security team (admin, analyst,
-- viewer) reads; admin and analyst (can_write) upload and delete; developers
-- see nothing. No UPDATE policy: uploads never overwrite (no upsert).

insert into storage.buckets (id, name, public, file_size_limit)
values ('resources', 'resources', false, 52428800) -- 50 MB, the project limit
on conflict (id) do nothing;

create policy "resources: team reads" on storage.objects
  for select to authenticated
  using (bucket_id = 'resources' and (select public.is_team_member()));

create policy "resources: writers upload" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'resources' and (select public.can_write()));

create policy "resources: writers delete" on storage.objects
  for delete to authenticated
  using (bucket_id = 'resources' and (select public.can_write()));
