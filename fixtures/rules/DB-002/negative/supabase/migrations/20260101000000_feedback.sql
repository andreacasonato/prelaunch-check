create table feedback (id serial primary key, user_id uuid, message text);
alter table feedback enable row level security;

create policy "Public read" on feedback for select using (true);
create policy "Owners insert" on feedback for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Server writes" on feedback for all to service_role using (true);
