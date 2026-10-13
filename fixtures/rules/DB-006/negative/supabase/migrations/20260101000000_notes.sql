create table notes (id serial primary key, user_id uuid, body text);
alter table notes enable row level security;
create policy "Own notes" on notes for select
  using ((select auth.uid()) is not null and (select auth.uid()) = user_id);
create policy "Public read" on notes for select using (true);
