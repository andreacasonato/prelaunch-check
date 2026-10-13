create table notes (id serial primary key, user_id uuid, body text);
alter table notes enable row level security;
create policy "Own notes" on notes for select using (auth.uid() = user_id);
