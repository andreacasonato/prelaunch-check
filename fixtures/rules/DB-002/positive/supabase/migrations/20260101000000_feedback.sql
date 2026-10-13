create table feedback (id serial primary key, message text);
alter table feedback enable row level security;

create policy "Anyone can send feedback" on feedback for insert with check (true);
create policy "Anyone can edit" on feedback for all using ( TRUE );
