-- Notes app
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);

create table todos (id serial primary key, title text);
alter table todos enable row level security;
alter table todos disable row level security;
