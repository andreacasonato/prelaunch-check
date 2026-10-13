create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);
alter table public.notes enable row level security;

-- Not exposed through the API
create table private.audit_log (id bigint, event text);

create table public.scratch (id int);
drop table public.scratch;
