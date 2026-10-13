-- Notes: RLS was never turned on.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);
