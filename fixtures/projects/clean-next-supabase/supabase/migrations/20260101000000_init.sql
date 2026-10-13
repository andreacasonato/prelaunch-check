create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);
alter table public.notes enable row level security;

create policy "Users manage own notes" on public.notes
  for all to authenticated
  using ((select auth.uid()) is not null and (select auth.uid()) = user_id)
  with check ((select auth.uid()) is not null and (select auth.uid()) = user_id);
