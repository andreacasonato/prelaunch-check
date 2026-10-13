create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text
);
alter table public.profiles enable row level security;

create policy "Users can update own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) is not null and (select auth.uid()) = id);

-- Money lives in its own table: users can read it, only the server writes it.
create table public.billing (
  user_id uuid primary key references auth.users on delete cascade,
  credits integer not null default 10,
  plan text not null default 'free'
);
alter table public.billing enable row level security;

create policy "Users can read own billing" on public.billing
  for select to authenticated
  using ((select auth.uid()) is not null and (select auth.uid()) = user_id);
