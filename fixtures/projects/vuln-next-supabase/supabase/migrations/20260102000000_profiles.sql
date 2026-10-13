create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text,
  credits integer not null default 10,
  plan text not null default 'free'
);
alter table public.profiles enable row level security;

create policy "Users can read own profile" on public.profiles
  for select using ((select auth.uid()) = id);

-- The sneaky failure: owners can update their whole row, including credits and plan.
create policy "Users can update own profile" on public.profiles
  for update using ((select auth.uid()) = id);
