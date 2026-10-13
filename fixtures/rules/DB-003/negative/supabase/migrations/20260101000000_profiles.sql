-- Right: money lives in a separate table users can only read.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text,
  avatar_url text
);
alter table public.profiles enable row level security;
create policy "Users can update own profile" on public.profiles
  for update using ((select auth.uid()) = id);

create table public.billing (
  user_id uuid primary key references auth.users on delete cascade,
  credits integer not null default 10,
  plan text not null default 'free'
);
alter table public.billing enable row level security;
create policy "Users can read own billing" on public.billing
  for select using ((select auth.uid()) = user_id);
