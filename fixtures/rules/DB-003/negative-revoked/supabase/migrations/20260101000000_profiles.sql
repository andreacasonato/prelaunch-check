create table public.profiles (
  id uuid primary key references auth.users,
  display_name text,
  credits integer default 10,
  role text default 'user'
);
alter table public.profiles enable row level security;
create policy "Users can update own profile" on public.profiles
  for update using ((select auth.uid()) = id);

revoke update on public.profiles from authenticated, anon;
grant update (display_name) on public.profiles to authenticated;
