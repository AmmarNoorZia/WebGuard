-- WebGuard auth + targets schema — run in Supabase SQL Editor. Safe to rerun.
-- Each user can only read/write their own targets and activity.
-- Scanner tables/findings will be added in later phases.

create extension if not exists pgcrypto;

create table if not exists public.targets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  url text not null check (char_length(url) <= 512),
  environment text not null default 'Local test',
  created_at timestamptz not null default now(),
  unique(user_id, url)
);

create table if not exists public.activity_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  event_type text not null,
  description text not null check (char_length(description) <= 255),
  created_at timestamptz not null default now()
);

create index if not exists targets_user_id_idx on public.targets(user_id);
create index if not exists activity_events_user_id_idx on public.activity_events(user_id);

alter table public.targets enable row level security;
alter table public.activity_events enable row level security;

-- Restrict grants to authenticated users. Anonymous visitors cannot access these tables.
revoke all on public.targets from anon;
revoke all on public.activity_events from anon;
grant select, insert, update, delete on public.targets to authenticated;
grant select, insert, update, delete on public.activity_events to authenticated;

drop policy if exists "targets_select_own" on public.targets;
create policy "targets_select_own" on public.targets
  for select to authenticated using ((select auth.uid()) = user_id);
drop policy if exists "targets_insert_own" on public.targets;
create policy "targets_insert_own" on public.targets
  for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "targets_update_own" on public.targets;
create policy "targets_update_own" on public.targets
  for update to authenticated using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
drop policy if exists "targets_delete_own" on public.targets;
create policy "targets_delete_own" on public.targets
  for delete to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "activity_select_own" on public.activity_events;
create policy "activity_select_own" on public.activity_events
  for select to authenticated using ((select auth.uid()) = user_id);
drop policy if exists "activity_insert_own" on public.activity_events;
create policy "activity_insert_own" on public.activity_events
  for insert to authenticated with check ((select auth.uid()) = user_id);
-- activity_events intentionally has NO update/delete policy.
