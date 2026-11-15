-- Additive migration. Apply AFTER schema.sql in the Supabase SQL Editor.
-- No service-role key; all API calls and this function use the caller's JWT/RLS.
begin;

create table if not exists public.scan_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  target_id uuid references public.targets(id) on delete set null,
  target_snapshot jsonb not null,
  module text not null,
  status text not null check (status in ('completed', 'inconclusive')),
  started_at timestamptz not null,
  completed_at timestamptz not null,
  result jsonb not null,
  created_at timestamptz not null default now()
);

-- Includes negative/inconclusive observations, explicitly labeled by detection_status.
create table if not exists public.security_findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scan_runs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  target_id uuid references public.targets(id) on delete set null,
  module text not null,
  title text not null,
  severity text check (severity in ('critical', 'high', 'medium', 'low')),
  affected_url text not null,
  detection_status text not null check (detection_status in ('confirmed', 'not_detected', 'inconclusive')),
  evidence jsonb not null,
  remediation text not null,
  created_at timestamptz not null default now(),
  unique (scan_id, module)
);

create index if not exists scan_runs_user_date_idx on public.scan_runs(user_id, created_at desc);
create index if not exists security_findings_user_date_idx on public.security_findings(user_id, created_at desc);
alter table public.scan_runs enable row level security;
alter table public.security_findings enable row level security;
revoke all on public.scan_runs, public.security_findings from anon;
grant select, insert on public.scan_runs, public.security_findings to authenticated;

drop policy if exists scan_runs_select_own on public.scan_runs;
create policy scan_runs_select_own on public.scan_runs for select to authenticated
  using ((select auth.uid()) = user_id);
drop policy if exists scan_runs_insert_own on public.scan_runs;
create policy scan_runs_insert_own on public.scan_runs for insert to authenticated
  with check ((select auth.uid()) = user_id and exists (
    select 1 from public.targets t where t.id = target_id and t.user_id = (select auth.uid())
  ));
drop policy if exists security_findings_select_own on public.security_findings;
create policy security_findings_select_own on public.security_findings for select to authenticated
  using ((select auth.uid()) = user_id);
drop policy if exists security_findings_insert_own on public.security_findings;
create policy security_findings_insert_own on public.security_findings for insert to authenticated
  with check ((select auth.uid()) = user_id and exists (
    select 1 from public.scan_runs s where s.id = scan_id and s.user_id = (select auth.uid())
      and s.target_id = security_findings.target_id
  ));

-- Both inserts commit together, avoiding orphaned runs/findings on partial failure.
create or replace function public.save_scan_run(p_target_id uuid, p_result jsonb)
returns jsonb language plpgsql security invoker set search_path = public
as $$
declare
  target public.targets%rowtype;
  saved public.scan_runs%rowtype;
begin
  select * into target from public.targets
    where id = p_target_id and user_id = auth.uid() for share;
  if not found then raise exception 'Target not available' using errcode = '42501'; end if;
  if p_result->>'status' not in ('confirmed', 'not_detected', 'inconclusive')
      or p_result->>'status' is null then
    raise exception 'Invalid detection status';
  end if;
  insert into public.scan_runs(user_id, target_id, target_snapshot, module, status, started_at, completed_at, result)
    values (auth.uid(), target.id, jsonb_build_object('id',target.id,'name',target.name,'url',target.url),
      p_result->>'module', case when p_result->>'status' = 'inconclusive' then 'inconclusive' else 'completed' end,
      (p_result->>'started_at')::timestamptz, (p_result->>'completed_at')::timestamptz, p_result)
    returning * into saved;
  insert into public.security_findings(scan_id, user_id, target_id, module, title, severity,
      affected_url, detection_status, evidence, remediation)
    values (saved.id, auth.uid(), target.id, saved.module, p_result->>'title', p_result->>'severity',
      p_result->>'affected_url', p_result->>'status', p_result->'evidence', p_result->>'remediation');
  return to_jsonb(saved);
end;
$$;
revoke all on function public.save_scan_run(uuid,jsonb) from public, anon;
grant execute on function public.save_scan_run(uuid,jsonb) to authenticated;
commit;
