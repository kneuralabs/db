-- ============================================================================
-- ROLLBACK for 20260616000000_secure_registry_rls.sql
-- Restores the previous (permissive) policies so the live app works with the
-- publishable key again. Use only if the secured rollout must be reverted.
-- ============================================================================

begin;

-- ── kn_employees ────────────────────────────────────────────────────────────
drop policy if exists kn_employees_admin_all  on public.kn_employees;
drop policy if exists kn_employees_self_read   on public.kn_employees;
grant all on public.kn_employees to anon;
create policy kn_employees_all on public.kn_employees
  for all to anon, authenticated
  using (true) with check (true);

-- ── kn_vendors ──────────────────────────────────────────────────────────────
drop policy if exists kn_vendors_admin_all on public.kn_vendors;
grant all on public.kn_vendors to anon;
create policy kn_vendors_all on public.kn_vendors
  for all to anon, authenticated
  using (true) with check (true);

commit;
