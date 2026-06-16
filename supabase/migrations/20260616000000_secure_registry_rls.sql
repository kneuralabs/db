-- ============================================================================
-- Secure the employee & vendor registry with role-scoped Row Level Security.
--
-- CURRENT (insecure) STATE
--   Policies `kn_employees_all` / `kn_vendors_all` grant ALL to `anon` and
--   `authenticated` with USING(true)/WITH CHECK(true). Because the publishable
--   key ships in the public site, anyone can read, edit, or delete every record
--   (salaries, blood group, government-ID numbers, addresses, phones).
--
-- TARGET STATE
--   * `anon` has no access at all.
--   * A Supabase-signed JWT with custom claim `app_role = 'admin'` has full access.
--   * An employee JWT (`app_role = 'employee'`, `emp_id = <their KN id>`) may read
--     ONLY its own employee row.
--
-- DEPENDENCY — APPLY ONLY AFTER COORDINATION (see docs/SECURITY-ROLLOUT.md)
--   The SSO (sso.kneuralabs.com) must mint a Supabase JWT signed with this
--   project's JWT secret, with: role='authenticated', app_role ('admin'|'employee'),
--   and (for employees) emp_id = the employee's KN id. The front-end already
--   forwards that JWT to Supabase (backward-compatible; see index.html).
--   Applying this migration BEFORE those tokens exist will lock the live app out.
--
-- Reversible: see the companion ..._rollback.sql to restore the previous policies.
-- ============================================================================

begin;

-- ── kn_employees ────────────────────────────────────────────────────────────
drop policy if exists kn_employees_all on public.kn_employees;

create policy kn_employees_admin_all on public.kn_employees
  for all to authenticated
  using      ( (auth.jwt() ->> 'app_role') = 'admin' )
  with check ( (auth.jwt() ->> 'app_role') = 'admin' );

create policy kn_employees_self_read on public.kn_employees
  for select to authenticated
  using (
    (auth.jwt() ->> 'app_role') = 'employee'
    and upper(data ->> 'id') = upper(auth.jwt() ->> 'emp_id')
  );

-- ── kn_vendors ──────────────────────────────────────────────────────────────
drop policy if exists kn_vendors_all on public.kn_vendors;

create policy kn_vendors_admin_all on public.kn_vendors
  for all to authenticated
  using      ( (auth.jwt() ->> 'app_role') = 'admin' )
  with check ( (auth.jwt() ->> 'app_role') = 'admin' );

-- Belt-and-suspenders: remove the anon role's table privileges entirely so the
-- registry is unreachable via PostgREST without an authenticated session.
revoke all on public.kn_employees from anon;
revoke all on public.kn_vendors   from anon;

commit;
