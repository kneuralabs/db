# Securing the employee & vendor registry — rollout runbook

## Why

The site is a static page that ships a Supabase **publishable** key. The registry
tables (`kn_employees`, `kn_vendors`) have RLS policies that grant **ALL** to the
`anon` role with `USING(true)`. Net effect: **anyone on the internet can read,
edit, and delete every employee and vendor record** — salaries, blood group,
government-ID numbers, addresses, phones — by replaying that key against the REST
API. The client-side `admin` check only controls what the UI *renders*, not what
the database *allows*.

This change closes that hole by requiring an authenticated, role-scoped session
for all registry access.

## End state

| Caller | kn_employees | kn_vendors |
| --- | --- | --- |
| `anon` (no login) | no access | no access |
| JWT `app_role=admin` | full read/write | full read/write |
| JWT `app_role=employee` | read **own** row only | none |

## The three pieces (and the order they must land)

This must be coordinated because the database lockdown and the login change depend
on each other. Do them in this order:

### 1. Front-end (this PR) — safe to merge anytime, no behaviour change
`index.html` now:
- forwards a Supabase JWT to Supabase when the SSO provides one
  (`Authorization: Bearer <jwt>`), and **falls back to the publishable key when it
  doesn't** — so merging this alone changes nothing for today's users;
- understands a JWT `?kn-auth=` token in addition to the legacy base64-JSON token
  (`parseAuth`), reading the role from the `app_role` claim.

Until steps 2 and 3 happen, the app behaves exactly as before.

### 2. SSO (`sso.kneuralabs.com`) — the one change outside this repo
Mint a **Supabase-signed JWT** instead of (or in addition to) the legacy token and
pass it as `?kn-auth=`. Requirements:

- **Signature:** HS256, signed with **this project's JWT secret**
  (Supabase Dashboard → Project Settings → API → JWT Secret). This is what lets
  Supabase trust the token.
- **Claims:**
  ```jsonc
  {
    "role": "authenticated",        // required by PostgREST
    "app_role": "admin",            // or "employee"
    "emp_id": "KN-2026-001",        // required when app_role = "employee"
    "sub": "KN-2026-001",           // stable subject id
    "aud": "authenticated",
    "exp": 1750000000               // short-lived; e.g. now + 1h
  }
  ```
- Keep redirecting back to the app with the token in `?kn-auth=`; the app already
  strips it from the URL after reading it.

### 3. Database — apply the migration (locks it down)
Once step 2 is live and verified, apply:

```
supabase/migrations/20260616000000_secure_registry_rls.sql
```

After this, `anon` can no longer touch the registry; only valid admin/employee
JWTs work. **Do not apply before step 2** or the live app will be locked out.

Rollback if needed:
```
supabase/migrations/20260616000000_secure_registry_rls_rollback.sql
```

## Verifying

- **Before step 3, with an admin JWT:** the registry loads and saves normally.
- **After step 3, as anon** (publishable key only) — should return zero rows / be
  denied:
  ```
  curl "$SB_URL/rest/v1/kn_employees?select=data" -H "apikey: $SB_KEY"
  ```
- **After step 3, employee JWT:** can read only their own row; cannot list others.

## Follow-ups (not in this PR)

- `kn_app_access` is also `anon`-writable (admin-grant table); if it gates admin
  rights this is a privilege-escalation path. It is left untouched here because it
  appears to belong to the SSO/admin tooling — secure it in that system's own
  change so nothing breaks unseen.
- Several `kn_admin_*` / `kn_*_password` RPCs are `anon`-callable; that is the
  existing credential-checked pattern and is fine to keep, but review whether each
  should be `SECURITY INVOKER` or have `EXECUTE` revoked.
- Move base64 employee photos out of the row JSON into Storage; switch `sbSync`
  from full-table rewrite to per-record `PATCH`/`DELETE`.
