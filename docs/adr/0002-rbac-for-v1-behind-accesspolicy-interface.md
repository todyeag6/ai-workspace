# ADR-0002: RBAC for v1, behind an `AccessPolicy` interface

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** Aiwebscapes owner (sign-off given during Phase 1 execution)
- **Related:** [ADR-0001 Modular Monolith](0001-modular-monolith.md),
  [Threat Model v0.1](../THREAT_MODEL.md), Platform FRD FR-TEN-003,
  Plan §7 Open Question 2, Plan Task P1-T4

---

## 1. Context

Plan §7 lists this as an **open question that must be resolved before P1-T4**
(the authorization middleware), because every later Phase 1 requirement inherits
AC-001 through that middleware:

> **RBAC vs ABAC for v1** (FR-TEN-003) — plan recommends **RBAC for MVP**, ABAC
> later. **Needs owner sign-off.** (P1-T4 builds authz — pick before that.)

The two candidate models differ in *what* the permission decision is a function of:

- **RBAC** — permission is a property of the **role** the subject holds.
  `staff` may `lead.read`. One join over `user_roles` → `roles` → `permissions`,
  and a boolean. The P1-T1 schema (`roles`, `permissions(code)`, `user_roles`)
  already models exactly this.
- **ABAC** — permission is computed by a **policy over attributes** of subject,
  object, and context: "may read this lead if same tenant AND (owns it OR is a
  manager in its region) AND is cleared for its data classification". Requires a
  policy engine, policy storage, policy versioning, and a combinatorially larger
  test matrix.

**The decisive observation:** tenant isolation — the thing AC-001 actually
demands — is **neither** RBAC nor ABAC. It is a hard structural invariant
enforced in `src/Data/TenantRepository.php` (P1-T3): every `SELECT/UPDATE/DELETE`
appends `tenant_id = :tenant`, bound internally so callers cannot override it.
That protection is **identical under both models**. The RBAC/ABAC choice governs
only the *verb* check layered on top of an already tenant-safe query.

---

## 2. Decision

Ship **RBAC in Phase 1**, but route every authorization decision through a
narrow interface so the model can be replaced without touching call sites:

```php
interface AccessPolicy
{
    public function permits(Subject $subject, string $action, ?object $object = null): bool;
}
```

- `RbacPolicy implements AccessPolicy` is the Phase 1 implementation: role →
  permission code lookup, deny-by-default.
- `TenantAuthMiddleware` (P1-T4) depends on the **interface**, never on
  `RbacPolicy` directly.
- The `?object $object` parameter exists from day one specifically so an
  object/attribute-aware implementation can be introduced later **without
  changing the interface** — the hard part of a retrofit.
- Tenant scoping is **not** delegated to the policy. It stays structural in
  `TenantRepository`, so a policy bug cannot become a cross-tenant data leak.

---

## 3. Consequences

### Good

- **Does not delay the linchpin.** Plan directive: *"Tenancy first. Do not build
  features before P1-T4 passes."* RBAC gets P1-T4 done and proven; ABAC
  machinery would spend Phase 1 budget on a policy engine instead of AC-001.
- **Better production readiness than ABAC *right now*.** An under-tested policy
  engine is a worse security posture than a well-tested role check. Small,
  fully-exercised decision surface beats a large, partly-exercised one.
- **The decision is reversible** — which is the real production-readiness
  property. Swapping `RbacPolicy` for `AbacPolicy` touches one binding, not the
  middleware, routes, repositories, or tests.
- **Test matrix stays tractable:** the AC-001 negative matrix is
  role × permission × tenant, all enumerable in `TenantAuthMiddlewareTest`.

### Bad / risks (and how we contain them)

- **No per-row rules in v1.** RBAC cannot express "a rep sees only their own
  leads." *Containment:* the `?object` parameter is in the interface from the
  start, and the owner confirmed no per-row requirement for the first tenant in
  Phase 1. If one appears, it is an `AbacPolicy` implementation — not a rewrite.
- **Interface drift:** developers could bypass `AccessPolicy` and inline role
  checks. *Containment:* code review (SEC-008), and the same PHPStan-rule
  approach used in P1-T3 to forbid unscoped queries.
- **An interface is not a free option.** It costs ~10 lines now; retrofitting
  object-level attributes into a role-only policy mid-phase costs far more.
  This is a deliberate, priced bet on reversibility.

### Revisit when

- The first tenant requires row-level or data-classification-conditional access
  (likely alongside LFR-AI-002 redaction / FR-DATA-002 data classes), **or**
- Phase 2 productization introduces cross-tenant delegated administration.

---

## 4. References

- Platform FRD: FR-TEN-002 (tenant scoping), FR-TEN-003 (access model),
  FR-IDENT-001/003/004, SEC-005 (authorization), SEC-008 (review/static analysis).
- Plan: §7 Open Question 2; Task P1-T3 (`TenantRepository`, AC-001);
  Task P1-T4 (`TenantAuthMiddleware`, deny-by-default, 403 for both "wrong
  tenant" and "not found" so IDs cannot be enumerated).
- Repo: `src/Data/TenantRepository.php`, `src/Security/TenantAuthMiddleware.php`,
  `src/Security/AccessPolicy.php`, `src/Security/RbacPolicy.php`.
