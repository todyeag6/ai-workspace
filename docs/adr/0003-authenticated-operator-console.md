# ADR-0003: An authenticated operator console for the agent registry

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Aiwebscapes owner (MFA deferral approved during execution)
- **Related:** [ADR-0001 Modular Monolith](0001-modular-monolith.md),
  [ADR-0002 RBAC behind AccessPolicy](0002-rbac-for-v1-behind-accesspolicy-interface.md),
  [Threat Model](../THREAT_MODEL.md), Platform FRD FR-AGENT-001/002/003,
  FR-IDENT-001/002/003/004, SEC-005, AC-001/002/003,
  Plan `.hermes/plans/2026-10-14_101432-agent-console-authenticated.md`

---

## 1. Context

The platform had a complete agent substrate — `src/Agents` (registry, immutable
versions, eval-gated activation), `src/Manager` (decomposition, dispatch, review
loop), `src/AI` (gateway, adapters, schema validation), `src/Tools` (allowlist) —
and **no way for a human to reach any of it**. The only HTTP-served surface was
`public/index.php` → `/dashboard`, a demo page whose own docblock said it was
"NOT the production entrypoint and is not wired into any auth flow."

So the agents were built, tested, and unreachable. This ADR records how the front
door was added and, more importantly, what was deliberately *not* added.

---

## 2. Decision

### 2.1 Shape: a thin front controller, not a framework

`public/index.php` routes to array-in/array-out controllers. No Slim, no Twig, no
kernel — consistent with ADR-0001 and the P1-T15 deviation
(`docs/SESSION_HANDOFF_P1T14.md`). Every controller remains directly testable, and
presentation lives in `App\Console\AgentConsoleView`, a pure string builder with a
single escape sink, so the accessibility and escaping guarantees are unit-testable
without a database.

### 2.2 Authentication: reuse, do not rebuild

Login is wired to the **existing** `AuthService` + Redis `SessionStore`
(FR-IDENT-003) and authorization to the **existing** `TenantAuthMiddleware` +
`RbacPolicy`. No second auth stack. The middleware runs **before** any controller
is constructed, so an unauthorised request never reaches code that reads tenant
data.

Two capability codes were added (`migrations/024_agent_console_permissions.sql`):
`agent.console.view` (see the registry) and `agent.invoke` (run an agent). They are
separate so that `staff` can look without being able to spend tokens or trigger
tool egress — deny-by-default only means something when the capabilities are
fine-grained enough to withhold something.

### 2.3 Tenant identity comes from the session, never the request

The console's tenant is read from the server-side session record, which only the
server can write. The existing `?tenant=` refusal is preserved. The session id is
read from the **cookie only** — never a query parameter or header (NIST SP
800-63B-4 §5.1.1; OWASP Session Management Cheat Sheet).

### 2.4 MFA is deferred — with an explicit reversal condition

**Decision: ship single-factor login now; the TOTP challenge is card `t_e2a46492`,
blocked.**

The platform is MFA-*ready* but MFA is not *enforced*: `users.mfa_secret` exists,
`Subject::mfaEnrolled()` is carried, and `AuthService` reads it at login, but
nothing challenges a second factor. Shipping "MFA" therefore means building a TOTP
flow, not switching one on.

The reasoning: the console was unreachable, and a TOTP challenge is a second
complete flow (secret provisioning, QR/OTP URI, recovery codes hashed at rest,
clock-drift handling, replay prevention) that would delay the thing actually asked
for. The risk is contained because **the console is not internet-exposed in this
scope** — see §2.5.

**Reversal condition: expose this console beyond the LAN, or the owner asks for
MFA.** When either happens, the TOTP work in card `t_e2a46492` becomes a
prerequisite, and NIST SP 800-63B-4's AAL2 requirements apply — including
**replay resistance, which is REQUIRED at AAL2** and is the requirement most TOTP
implementations miss.

Stated honestly: **OTP is not phishing-resistant.** NIST SP 800-63B-4 says manual
entry of an authenticator output "does not bind the authenticator output to the
specific session being authenticated", so TOTP is a real improvement over a
password alone but is not phishing-resistant 2FA. A future reader should not
treat card `t_e2a46492` as delivering phishing resistance.

### 2.5 The deploy story is explicitly out of scope

The repository has no Apache/nginx configuration and its README describes the
platform as "a backend you prove with tests." This ADR adds a browser-reachable
surface **against the app**; it does not make that surface internet-safe. Doing so
requires a TLS terminator, HSTS, the cookie `Secure` flag actually in force
(it is set only when the request arrives over HTTPS — correct, but it means
plain-HTTP deployment silently downgrades the control), and a decision about the
surface in §3.1 below.

---

## 3. Consequences

### 3.1 `/dashboard` is NOT gated — a recorded finding, not an oversight

`/dashboard` serves lead-pipeline counts **without any session**. It predates this
work, is not wired into an auth flow by its own admission, and
`tests/Bootstrap/ServedPageTest.php` asserts it unauthenticated. Gating it would
be scope expansion beyond "make the agents reachable" **and** would break shipped
tests, so it was left exactly as it was.

This is a real finding and is recorded rather than silently changed. **Anyone
deploying this beyond localhost must decide that surface's fate deliberately.**

### 3.2 Good

- The agent registry, invocation path and audit trail are reachable by a
  signed-in operator, which was the point.
- No new auth stack: the console inherits lockout (FR-IDENT-004), argon2id with
  rehash-on-login (FR-IDENT-002), generic failure messages (no account
  enumeration), server-side revocable sessions (FR-IDENT-003), CSRF on every state
  change, deny-by-default RBAC, and audit on success **and** denial.
- Four distinct refusal reasons (`authz.no_session`, `authz.csrf`,
  `authz.forbidden`, `authz.object_unavailable`) tell an operator what to *do*,
  while "wrong id" and "someone else's id" stay one answer so agent ids cannot be
  enumerated across tenants (AC-001).
- Accessibility is a property of the code, not a review habit: WCAG 2.2 AA
  assertions and a measured contrast check run in the suite, and the CSP stays at
  `style-src 'self'` because no view emits inline style or script.

### 3.3 Bad / risks, and how they are contained

- **A credential-accepting endpoint is new attack surface.** It is the platform's
  first. Contained by reusing the audited auth path rather than writing one, and
  by the tests asserting the negative paths (no session, bad CSRF, no permission,
  cross-tenant id) individually rather than one generic 403.
- **A latent defect was found and fixed in passing:** `SchemaValidator` rejected
  the `array` schema type that `TaskDecomposer` and `ReviewLoop` both declare, so
  `ManagerOrchestrator::manage()` had **never been able to run** — `AIRequest`
  threw at construction on every call. It survived because nothing exercised the
  path end to end. The first invocation did. `array` now means a JSON list
  (`array_is_list`), and `SchemaValidatorTest.php` exists where it previously did
  not.
- **Invocation is synchronous.** `ManagerOrchestrator::manage()` calls the model
  in the request; a browser request can block for the model's timeout. Acceptable
  for an operator tool; a queue is the answer if it ever is not.
- **Test isolation needed two deviations.** Served-surface and provisioning tests
  exercise a **subprocess** (`php -S`, a CLI script) that cannot see rows inside
  the base class's rolled-back transaction, so those fixtures are committed on a
  second connection and removed by id — including the `audit_log` rows the served
  process writes, which otherwise inflate every later test that counts audit rows.

### 3.4 Revisit when

- The console is exposed beyond the LAN → §2.4's MFA prerequisite applies.
- Multi-tenant operation begins → the `agent.*` grants in migration 024 are
  seeded for tenant 1 only and must be seeded per tenant.
- The `/dashboard` surface is deployed anywhere reachable → §3.1 must be decided.

---

## 4. References

- Platform FRD: FR-AGENT-001/002/003, FR-IDENT-001/002/003/004, FR-AUD-001,
  SEC-004, SEC-005, SEC-009, SEC-010, AC-001/002/003.
- **NIST SP 800-63B-4** (final, July 2025) — the current revision; supersedes
  SP 800-63B. https://pages.nist.gov/800-63-4/sp800-63b.html ·
  authenticators https://pages.nist.gov/800-63-4/sp800-63b/authenticators/ ·
  sessions https://pages.nist.gov/800-63-4/sp800-63b/session/
- **OWASP** Authentication, Session Management and CSRF Prevention Cheat Sheets —
  https://cheatsheetseries.owasp.org/
- **WCAG 2.2** (W3C Recommendation) — https://www.w3.org/TR/WCAG22/ (SC 3.3.8
  Accessible Authentication is new in 2.2 and constrains the login form.)
- Repo: `public/index.php`, `src/Console/*`, `src/Identity/LoginController.php`,
  `src/Agents/AgentResourceLocator.php`, `migrations/024_agent_console_permissions.sql`,
  `scripts/create-operator.php`.
