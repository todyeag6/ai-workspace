<?php

declare(strict_types=1);

namespace App\Security;

/**
 * The authorisation question, asked in one place and one shape.
 *
 * ADR-0002 (ACCEPTED): callers depend on THIS interface, never on a concrete
 * policy. The reason is not abstraction for its own sake - it is that the
 * authorisation model will change (RBAC today, ABAC or policy-per-resource
 * later) and every call site that named RbacPolicy directly would have to
 * change with it. App\Security\TenantAuthMiddleware therefore type-hints
 * AccessPolicy, and swapping the implementation is a container edit.
 *
 * CONTRACT: implementations are DENY BY DEFAULT. permits() returns true only
 * when a grant positively says so - an unknown action, a subject with no
 * roles, a missing object and any error condition all answer false. There is
 * no "allow unless denied" mode, because a fail-open authorisation layer is
 * indistinguishable from no authorisation layer during an outage.
 *
 * $object is optional because some actions are object-free (e.g. 'user.view'
 * as a listing). When it IS supplied and it is TenantOwned, an implementation
 * must refuse a tenant mismatch (AC-001) regardless of the permission held.
 *
 * © AI WebScapes 2026
 */
interface AccessPolicy
{
    public function permits(Subject $subject, string $action, ?object $object = null): bool;
}
