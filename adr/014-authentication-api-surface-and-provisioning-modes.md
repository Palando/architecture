# ADR 014: Authentication API Surface and Provisioning Modes

| Status          | Proposed                                                                 |
|-----------------|--------------------------------------------------------------------------|
| Date            | 2026-09-18                                                               |
| Decision-makers | Platform Mesh TSC                                                        |
| Related         | [RFC 008](../rfc/008-platform-mesh-modularization.md), [ADR 007](007-transition-from-bitnami-keycloak-to-keycloak-operator.md), [ADR 013](013-engine-neutral-authorization-api.md) |

## Context and Problem Statement

[RFC 008](../rfc/008-platform-mesh-modularization.md) makes authentication a required capability
whose *managed, multi-tenant* form is optional, and names the interface as OIDC plus RFC 7591
Dynamic Client Registration. [ADR 007](007-transition-from-bitnami-keycloak-to-keycloak-operator.md)
decides how Keycloak is *deployed*, and notes that the transition must be optional. Neither document
defines the authentication **contract**: what Platform Mesh needs from an identity provider, and
what it guarantees in return.

The absence shows in the implementation, where exactly one topology is expressible.

**What is already abstracted.** `security-operator/pkg/clientreg` is a generic RFC 7591 Dynamic
Client Registration client (`Register` / `Read` / `Update` / `Delete`). Keycloak appears only as the
`TokenProvider` and admin adapter behind it (`pkg/clientreg/keycloak/admin.go`). The "pure OIDC"
half of the problem is therefore largely solved, and this ADR must not re-solve it.

**What is not abstracted** is precisely the half for which no standard exists — the mapping from
tenant to IdP tenancy construct:

* the issuer URL is a string template over the workspace name —
  `https://{BaseDomain}/keycloak/realms/{workspaceName}`
  (`internal/subroutine/workspace_authorization.go`);
* realm lifecycle (`ensureRealm`, `CreateOrUpdateRealm`, `DeleteRealm`) is Keycloak API surface
  invoked directly from the org reconcile path;
* the DCR registration URI is likewise templated —
  `{base}/realms/{realm}/clients-registrations/openid-connect/{clientID}`
  (`internal/subroutine/idp/subroutine.go`);
* the admin issuer is `{base}/realms/master`, configured as `cfg.Keycloak.BaseURL`;
* service-account clients and realm-role assignment are Keycloak-specific
  (`CreateServiceAccountClient`, `AssignRealmRoleToUser`);
* the portal hardcodes a Keycloak discovery URL template with the realm name substituted in.

**Two consequences follow, and both are load-bearing for this ADR.**

*First, only one operational mode exists.* Because the issuer URL is derived from the workspace
name, Platform Mesh can express "one issuer per organization" and nothing else. A single
platform-wide issuer, or a mix where organizations without their own issuer fall back to a global
one, cannot be configured at all.

*Second, identities are not namespaced.* The generated kcp
`WorkspaceAuthenticationConfiguration` sets **both** claim prefixes to the empty string:

```go
ClaimMappings: kcptenancyv1alpha1.ClaimMappings{
    Groups:   {Claim: r.cfg.GroupClaim, Prefix: ptr.To("")},
    Username: {Claim: r.cfg.UserClaim,  Prefix: ptr.To("")},
}
```

With an empty username prefix, two different issuers presenting the same `email` claim map to the
**same** kcp username, and therefore to the same RBAC subject and the same authorization subject.
Today only one issuer exists per workspace, so this is latent. The moment a second issuer can be
configured it becomes an account-takeover vector:
whoever may register an issuer may mint an identity that collides with an existing principal. This
is not a hypothetical to document; it is the current default, and it must be closed by the same
change that makes multiple issuers possible.

The `AccountInfo.spec.oidc` field (`{issuerUrl, clients}`) is already optional and engine-neutral,
and already feeds the kcp authentication configuration (it supplies the audience list). It is the
one piece of neutral surface that exists and can be kept as-is.

## Decision Drivers

* **OIDC is standard; multi-tenant OIDC is not.** The platform must own the multi-tenancy
  abstraction, because no upstream standard defines it.
* **Three operational modes must be expressible**: one platform-wide issuer, one issuer per tenant,
  and a mix with fallback.
* **A mode in which Platform Mesh never writes to the IdP must exist.** In regulated environments,
  automated modification of identity infrastructure is prohibited; the admin supplies a finished
  client configuration instead.
* **Identity must be unambiguous across issuers by construction**, not by operator convention.
* **Self-service must not permit lock-out.** A tenant editing its own authentication configuration
  must not be able to lose access to its workspace.
* **Keycloak remains the Tier 1 default** (RFC 008 non-goals). This ADR does not demote it.
* **Do not re-abstract DCR.** `pkg/clientreg` already is the interface.

## Considered Options

1. **Status quo plus a Keycloak on/off switch** — Rejected: It makes an implementation optional
   without defining what replaces it.
2. **One CR per tenant carrying a complete OIDC client configuration, no provisioning concept.**
   Rejected: it discards managed DCR, which RFC 008 identifies as what makes managed multi-org
   practical, and pushes per-tenant client creation onto administrators.
3. **An `AuthenticationConfig` resource with an explicit provisioning mode and a defined resolution
   order.** This ADR.
4. **Manage kcp's `WorkspaceAuthenticationConfiguration` directly and drop the abstraction.**
   Rejected: no per-tenant client provisioning, no invite flow, and the resource becomes a
   hand-maintained artifact per organization.

## Decision Outcome

Chosen: **option 3**.

### The API group and resource

Introduce **`authentication.platform-mesh.io/v1alpha1`** with `AuthenticationConfig`, which may
exist at platform level (in `root:platform-mesh-system`) and per organization workspace.

```yaml
apiVersion: authentication.platform-mesh.io/v1alpha1
kind: AuthenticationConfig
metadata:
  name: acme
spec:
  provisioning: External          # Managed | External
  issuer:
    url: https://login.example.com/realms/acme
    discovery: WellKnown          # WellKnown | Static
    certificateAuthorityRef:
      name: domain-ca
      key: tls.crt
  identity:
    usernameClaim: sub
    usernamePrefix: "acme:"       # optional; defaults to "<organization-name>:" — see below.
                                   # Once resolved onto status, non-empty and immutable.
    groupsClaim: groups
    groupsPrefix: "acme:"         # same default and invariant as usernamePrefix
  clients:
    - name: portal
      type: public                # public | confidential
      redirectUris: ["https://portal.example.com/callback"]
      postLogoutRedirectUris: ["https://portal.example.com"]
      secretRef:                  # External: admin-provided. Managed: written by the provisioner.
        name: portal-oidc
  additionalAudiences: []
status:
  conditions: [...]               # includes Validated
  resolvedIssuerURL: https://login.example.com/realms/acme
  effectiveFrom: Organization     # Organization | Platform
  managedClients: {...}
```

`provisioning: Managed` — a provisioner creates the tenancy construct in the IdP (for Keycloak: the
realm) and registers clients through DCR using the existing `pkg/clientreg`.

`provisioning: External` — **nothing is written to the IdP.** The admin supplies the issuer and the
client credentials; the only thing Platform Mesh writes is the kcp
`WorkspaceAuthenticationConfiguration` derived from the resolved configuration.

### The three operational modes are placement, not new concepts

| Mode | Expressed as |
|---|---|
| One platform-wide issuer (Kubernetes-style) | a single `AuthenticationConfig` in `root:platform-mesh-system`, no per-organization resources |
| One issuer per tenant | one `AuthenticationConfig` per organization workspace |
| Mixed, with fallback | a platform-level resource plus per-organization overrides; organizations without one inherit the platform-level config |

**Resolution order:** an organization-scoped `AuthenticationConfig` wins; otherwise the
platform-level one applies; if neither exists, organization initialization **fails with a condition**
rather than falling back to a built-in default. `status.effectiveFrom` records which one applied, so
the mode is observable rather than inferred.

**Where each object lives.** An organization-scoped `AuthenticationConfig` lives *inside* the
organization's own workspace (e.g. `root:orgs:acme`) — the same workspace its tenants already write
into, reachable through the `authentication.platform-mesh.io` export bound there via
`defaultAPIBindings`, mirroring [ADR 013](013-engine-neutral-authorization-api.md)'s
`authorization.platform-mesh.io` export. This is deliberately **not** where the native object lives:
kcp's `WorkspaceAuthenticationConfiguration` for an organization is a `root:orgs`-scoped resource
named after the organization, referenced from the organization's `WorkspaceType` — both already true
today, via `patchWorkspaceTypes`. kcp resolves the authenticator for a workspace from its
`WorkspaceType`, not from inside the workspace itself, so the native object has to live where the
`WorkspaceType` can be patched to point at it, which is `root:orgs` — not inside the org.

The `security-operator` bridges the two: it reads the tenant-authored `AuthenticationConfig` from
inside the organization's workspace — which needs its own read grant into every organization
workspace, an access requirement this ADR introduces and does not yet fully specify, left to the same
follow-up as [ADR 013](013-engine-neutral-authorization-api.md)'s access-model open items — and
writes the resolved `WorkspaceAuthenticationConfiguration` into `root:orgs`, exactly as it does today.
`AuthenticationConfig` is a friendlier, namespaced-identity-aware **intent** surface;
`WorkspaceAuthenticationConfiguration` in `root:orgs` remains the only thing kcp actually
authenticates against — this ADR adds a surface in front of it, not a second authority. The
platform-level `AuthenticationConfig` (mode 1, and the fallback half of mode 3) lives in
`root:platform-mesh-system`, where the `security-operator` already operates directly.

This is why the modes are an API concern and not an implementation detail of a provisioner: mode 1
versus mode 2 determines where the resource lives and how the kcp
`WorkspaceAuthenticationConfiguration` is derived, and a provisioner cannot decide that on the
platform's behalf.

### Identity is namespaced by construction

`spec.identity.usernamePrefix` is optional in the spec; once resolved onto `status` it is non-empty,
immutable, and unique across every `AuthenticationConfig` on the platform. The same applies to
`groupsPrefix`.

**Enforcing that uniqueness at admission does not work.** A webhook validating a new
`AuthenticationConfig` would need to enumerate every other `AuthenticationConfig` across every
organization workspace to check for a collision — the same cross-workspace reach [ADR
013](013-engine-neutral-authorization-api.md) rejects for RBAC materialization, and for the same
reason: a live `List`/`Watch` grant spanning every tenant workspace, held by an admission webhook, is
a large blast radius for a small check. Two mechanisms are used instead, matched to how a prefix is
obtained:

* **Default: the prefix is derived, not chosen.** `usernamePrefix` defaults to
  `<organization-name>:`, where `<organization-name>` is the `Account`'s name in `root:orgs` —
  already guaranteed unique by kcp's own name uniqueness within that workspace. No admission check,
  no new resource, and no cross-workspace read: the `security-operator` already has whatever access
  it needs to read the `Account` it is reconciling.
* **Opt-in: a custom prefix goes through a claim.** `PrefixClaim.authentication.platform-mesh.io` is
  a cluster-scoped resource in `root:platform-mesh-system` whose `metadata.name` *is* the prefix.
  Turning "is this prefix free" into a single `Create` lets the API server's own name-uniqueness
  guarantee answer it — no list, no lock, the same technique Kubernetes uses for `ClusterIP` and
  `Namespace` allocation. **Only the `security-operator` creates `PrefixClaim` objects**, while
  resolving an `AuthenticationConfig` that requests a non-default prefix — never the tenant directly,
  and never from a webhook. A tenant can *request* a prefix; it cannot *mint* one. This closes the
  squatting gap a tenant-writable claim would open (an org claiming `acme:` before the real `acme`
  organization exists), at the cost of the request going through a reconcile rather than resolving
  synchronously. Because the `security-operator` already obtains clients for arbitrary logical
  clusters (it already reconciles `root:platform-mesh-system` and `root:orgs`), writing a
  `PrefixClaim` needs no new access grant, unlike the org-workspace read introduced below.
  `PrefixClaim.spec.claimant` records the requesting `AuthenticationConfig`'s workspace path and
  name — a cross-workspace reference cannot be a Kubernetes owner reference — and the
  `security-operator` places a finalizer on the `AuthenticationConfig` that releases the claim on
  deletion. Whether a released prefix should be reusable immediately or held for a cooldown is an
  open decision below; reuse here is lower-risk than the RBAC materialization case, because deleting
  an organization tears down every principal that held its prefix, unlike a stale `RoleBinding`.

`alice@example.com` authenticated through issuer `acme` is the kcp principal
`acme:alice@example.com`; through a different issuer it is a different principal — in kcp
authentication, in RBAC, and in `RoleAssignment.spec.subjects[].name` (ADR 013, whose `issuerRef`
field names the `AuthenticationConfig` that vouches for a subject). The takeover scenario becomes
unrepresentable rather than documented as a caveat.

The recommended `usernameClaim` is **`sub`**, not `email`: `sub` is stable and opaque, whereas an
email address is mutable and may be reassigned to a different person. Email remains available as
display metadata. This differs from today's behaviour and is called out as an open decision below,
because it changes what an operator sees in audit logs and bindings.

### Self-service without lock-out

Three mechanisms, in order of importance:

1. **Validated before effective.** A new or changed issuer is applied to the kcp authentication
   configuration only after the provisioner has fetched its discovery document and confirmed a token
   can be validated against it. Until then, the previous configuration stays effective and the
   resource carries a failing `Validated` condition. A misconfigured issuer becomes a failed
   reconcile, not a lock-out.
2. **Last-issuer protection.** A validating webhook rejects any change that would leave a workspace
   with no working issuer.
3. **Break-glass.** A static issuer configured at install time on the `WorkspaceType` cannot be
   removed by tenant-scoped writes.

### Component boundaries after this ADR

| Component | Today | After |
|---|---|---|
| `security-operator` | reconciles IdP configuration against the Keycloak admin API, templates realm URLs, writes the kcp `WorkspaceAuthenticationConfiguration` | resolves `AuthenticationConfig`, writes its status and the kcp `WorkspaceAuthenticationConfiguration`; holds no IdP client and no Keycloak configuration |
| `keycloak-authn-operator` (new) | — | `Managed` mode: realm lifecycle, DCR client registration via `pkg/clientreg`, service-account clients |
| `static-oidc-provisioner` | — | `External` mode: validates discovery, resolves clients from secrets. Small enough to remain a subroutine of the `security-operator` — see open decisions |
| `iam-service` | Keycloak-specific user management | optional, behind a user-directory interface; absent ⇒ the portal hides user management |
| `portal` / `portal-server-lib` | hardcoded Keycloak discovery URL template | reads `status.resolvedIssuerURL` |
| `IdentityProviderConfiguration` | public CRD in `core.platform-mesh.io` | a `Managed`-mode detail owned by the Keycloak provisioner; moves out of `core` |
| `AccountInfo.spec.oidc` | populated by the `security-operator` | unchanged shape, populated from the resolved configuration |
| `backup-operator` | backs up the Keycloak CloudNativePG cluster unconditionally | backs up the IdP database only in `Managed` mode; see ADR 008 note below |

**Note the asymmetry with [ADR 013](013-engine-neutral-authorization-api.md).** For authorization,
the alternative to OpenFGA is a *different engine* (Kubernetes RBAC). For authentication, the
alternative to Keycloak is *no provisioning at all* — Kubernetes has no built-in identity provider,
and RBAC is an authorization mechanism. `External` mode is the counterpart of Keycloak
here.

### User management and invites

User *directory* functionality is an IdP capability, not a platform one. The `iam-service` keeps its
GraphQL surface but reads and writes through a `UserDirectory` interface with a Keycloak
implementation. In `External` mode with no directory backend, the user list and invite flows are
hidden in the portal rather than failing at runtime, advertised through an
`AuthenticationCapabilities` singleton mirroring ADR 013's `AuthorizationCapabilities`, so the portal
has one place to ask.

`Invite`, which depends on writing users into the IdP, becomes a `Managed`-mode capability.

### Interaction with ADR 008 (backup and restore)

[ADR 008](008-platform-mesh-backup-and-restore.md) pins restores to the source topology and requires
the topology to travel inside the backup. Once authentication provisioning is a mode rather than a
constant, the provisioning mode becomes part of that topology: a `Managed`-mode backup contains an
IdP database that has no restore target in an `External`-mode deployment. The restore controller must
treat a provisioning-mode mismatch as a validation failure, consistent with ADR 008's
architecture-pinning decision. This ADR records the requirement; the concrete validation rule belongs
in an amendment to ADR 008.

### Migration

| Phase | Content |
|---|---|
| 0 | Introduce the group and `AuthenticationConfig`. The `security-operator` derives one resource per organization from today's implicit values — templated issuer URL, empty prefixes. No behaviour change; the current topology becomes explicit. |
| 1 | Extract Keycloak provisioning into `keycloak-authn-operator`. The `security-operator` loses `cfg.Keycloak.*`. |
| 2 | `External` mode; the portal reads `status.resolvedIssuerURL` instead of templating a discovery URL. |
| 3 | **Prefix migration — the breaking step.** The kcp authentication configuration temporarily carries two authenticators for the same issuer, one unprefixed and one prefixed. `RoleAssignment` subjects are backfilled to prefixed names (ADR 013). Once no unprefixed principal is in use, the unprefixed authenticator is removed. This phase needs its own runbook. |
| 4 | `IdentityProviderConfiguration` deprecated in `core.platform-mesh.io`; `Invite` gated on `Managed` mode. |

## Consequences

### Positive

* The three operational modes administrators actually ask for become configurable, rather than one
  being hardcoded.
* The identity-collision vector is closed by construction at the same time multiple issuers become
  possible, instead of afterwards.
* `External` mode makes Platform Mesh deployable in environments that forbid automated IdP
  modification — a category currently excluded outright.
* The process holding Keycloak admin credentials is no longer the process reconciling accounts,
  which reduces the blast radius RFC 008's security rationale describes.
* `pkg/clientreg` is reused rather than reinvented.

### Negative

* **The prefix change is breaking** and touches every existing principal, `RoleBinding`, and
  authorization subject. Phase 3 is the most expensive part of this ADR and cannot be avoided if
  multiple issuers are to be supported safely.
* One more operator in the default composition, with its chart and OCM component.
* Issuer validation introduces a reconcile-time dependency on IdP reachability: an unreachable IdP
  blocks configuration changes, by design.
* Switching the recommended `usernameClaim` to `sub` makes bindings and audit output less
  human-readable.
* `IdentityProviderConfiguration` leaving `core.platform-mesh.io` is an API break for anything that
  reads it today.

### Confirmation

* CI compositions: `Managed` (Keycloak) and `External` (a static OIDC issuer — Dex is already the
  RFC 008 Tier 2 candidate), each creating an organization and completing a login.
* A negative test asserting that two `AuthenticationConfig`s cannot claim the same
  `usernamePrefix`.
* A negative test asserting that an issuer failing discovery validation does not become effective
  and does not disturb the previous configuration.
* A test asserting that a change removing the last working issuer for a workspace is rejected.
* No `cfg.Keycloak.*` configuration remains in the `security-operator` (mechanically checkable).
* A test asserting that only the `security-operator`'s identity can create `PrefixClaim` objects —
  no path exists for a tenant-held identity to create one directly.
* A test asserting that two organizations left at their default prefix never collide, without any
  admission check running (the derivation, not enforcement, is what is being tested).

## Open decisions for the TSC

1. ~~**Prefix scope.**~~ **Resolved by the derived-prefix design above:** each `AuthenticationConfig`
   gets a unique prefix by construction (derived from its organization's name, or an explicitly
   claimed one), and v1 allows at most one `AuthenticationConfig` per organization, so per-issuer and
   per-organization coincide. Revisit only if a later version allows more than one issuer per
   organization.
2. **`usernameClaim` default.** `sub` (recommended, stable and opaque) or `email` (current,
   readable, but mutable and reassignable)?
3. **Where `External` mode lives.** A subroutine of the `security-operator` (recommended — it is
   small, and the null provisioner is arguably baseline behaviour) or its own operator for symmetry
   with the Keycloak provisioner?
4. **`Invite`.** `Managed`-mode only (recommended), or is a generic invite contract worth defining
   across providers?
5. **Development mode.** The `DevelopmentAllowUnverifiedEmails` path currently relaxes email
   verification through a CEL claim-validation rule. Keep it as an explicit field on
   `AuthenticationConfig`, or remove it in favour of an unverified-email-tolerant test issuer?
6. **`AuthenticationCapabilities`.** A status-only singleton as proposed, or folded into the
   `PlatformMesh` resource's status — same question as ADR 013 raises, and it should be answered the
   same way in both.
7. **Prefix reuse cooldown.** Let a released `PrefixClaim` name be reused immediately (recommended —
   deleting an organization already removes every principal that held its prefix), or hold it for a
   cooldown window?
8. **`security-operator` read access into every organization workspace.** Introduced above to read
   tenant-authored `AuthenticationConfig`; the exact claim shape is left to the same access-model
   follow-up as [ADR 013](013-engine-neutral-authorization-api.md)'s open items. Confirm that
   follow-up covers both ADRs rather than each specifying its own mechanism.

## References

* [RFC 008 — A Modular Framework for Platform Mesh](../rfc/008-platform-mesh-modularization.md)
* [ADR 007 — Transition from Bitnami Keycloak Helm Chart to the Official Keycloak Operator](007-transition-from-bitnami-keycloak-to-keycloak-operator.md)
* [ADR 008 — Platform Mesh Backup and Restore](008-platform-mesh-backup-and-restore.md)
* [ADR 013 — Engine-Neutral Authorization API](013-engine-neutral-authorization-api.md)
* [RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
