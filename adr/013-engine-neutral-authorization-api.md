# ADR 013: Engine-Neutral Authorization API

| Status          | Proposed                                                                 |
|-----------------|--------------------------------------------------------------------------|
| Date            | 2026-09-18                                                               |
| Supersedes      | [ADR 002](002-apiexport-binding-access-control.md) (decision 3 only)     |
| Decision-makers | Platform Mesh TSC                                                        |
| Epic            | [platform-mesh/backlog#381](https://github.com/platform-mesh/backlog/issues/381) |
| Related         | [RFC 008](../rfc/008-platform-mesh-modularization.md), [RFC 010](../rfc/010-provider-permissions-configuration.md), [ADR 011](011-mcp-server-for-kcp-and-platform-mesh.md) |

## Context and Problem Statement

[RFC 008](../rfc/008-platform-mesh-modularization.md) makes authorization a module: the Kubernetes
authorization webhook (`SubjectAccessReview`) is the interface, OpenFGA is the swappable engine
behind it, and managed Kubernetes RBAC is the fallback when no engine is deployed. RFC 008 further
states that authorization intent is expressed as KRM resources.

Neither half holds today.

**OpenFGA is not an implementation detail — it is public API surface.** Three places, in increasing
order of consequence:

1. `core.platform-mesh.io` carries `Store` — whose `spec.tuples[]` are literal OpenFGA tuples
   (`{object, relation, user}`) — and `AuthorizationModel`, whose payload is an OpenFGA
   authorization model. Both are installed in every deployment.
2. [ADR 002](002-apiexport-binding-access-control.md) (**Approved**) decides that the
   `security-operator` "reconciles `APIExportPolicy` resources and **writes tuples directly to the
   appropriate FGA stores**", and that the authorization webhook checks the consumer's FGA store for
   a `bind` relation. API binding is a Core function, so an approved decision puts OpenFGA on the
   Core path.
3. [RFC 010](../rfc/010-provider-permissions-configuration.md) introduces a `ProviderPermissions`
   CRD in `providers.platform-mesh.io` whose field values are **OpenFGA DSL**
   (`define codeviewer: [role#assignee] or owner`). This is a provider-facing, third-party-authored
   API, and it is currently in implementation.

**Authorization intent is not KRM at all.** The role catalog is a YAML file mounted into the
`iam-service` (`pkg/roles/roles.go`), and its role objects carry only `{id, displayName,
description}` — no permissions. Role *assignment* is a GraphQL mutation (`assignRolesToUsers`) that
writes OpenFGA tuples directly (`pkg/fga/fga.go`). There is no declarative, reconcilable resource
recording who holds which role, so there is nothing for a second engine to read and nothing to back
up, diff, or review.

Mechanically, the coupling reaches further: the `security-operator` opens an OpenFGA gRPC connection
unconditionally in all four of its commands (`initializer`, `operator`, `system`, `terminator`), the
`search-service` dials OpenFGA at startup and exits on failure, `AccountInfoSpec.FGA` is a required
field, and `golang-commons/fga` sits on the import path of components that must run without the
module.

So this ADR must solve two problems, not one: engine vocabulary in public APIs, and the absence of a
declarative intent surface.

## Decision Drivers

* **The interface is the contract** (RFC 008). Public APIs must not name an engine.
* **Intent must be KRM.** Role assignments must be reconcilable resources, not side effects of a
  GraphQL call.
* **Core must reconcile with no engine present.** Account and organization creation, and API
  binding, cannot depend on an optional module.
* **Bounded support surface.** One neutral API, N projectors — not N APIs.
* **Do not add coupling while removing coupling.** RFC 010 is in flight and would bake OpenFGA DSL
  into a provider-facing API.
* **No silent capability loss.** Where an engine cannot express an intent, that must surface as
  status, not as a quietly missing permission.
* **Existing assignments must survive.** Deployments hold live tuples and populated
  `AccountInfo.spec.fga`.

## Considered Options

1. **Keep engine-specific CRDs, gate controllers behind flags.** Cheapest. Rejected: the public API
   stays OpenFGA-shaped, so an RBAC composition has no vocabulary in which to express anything, and
   `Store`/`AuthorizationModel` remain installed but meaningless.
2. **Neutral intent CRDs, one projector per engine.** This ADR.
3. **Neutral intent CRDs, projected by the IAM Service** — the literal wording of RFC 008
   ("projected into the engine by a single reconciler (IAM Service)").
4. **A Go interface inside the `security-operator`, no new CRDs** — Rejected: every new engine then
   requires a commit to a Core component and ships inside the Core binary, which is the coupling
   RFC 008 exists to remove.

## Decision Outcome

Chosen: **option 2**, with the projector/IAM-Service question resolved explicitly below.

### The API group

Introduce **`authorization.platform-mesh.io/v1alpha1`**.

This group is not new: [ADR 002](002-apiexport-binding-access-control.md) already specifies
`APIExportPolicy` as `authorization.platform-mesh.io/v1alpha1`. It was implemented in
`core.platform-mesh.io`. This ADR realizes the group ADR 002 intended.

### Resources

Three resources. The first two are intent, the third is advertised capability.

#### `RoleDefinition` — the catalog

```yaml
apiVersion: authorization.platform-mesh.io/v1alpha1
kind: RoleDefinition
metadata:
  name: httpbin-codeviewer
spec:
  displayName: Code Viewer
  description: Read-only access to httpbins
  scopeType: Account            # Account | Workspace | Resource
  target:                       # the type this role is about
    group: orchestrate.platform-mesh.io
    resource: httpbins
  rules:                        # intent, engine-neutral
    - apiGroups: ["orchestrate.platform-mesh.io"]
      resources: ["httpbins"]
      verbs: ["get", "list", "watch"]
  assignable: true              # appears in the IAM role catalog
status:
  conditions: [...]
  projections:
    - engine: openfga
      state: Applied
    - engine: rbac
      state: Applied
```

`rules` is deliberately shaped like `rbac.authorization.k8s.io/v1` `PolicyRule`. That shape is the
lowest common denominator both engines consume, and it is already the vocabulary of the *input* the
`security-operator`'s `model-generator` reads today: it derives the OpenFGA authorization model from
an `APIExport`'s `boundResources`. The neutral source therefore already exists; only the projection
is engine-specific.

`RoleDefinition` replaces the YAML file in the `iam-service`.

#### `RoleAssignment` — the binding

```yaml
apiVersion: authorization.platform-mesh.io/v1alpha1
kind: RoleAssignment
metadata:
  name: alice-codeviewer
spec:
  subjects:
    - kind: User                # User | Group | ServiceAccount
      name: "acme:alice@example.com"
      issuerRef: acme           # the AuthenticationConfig that vouches for this name (ADR 013)
  roleRef:
    name: httpbin-codeviewer
  scope:
    accountPath: root:orgs:acme:team-a
  inheritance: Inherited        # Inherited | Local
status:
  conditions: [...]
  projections: [...]
```

`issuerRef` exists because a subject name is only unambiguous relative to the issuer that produced
it; see [ADR 014](014-authentication-api-surface-and-provisioning-modes.md).

#### `AuthorizationCapabilities` — what the installed engine can do

```yaml
apiVersion: authorization.platform-mesh.io/v1alpha1
kind: AuthorizationCapabilities
metadata:
  name: cluster
status:
  engine: openfga               # openfga | rbac | <third-party>
  features:
    hierarchicalInheritance: true
    instanceScopedRoles: true
    transitiveGroups: true
    listFiltering: true
```

A singleton, status-only, written by whichever projector is deployed. It is how the portal, the
`iam-service`, and the `search-service` degrade deliberately instead of guessing or erroring.

### Projectors

Two default projectors, **neither in Core**:

* `openfga-authz-operator` — owns `Store`, `AuthorizationModel`, tuples, and the OpenFGA
  authorization model generation.
* `rbac-authz-operator` — projects to `rbac.authorization.k8s.io` `ClusterRole` / `RoleBinding`.

Each watches `RoleDefinition` and `RoleAssignment`, writes engine state, and writes
`status.projections[]` back. Status write-back is not optional: it is the only way the writer of the
intent, and the UI, can tell whether a grant took effect.

### Resolving the RFC 008 wording: projector, not IAM Service

RFC 008 says intent is "projected into the engine by a single reconciler (IAM Service)". Read as
*exactly one component projects, rather than projection scattered across several*, this ADR complies.
Read as *that component is the IAM Service*, it does not, deliberately:

* the `iam-service` is a request-path GraphQL service in the **UI boundary**; authorization must
  function in a headless composition where no UI module is installed;
* a projector must run as a controller with leader election and full reconcile-on-restart semantics,
  which is a different runtime shape from a GraphQL service;
* keeping projection in the `iam-service` would make the UI boundary a hard dependency of the
  Authorization boundary — an inverted dependency direction that RFC 008's own module rules forbid.

**RFC 008 should be amended** to read "by a single projector per engine". This is an open item for
the TSC (see below), not a unilateral reinterpretation.

### Expressiveness: named, bounded, and advertised

ReBAC is strictly more expressive than RBAC. Three concrete gaps:

| Capability | OpenFGA | Kubernetes RBAC |
|---|---|---|
| Hierarchical inheritance (org → account → sub-account) | relation walk via `parent` | only by materializing bindings into every descendant |
| Instance-scoped relations ("owner of *this* object") | native | only `resourceNames`, no relations |
| Transitive group/team relations | native | not expressible |

The intent API is authored at the intent level, and the gap is handled explicitly:

* `RoleAssignment.spec.inheritance: Inherited` — the OpenFGA projector maps this to a `parent` walk.
  The RBAC projector **materializes** `RoleBinding`s into descendant workspaces, bounded by a
  configurable `maxDepth`. If the bound is exceeded, it sets a `Degraded` condition with reason
  `InheritanceNotProjected` and names the workspaces it did not reach. Never silent.
* Intents an engine cannot express at all are rejected at admission by that engine's projector, with
  a condition — not accepted and dropped.
* `AuthorizationCapabilities.status.features` lets consumers adapt before they try.

### `APIExportPolicy` and ADR 002

`APIExportPolicy`'s *shape* is already engine-neutral: an `apiExportRef` plus
`allowPathExpressions`. Its policy semantics, including the deliberate non-inheritance to child
accounts documented in ADR 002's scenarios, are **retained verbatim**.

What changes is decision 3 alone. The `security-operator` stops writing tuples; it resolves path
expressions and records the result in `status.resolvedAccounts`. A projector turns that into engine
state:

* `openfga-authz-operator` — the `bind` tuples exactly as ADR 002 specifies;
* `rbac-authz-operator` — `ClusterRole`/`ClusterRoleBinding` granting the `bind` verb on the
  referenced `APIExport` in the resolved workspaces.

`APIExportPolicy` **stays in `core.platform-mesh.io`**, despite ADR 002's group name, because API
binding is a Core capability that must work in every composition. The resource is Core; only its
projection is modular.

### RFC 010 alignment — required, and before merge

[RFC 010](../rfc/010-provider-permissions-configuration.md) already anticipates a non-OpenFGA engine
("in RBAC mode it will not be needed"; "In future with RBAC system (or another authorization module)
it can be left empty"), but its resource carries OpenFGA DSL as field values. Align it as follows:

* `roles[].definition` (a DSL string) is replaced by `rules` (the `RoleDefinition` shape above);
* genuinely ReBAC-only constructs move to an explicit
  `engineOverrides.openfga.definition` escape hatch;
* `ProviderPermissions` becomes a **generator of `RoleDefinition`s** rather than a merge input to
  `AuthorizationModel`;
* a projector that cannot honour an `engineOverrides` entry reports `Degraded` for it rather than
  dropping it.

This preserves everything RFC 010 sets out to do — providers extending relations and contributing
roles — while keeping the engine out of a public, third-party-authored API. Doing it after RFC 010
ships means breaking a provider-facing API later.

### List filtering and search — fail closed

The `search-service` today performs an OpenFGA pre-filter and a per-hit filter. The no-engine
behaviour is a security decision, so it is made here rather than left to the epic:

The `search-service` reads `AuthorizationCapabilities`. When `listFiltering` is `false`, it
restricts results to the workspaces the caller may `list`, resolved through the
`SelfSubjectAccessReview` / Access Virtual Workspace mechanism of
[ADR 011](011-mcp-server-for-kcp-and-platform-mesh.md), and **returns an error rather than unfiltered
results** if that resolution is unavailable. Unfiltered search over a cross-workspace index is never
a fallback.

Reusing ADR 011's mechanism is deliberate: "which workspaces may this user see" is the same question
that ADR already answers, and a second mechanism for it would be a second thing to get wrong.

### Component boundaries after this ADR

| Component | Today | After |
|---|---|---|
| `security-operator` | writes tuples; dials OpenFGA gRPC in all four commands | writes `RoleDefinition` / `RoleAssignment` / `APIExportPolicy.status`; no OpenFGA client, no `golang-commons/fga` import |
| `openfga-authz-operator` (new) | — | owns `Store`, `AuthorizationModel`, tuples, model generation |
| `rbac-authz-operator` (new) | — | projects to `ClusterRole` / `RoleBinding` |
| `iam-service` | YAML role catalog; writes tuples via GraphQL | reads `RoleDefinition`, writes `RoleAssignment`; no engine write path |
| `rebac-authz-webhook` | on the kcp webhook chain | unchanged; deployed only alongside the OpenFGA projector |
| `search-service` | OpenFGA pre- and post-filter | reads `AuthorizationCapabilities`; the OpenFGA authorizer becomes one implementation |
| `golang-commons/fga` | imported broadly | imported only by the OpenFGA projector and the webhook |
| `model-generator` | `boundResources` → OpenFGA model | one projection among two from the same neutral input |

### Migration

| Phase | Content |
|---|---|
| 0 | Introduce the group and CRDs. No behaviour change. |
| 1 | `security-operator` dual-writes (tuples **and** the new resources). A backfill job derives `RoleAssignment`s from existing tuples. The OpenFGA projector runs in shadow mode and its output is diffed against the live store. |
| 2 | The projector becomes authoritative; the `security-operator` stops writing tuples. ADR 002 decision 3 is superseded at this point, not before. |
| 3 | `Store`, `AuthorizationModel` and `Tuple` deprecated in `core.platform-mesh.io`, re-published in an engine-owned group. `AccountInfoSpec.FGA` becomes optional (still populated by the OpenFGA projector), then removed in the next API version. |
| 4 | `rbac-authz-operator`; engine-free compositions enter CI. |

`AccountInfoSpec.FGA` is a required field with live data, so it cannot be dropped in one step:
optional first, populated by the projector for one release, then removed.

## Consequences

### Positive

* A new engine is a new operator, not a commit to a Core component — the RFC 008 ecosystem promise
  becomes mechanically true.
* Role assignments become reviewable, diffable, backup-able KRM state. They are currently
  reconstructible only from the engine's own store.
* The process holding OpenFGA credentials is no longer the process that reconciles accounts.
* Capability degradation is advertised rather than discovered.

### Negative

* **Role assignment stops being synchronous.** Today a GraphQL mutation writes the tuple and
  returns. After this ADR the mutation writes a resource and a projector applies it. The IAM UI must
  render a pending state and surface projection failures. This is the main user-visible cost and it
  is not avoidable in a projector model.
* Two additional deployables, with their OCM components and charts
  ([ADR 001](001-sbom-generation-and-ocm-component-restructuring.md),
  [ADR 010](010-consolidate-helm-charts-and-ocm.md)).
* The test matrix grows, which is the risk
  [backlog#290](https://github.com/platform-mesh/backlog/issues/290) names.
* The RBAC projector's materialized inheritance causes write amplification in deep account trees.
* A superseded, approved ADR (002) and an in-flight RFC (010) both require follow-up work.

### Confirmation

* CI composition tests: at minimum one with the OpenFGA projector and one with the RBAC projector,
  both creating an organization, an account, and a role assignment.
* A projector conformance suite: one intent fixture set, asserted per engine, with the expected
  `Degraded` conditions where a capability is absent.
* A lint gate asserting that `golang-commons/fga` is not on the import path of the
  `security-operator` or the `search-service`. Mechanically checkable, unlike a documented intent.
* `Store`/`AuthorizationModel` absent from a `kubectl api-resources` listing in an RBAC composition.

## Open decisions for the TSC

1. **RFC 008 amendment.** Adopt "a single projector per engine" in place of "a single reconciler
   (IAM Service)"?
2. **RBAC inheritance.** Materialize descendant bindings with a `maxDepth` bound (recommended), or
   declare hierarchical inheritance unsupported under RBAC?
3. **RFC 010 sequencing.** Align `ProviderPermissions` before it merges (recommended), or ship it as
   specified and break the provider API later?
4. **Deprecation window** for `Store` / `AuthorizationModel` in `core.platform-mesh.io`.
5. **`AuthorizationCapabilities` shape.** A status-only singleton as proposed, or fold the same
   information into the `PlatformMesh` resource's status?

## References

* [RFC 008 — A Modular Framework for Platform Mesh](../rfc/008-platform-mesh-modularization.md)
* [RFC 010 — Provider Permissions Configuration](../rfc/010-provider-permissions-configuration.md)
  (note: this file's heading currently reads "RFC 008")
* [ADR 002 — Fine-Grained Access Control for APIExport Binding](002-apiexport-binding-access-control.md)
* [ADR 011 — MCP Server for kcp and Platform Mesh](011-mcp-server-for-kcp-and-platform-mesh.md)
* [ADR 013 — Authentication API Surface and Provisioning Modes](014-authentication-api-surface-and-provisioning-modes.md)
* [backlog#381 — epic: Authorization as a pluggable module](https://github.com/platform-mesh/backlog/issues/381)
