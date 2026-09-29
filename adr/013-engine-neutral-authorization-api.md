# ADR 013: Engine-Neutral Authorization API

| Status          | Proposed                                                                 |
|-----------------|--------------------------------------------------------------------------|
| Date            | 2026-09-18                                                               |
| Supersedes      | [ADR 002](002-apiexport-binding-access-control.md) (decision 3 only)     |
| Decision-makers | Platform Mesh TSC                                                        |
| Related         | [RFC 008](../rfc/008-platform-mesh-modularization.md), [RFC 010](../rfc/010-provider-permissions-configuration.md), [ADR 011](011-mcp-server-for-kcp-and-platform-mesh.md), [ADR 014](014-authentication-api-surface-and-provisioning-modes.md) |

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

### Terminology: Account and Workspace

An **Account** (`core.platform-mesh.io`) is the platform resource: it carries a type (`org` or
`account`), a creator and extensions, and it lives in its *parent's* workspace. A **Workspace** is
the kcp logical cluster that holds an account's content. The two are one-to-one: the
`account-operator` creates a `Workspace` with the same name as the `Account` (in the same parent
cluster), and `AccountInfo` records both the account and the generated cluster
(`GeneratedClusterId`, `Path`).

This ADR therefore does not distinguish them for scoping: **an object's scope is the workspace it
lives in**, and an "account path" (as used by the `iam-service`'s `ResourceContext.accountPath`) is
that workspace's path. There is no separate `Workspace` scope type.

### Resources

Three resources. The first two are intent, the third is advertised capability. Where they live and
who may write them is specified in [Placement, ownership and access](#placement-ownership-and-access).

#### `RoleDefinition` — the catalog

```yaml
apiVersion: authorization.platform-mesh.io/v1alpha1
kind: RoleDefinition
metadata:
  name: httpbin-codeviewer
spec:
  displayName: Code Viewer
  description: Read-only access to httpbins
  target:                       # the resource type this role is about; must be a type the
    group: orchestrate.platform-mesh.io   # defining workspace's APIExport serves (or, for
    resource: httpbins                    # platform types, the platform workspace)
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
      issuerRef: acme           # the AuthenticationConfig that vouches for this name (ADR 014)
  roleRef:
    name: httpbin-codeviewer
  resourceRef:                  # optional: narrow the grant to one object in this workspace
    group: orchestrate.platform-mesh.io
    resource: httpbins
    name: my-httpbin
  inheritance: Local            # Local | Inherited (Inherited: see Expressiveness)
status:
  conditions: [...]
  projections: [...]
```

A `RoleAssignment` **lives in the workspace it grants access in**, exactly as a Kubernetes
`RoleBinding` lives in the namespace it applies to. It carries no target-workspace field, because a
field naming another workspace would need write access to that workspace — the problem the
[access model](#kcp-access-model-least-privilege) below exists to avoid. Consequences that follow
for free: a tenant can only write inside its own workspace, the assignment is deleted together with
the workspace, and it is backed up together with the workspace's other content.

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
    batchAccessCheck: true
```

A **singleton per platform**, named `cluster`, living in `root:platform-mesh-system`. It is
status-only and written by the active projector — nobody else. It is how the portal, the
`iam-service`, and the `search-service` degrade deliberately instead of guessing or erroring.

| Feature | Meaning | Consumer that needs it |
|---|---|---|
| `hierarchicalInheritance` | A grant on an account also applies to its descendant accounts, without the grant being repeated in each descendant. | `iam-service` / portal: offer "inherited" as an option |
| `instanceScopedRoles` | A role can be granted on one named object (`resourceRef`), not only on a resource type in a workspace. | `iam-service` / portal |
| `transitiveGroups` | Membership of a group that is a member of another group is honoured. | `iam-service` |
| `batchAccessCheck` | The engine can decide access for a **set of candidate objects** — e.g. a page of search hits spanning many workspaces — in a bounded number of calls. OpenFGA provides this as `BatchCheck`, which the `search-service` uses today. Kubernetes RBAC answers one `SubjectAccessReview` per request and has no bulk form. | `search-service`: choose filtering strategy, see [List filtering and search](#list-filtering-and-search--fail-closed) |

### Placement, ownership and access

| Resource | Lives in | Written by | Read by |
|---|---|---|---|
| `RoleDefinition` | the workspace that owns the `target` type — the provider's workspace, next to its `APIExport` (the model of [RFC 010](../rfc/010-provider-permissions-configuration.md)); platform-owned types (accounts) in `root:platform-mesh-system` | the provider, for types its own `APIExport` serves — **never for another provider's types** (RFC 010, decision 4); the platform administrator for platform types | projectors, `iam-service` (role catalog) |
| `RoleAssignment` | the account workspace it grants access in | holders of the role-management permission in that workspace, authorized by kcp like any other write (through whichever engine is active); the `security-operator` for the baseline owner assignment at account creation; the `iam-service` **using the caller's token**, not a service identity | the active projector |
| `AuthorizationCapabilities` | `root:platform-mesh-system` (singleton) | the active projector, status only | `search-service`, `iam-service`, portal |
| `APIExportPolicy` | `root:platform-mesh-system` (unchanged, see below) | the platform administrator | `security-operator`, projectors |

Tenants do **not** define `RoleDefinition`s in v1: they consume the catalog. Tenant-defined roles are
a possible later extension and are out of scope here.

The ownership rule for `RoleDefinition.target` is checkable at admission because the `APIExport` that
proves ownership lives in the same logical cluster as the `RoleDefinition`; the projector re-verifies
it on reconcile and reports `Rejected` rather than projecting. (Cross-workspace uniqueness rules
cannot be enforced by admission, which sees one logical cluster; this ADR avoids designing any.)

Using the caller's token for `iam-service` writes is deliberate. It means a user can only grant what
kcp already lets them write, instead of the `iam-service` holding a broad identity and having to
re-implement that check. It is a behaviour change for the `iam-service`, called out in the component
table.

### kcp access model: least privilege

The projectors must never require a kcp-admin identity: that would cross the boundary between the
platform's control plane and every tenant's workspace. Access is instead granted through APIExports
whose **claims are the blast radius**, following the pattern the `tenancy-operator` already
establishes with two deliberately separate exports:

* [`tenancy-provisioner`](https://github.com/platform-mesh/platform-mesh/blob/main/operators/tenancy-operator/deploy/kcp/resources/apiexport-tenancy-provisioner.yaml)
  — the capability to *make* a workspace;
* [`tenancy-access`](https://github.com/platform-mesh/platform-mesh/blob/main/operators/tenancy-operator/deploy/kcp/resources/apiexport-tenancy-access.yaml)
  — the capability to *write inside* one, including `clusterroles` and `clusterrolebindings`, bound
  through the `WorkspaceType`'s `defaultAPIBindings` so that kcp copies the claims into the binding
  already accepted.

Both declare no resources of their own. The same separation applies here: the API that carries the
*intent* and the capability that lets a component *act on a workspace* are different exports with
different holders.

| Export | Contents | Bound in | Held by |
|---|---|---|---|
| `authorization.platform-mesh.io` | schemas for `RoleDefinition`, `RoleAssignment`, `AuthorizationCapabilities`; **no permission claims** | every account workspace (via `defaultAPIBindings`); `root:platform-mesh-system` binds it itself | both projectors (read, status write), the `security-operator` (create baseline assignments) |
| `authorization-rbac-projection` | **no schemas**; claims only `rbac.authorization.k8s.io` `clusterroles` and `clusterrolebindings` (`get, list, watch, create, update, delete`) | every account workspace via `defaultAPIBindings` — **only in a composition that selects the RBAC engine** | the `rbac-authz-operator` only |

The OpenFGA projector needs the first export and read access to `Account` / `AccountInfo` through the
existing `core.platform-mesh.io` export. It needs **no claim on RBAC objects**. In a composition
that selects OpenFGA the second export exists in no workspace, so its blast radius is zero.

Two honest limits on this:

* **The platform does not have this today for its own exports.** `core.platform-mesh.io` and
  `system.platform-mesh.io` both carry broad `all: true` claims, including on `secrets`. This ADR
  does not change them and does not add a third broad export; it adds exports in the narrow style of
  `tenancy-access`. Narrowing the existing two is separate work.
* **A component that can write `ClusterRoleBinding`s can grant access, whatever the claim list
  says.** The claim limits *which resource types* the projector can touch, not *which roles it can
  bind*. The RBAC projector is therefore a highly privileged component by nature. Whether kcp applies
  RBAC escalation checks to writes made through an APIExport virtual workspace has **not been
  verified** for this ADR and must be established before the RBAC projector ships.

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
| Hierarchical inheritance (org → account → sub-account) | relation walk via `parent` | not natively; would need a binding materialized into every descendant workspace (see below) |
| Instance-scoped relations ("owner of *this* object") | native | only `resourceNames`, no relations |
| Transitive group/team relations | native | not expressible |

The intent API is authored at the intent level, and the gap is handled explicitly:

* `RoleAssignment.spec.inheritance: Inherited` — the OpenFGA projector maps this to a `parent` walk.
  **The RBAC projector does not support `Inherited` in v1.** It sets a `Rejected` condition with
  reason `InheritanceUnsupported` on such an assignment and projects nothing for it. A grant made
  with `Local` applies to the workspace the `RoleAssignment` lives in, and only there.
* Intents an engine cannot express at all are rejected by that engine's projector with a condition —
  not accepted and dropped.
* `AuthorizationCapabilities.status.features` lets consumers adapt before they try: the portal
  offers "inherited" only when `hierarchicalInheritance` is `true`.

This scoping is deliberate, not a deferral of effort. The compositions that select RBAC are the ones
[RFC 008](../rfc/008-platform-mesh-modularization.md) motivates with deployments that "do not need
multiple organizations or nested accounts" — where inheritance down an account tree has no meaning.
Deployments with a real account hierarchy select OpenFGA.

#### Deferred: materialized inheritance under RBAC

Kubernetes RBAC has no inheritance across the workspace tree, so supporting `Inherited` there means
the RBAC projector must write a `ClusterRole`/`ClusterRoleBinding` pair into every descendant
workspace. Given a `RoleAssignment` in `foo` with `inheritance: Inherited`:

```
root:orgs:foo                     RoleAssignment (Inherited)   ← source, in foo
├── account1                      ClusterRole + ClusterRoleBinding written here
│   └── account1-sub1             ClusterRole + ClusterRoleBinding written here
│       └── sub2                  ClusterRole + ClusterRoleBinding written here
└── account2                      ClusterRole + ClusterRoleBinding written here
```

This does not need a *third* export: `authorization-rbac-projection` (above) already claims
`clusterroles`/`clusterrolebindings` and is already bound in every account workspace when the RBAC
engine is selected, which covers the *write* side for both `Local` and `Inherited` assignments. The
`RoleDefinition` a `RoleAssignment` refers to must be projected to a `ClusterRole` in every one of
those workspaces too — a `ClusterRoleBinding` cannot reference a `ClusterRole` in a different logical
cluster. The claim's `defaultSelector` should scope the projector to objects carrying one **constant**
label (e.g. `authorization.platform-mesh.io/managed-by: rbac-authz-operator`), not a per-assignment
value — a `LabelSelector` matches a fixed key/value, not "whichever `RoleAssignment` wrote this". A
second, unselected label (`authorization.platform-mesh.io/source: <sourceCluster>.<sourceName>`)
records provenance for cleanup and plays no part in the claim itself.

What the write side does not solve is **discovery**: the projector must enumerate `foo`'s descendants
to know where to write. `Account` objects for `foo`'s children live inside `foo` itself (per
[Terminology](#terminology-account-and-workspace)), so discovering the full descendant set means
recursively listing `Account` objects, one workspace down at a time — which needs its own read grant
into every account workspace, on top of the write claim above. Whether that read grant is a third,
narrow export (read-only on `accounts.core.platform-mesh.io`) or reuses the existing broader
`core.platform-mesh.io` claims is not decided here; either way it is access the
`openfga-authz-operator` does not need, because OpenFGA's `parent` walk requires no discovery step at
reconcile time.

Four further reasons this stays out of v1, on top of discovery:

1. **Ordering.** A new child must receive its objects *before* it is usable, or a window of missing
   access opens; discovery-then-write must run fast enough relative to account creation for that
   window not to matter.
2. **Lifecycle across workspaces.** Kubernetes owner references do not cross workspaces. Removing or
   changing the source assignment must remove the materialized objects in every descendant, driven by
   the `source` label above and a finalizer on the source `RoleAssignment`.
3. **Drift.** A descendant's administrator can edit or delete a materialized object; the projector
   must reconcile it back, putting the platform in contention with tenant edits in the tenant's own
   workspace.
4. **Cost has no bound.** Writes scale as descendants × assignments, and no depth or width limit
   changes that — a `maxDepth` bounds the tree's *height*, not the number of nodes in it, which is why
   it was dropped from this ADR rather than offered as a false bound.

This sketch resolves the export question the first draft of this ADR left unaddressed, and is enough
to start a follow-up ADR from — but it does not resolve 1–4, and it does not change the
recommendation: `Inherited` stays `Rejected` under RBAC until that ADR exists. Until then the answer
to "how does an assignment in `foo` reach `account1-sub1`?" is: **under RBAC, it does not — an
assignment applies where it lives.**

### `APIExportPolicy` and ADR 002

`APIExportPolicy`'s *shape* is already engine-neutral: an `apiExportRef` plus
`allowPathExpressions`. Its policy semantics, including the deliberate non-inheritance to child
accounts documented in ADR 002's scenarios, are **retained verbatim**.

What changes is decision 3 alone. The `security-operator` stops writing tuples; it resolves path
expressions and records the result in `status.resolvedAccounts`. A projector turns that into engine
state:

* `openfga-authz-operator` — the `bind` tuples exactly as ADR 002 specifies;
* `rbac-authz-operator` — a projection to the `bind` verb on the referenced `APIExport`. **This one
  is not yet designed.** ADR 002 grants binding to *accounts* (through the consumer's store), whereas
  RBAC grants to *subjects* (users and groups) and is evaluated in the *provider's* workspace, where
  the `APIExport` lives. Deciding which subjects in a consumer account hold `bind`, and how that maps
  onto ADR 002's path expressions and its deliberate non-inheritance, is left to the implementation
  ADR for the RBAC projector; see the open decisions.

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

The `search-service` reads `AuthorizationCapabilities`. When `batchAccessCheck` is `false`, it
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
| `rbac-authz-operator` (new) | — | projects to `ClusterRole` / `ClusterRoleBinding` in the workspace of each `RoleAssignment`, through the `authorization-rbac-projection` export only; `Local` assignments only in v1 |
| `iam-service` | YAML role catalog; writes tuples via GraphQL | reads `RoleDefinition`, writes `RoleAssignment` **with the caller's token**; no engine write path |
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
| 4 | `authorization-rbac-projection` export and `rbac-authz-operator`; engine-free compositions enter CI. RBAC escalation behaviour through an APIExport virtual workspace is verified before this phase ships. |

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
* **Under RBAC, an assignment applies only where it lives.** An organization owner does not
  automatically administer sub-accounts; that requires OpenFGA. See the deferred design above.
* The RBAC projector is a highly privileged component: a claim on `clusterrolebindings` bounds the
  resource type, not the roles that can be bound.
* Materialized inheritance, if built, needs a descendant-discovery read path this ADR sketches but
  does not fully specify (see the deferred design above).
* Two new exports, and a `defaultAPIBindings` change on every account `WorkspaceType`, are part of
  the composition machinery the `pm-operator` must drive.
* A superseded, approved ADR (002) and an in-flight RFC (010) both require follow-up work.

### Confirmation

* CI composition tests: at minimum one with the OpenFGA projector and one with the RBAC projector,
  both creating an organization, an account, and a role assignment.
* A projector conformance suite: one intent fixture set, asserted per engine, with the expected
  `Degraded` conditions where a capability is absent.
* A lint gate asserting that `golang-commons/fga` is not on the import path of the
  `security-operator` or the `search-service`. Mechanically checkable, unlike a documented intent.
* `Store`/`AuthorizationModel` absent from a `kubectl api-resources` listing in an RBAC composition.
* A test asserting that the `authorization-rbac-projection` export is bound in **no** workspace in an
  OpenFGA composition, and that its claims are exactly `clusterroles` and `clusterrolebindings`.
* A test asserting that an `Inherited` assignment under the RBAC projector is `Rejected` with
  `InheritanceUnsupported` and produces no binding in any workspace.

## Open decisions for the TSC

1. **RFC 008 amendment.** Adopt "a single projector per engine" in place of "a single reconciler
   (IAM Service)"?
2. **RBAC inheritance.** Declare `Inherited` unsupported under RBAC in v1 (recommended — the sketch
   above resolves the export question but leaves discovery, lifecycle, drift and cost open), or
   commit to materialization now via a follow-up ADR building on that sketch?
3. **RFC 010 sequencing.** Align `ProviderPermissions` before it merges (recommended), or ship it as
   specified and break the provider API later?
4. **Deprecation window** for `Store` / `AuthorizationModel` in `core.platform-mesh.io`.
5. **`AuthorizationCapabilities` shape.** A status-only singleton in `root:platform-mesh-system` as
   proposed, or fold the same information into the `PlatformMesh` resource's status?
6. **Escalation prevention for `RoleAssignment` writes.** Whoever may create a `RoleAssignment` can
   grant any role in that workspace, including `owner`, to themselves. Kubernetes prevents this for
   `RoleBinding`s; nothing does for this resource. Options: an admission check against the requesting
   user's own role, or a projector-side check. Not designed here, and it must be before the resource
   is writable by tenants.
7. **RBAC projection of `APIExportPolicy`.** Which subjects hold `bind`, given RBAC grants to
   subjects in the provider's workspace where ADR 002 grants to accounts?
8. **Tenant-defined roles.** Out of scope for v1 (tenants consume the catalog). Confirm.

## References

* [RFC 008 — A Modular Framework for Platform Mesh](../rfc/008-platform-mesh-modularization.md)
* [RFC 010 — Provider Permissions Configuration](../rfc/010-provider-permissions-configuration.md)
* [ADR 002 — Fine-Grained Access Control for APIExport Binding](002-apiexport-binding-access-control.md)
* [ADR 011 — MCP Server for kcp and Platform Mesh](011-mcp-server-for-kcp-and-platform-mesh.md)
* [ADR 014 — Authentication API Surface and Provisioning Modes](014-authentication-api-surface-and-provisioning-modes.md)
