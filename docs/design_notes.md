# Design Notes & Architecture Decisions

## 1. Collect / Analyze Separation
Collection and analysis are decoupled by design:
- `collect.py` connects to the AWS IAM API using standard SDK credential resolution and extracts raw entity structures into a snapshot file.
- All analysis modules (`graph.py`, `assume_role.py`, `attack_path.py`, `analysis.py`, `api.py`) operate purely on in-memory representations or snapshot files. They make zero live AWS calls and never require credentials.

## 2. Snapshot Format v1
Snapshots are structured JSON files adhering to `schema_version: 1`:
- `schema_version`: Integer specifying format compatibility (current: `1`).
- `meta`: Metadata dictionary containing `account_id`, `created_at` (ISO-8601 UTC), `prefix`, and `tool_version`.
- `inventory`: Serialized `IAMInventory` containing lists of users, groups, roles, customer-managed policies, and entity relationships.
- `permission_map`: Dictionary mapping identity ARNs to lists of resolved `EffectivePermission` records with full `via` delegation chains.

## 3. Attack View Allowlist
The attack view (`attack_view`) isolates traversable escalation paths from non-traversable administrative relationships:
- Node filter: Only nodes of type `User` and `Role` are included. Groups, policies, and service principals cannot execute actions or assume roles directly and are omitted from attack graph traversal.
- Edge filter: Only edges with the key `can-assume` (defined in `TRAVERSABLE_EDGE_TYPES`) are traversable. `trusted-to-assume`, `member-of`, and `attached-policy` relationships are foundational for authorization calculations but do not constitute executable escalation hops on their own.

## 4. Node Classification Rules
The `classify_node_type(identifier)` engine in `graph.py` assigns types to relationship targets and sources not present in the inventory:
1. `*` -> `Wildcard`
2. Non-ARN identifiers ending in `.amazonaws.com` or `.amazonaws.com.cn` -> `Service`
3. ARNs with IAM namespace and `policy/` resource path -> `Policy`
4. Root account identifiers, external AWS account principals, unmanaged roles, and malformed strings -> `External`

## 5. Known Limitations
- **Plausible Access Model:** Explicit Deny statements, Condition blocks, Permission Boundaries, and AWS Organizations Service Control Policies (SCPs) are not evaluated.
- **Shortest Path Only:** `find_reachable` uses Dijkstra/BFS shortest path semantics. When multiple paths exist between a source and target, one shortest path is returned; alternative paths are not enumerated.
- **Inline Policies:** Current enumeration collects attached managed policies. Inline policies embedded directly inside user, group, or role resources are enumerated but not yet expanded into the effective permission resolver.
- **AWS-Managed Policies Scope:** `enumerate_policies` defaults to `Scope='Local'` (customer-managed). Referenced AWS-managed policies (e.g., `AdministratorAccess`) attached to roles are parsed when encountered via attached policy enumeration, but the catalog is not pre-enumerated globally.

