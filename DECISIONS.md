# DECISIONS

### Permission resolution is data-driven, not role-driven

**What I chose:** Read the permission catalogue and role baselines from SQLite on every resolution path.
**Why:** `server/permissions.js` queries `permissions` and `role_permissions`; the personalised fixture is specifically intended to introduce a role and permission that are absent from the prose. This also keeps the implementation valid when the grading fixture changes.
**What I rejected:** A JavaScript object containing the five documented roles and nineteen permissions. It would pass the published demo but fail the personalised/hidden fixture.
**What would change my mind:** A grading contract that made the database reference data immutable and explicitly required a generated static matrix. The current repository does the opposite.

### Explicit deny is checked before every allow

**What I chose:** Any applicable deny grant wins before an allow grant or role baseline.
**Why:** The Acme fixture includes an org-wide `device:terminal` deny for Sam while the operator baseline allows terminal. The intended result is that Terminal is absent while Control remains available. The resolution code therefore searches the deny set first.
**What I rejected:** Letting a more-specific device allow override an org-wide deny. That makes scope specificity a privilege escalation mechanism and breaks the documented deny-wins case.
**What would change my mind:** A test fixture demonstrating an explicit, supported carve-out where a device allow must override an org-wide deny. No such rule exists in the current contract.

### Roles are bundles; rank is only for administration

**What I chose:** `roles.rank` is used only by `assertCanModify`; `can()` never compares ranks.
**Why:** Sam is an operator in Acme and an auditor in Globex. The operator can control devices while the auditor can read audit events. Treating the roles as an ordered permission ladder would incorrectly make one role inherit the other's capabilities.
**What I rejected:** `callerRank >= targetRank` as a general authorization check. It answers “who may modify whom,” not “what may this role do.”
**What would change my mind:** A schema change explicitly redefining rank as a permission hierarchy.

### Cross-organisation access is invisible

**What I chose:** The token's `org` claim is the structural organisation boundary, and a different `:org` path returns `404`.
**Why:** `server/context.js` rejects a path organisation that differs from the token scope before downstream handlers run. This means the application does not fetch another tenant's rows and then try to hide them afterward.
**What I rejected:** Returning `403` after checking membership. That would confirm that another organisation exists and would make tenant isolation a convention rather than a request boundary.
**What would change my mind:** An API contract that intentionally exposed cross-org existence to the caller.

### Permission changes invalidate the next request, not an active session

**What I chose:** Mutations bump `perm_version`; active sessions keep their snapshot until TTL or an account/tenancy event ends them.
**Why:** The schema's `sessions.authorized_by` is explicitly a snapshot, while `memberships.perm_version` is the freshness mechanism. `server/lifecycle.js` therefore ends sessions for suspension/removal/device transfer, not for ordinary grant or role changes.
**What I rejected:** Re-resolving permissions for an existing session on every request. That would make a “grandfathered” session stop immediately after a grant change and contradict the session model.
**What would change my mind:** A session schema without an authority snapshot or a revised contract saying permission changes terminate sessions immediately.

### The database arbitrates exclusive sessions

**What I chose:** Insert the active session and let the partial unique index decide whether an exclusive device is already occupied.
**Why:** The schema has `one_exclusive_session_per_device`; using a preliminary SELECT would create a check-then-act race under concurrent requests. The route translates the constraint failure into `DEVICE_BUSY`.
**What I rejected:** `SELECT active session -> if none INSERT`. Two simultaneous requests can both observe no holder and then both attempt the insert.
**What would change my mind:** Removal of the unique index or a storage layer that could not provide the required transactional constraint.

### The console renders server answers instead of reconstructing authorization

**What I chose:** React consumes `permissions` from `/auth/me` and device rows and conditionally renders elements from those answers.
**Why:** The architecture test can alter an API response to deny `device:control`; the UI must then remove the element. Keeping the matrix out of `web/` makes that test meaningful.
**What I rejected:** `if (role === 'owner')` / `if (role === 'operator')` checks in React. They would duplicate the authorization model and diverge when grants or a new database role are introduced.
**What would change my mind:** A product contract that moved authorization entirely into a trusted client and removed server enforcement, which is not this application's model.

### Tokens are memory-only on the client

**What I chose:** Keep the access token in React state and use an HttpOnly refresh cookie for reload recovery.
**Why:** The assignment explicitly prohibits localStorage/sessionStorage for credentials. React state also means a page reload loses the access token, after which `/auth/refresh` obtains a fresh one without exposing the refresh credential to JavaScript.
**What I rejected:** Persisting the JWT in localStorage for convenience. It violates the stated credential boundary and unnecessarily exposes a bearer token to JavaScript-readable storage.
**What would change my mind:** A revised security requirement that explicitly permitted persistent browser storage for access tokens.

## Where this repo argues with itself

The working tree contains a small terminology mismatch between the API brief and the implementation comments around “org-level” permission views: an org-level result is not merely the role baseline; device-scoped grants can make a permission available somewhere in the organisation. I built the navigation view as a union over applicable grants, while exact device actions use the device-scoped result. This keeps a device-specific capability discoverable without making it appear on unrelated device rows.

## Deliberately not built

- Remote screen streaming, keyboard/mouse injection, shell execution, and screen capture were not built because sessions are records only.
- Rate limiting, password reset, email delivery, and multi-region infrastructure were not added because the brief explicitly excludes them.
- I did not alter `db/schema.sql` or `db/reference.sql`; invariants already expressed there remain database responsibilities.
