# BUILD-LOG

## Phase 0 — orientation

- The starter initially had every `/v1` route unregistered and the permission/auth modules were explicit stubs.
- I first treated the database tables as the model instead of copying the role matrix into application code; the personalised check is designed specifically to catch that mistake.
- One practical constraint showed up immediately: `better-sqlite3` is a native dependency, so local verification depends on a successful `npm ci` before the API suites can run.

## Phase 1 — token verification

- I implemented the verifier in `server/auth.js` and ran `node scripts/check-jwt.js`: **43 passed, 0 failed**.
- A small implementation detail mattered: `timingSafeEqual` throws when buffers have different lengths, so the signature check compares lengths before calling it.
- The verifier reads and validates the header before using the HS256 key, then verifies the signature, then validates the claims. This keeps `alg: none` and algorithm substitution out of the accepted path.

## Phase 2 — caller context and the resolution engine

- I kept organisation scope in the token and checked the URL organisation against that claim before any permission decision; a mismatch becomes the same 404 path as an invisible resource.
- The first implementation of `assertCanStartSession` resolved the same device twice. I removed that duplicate lookup so the compound check uses one resolved set and still returns two distinct failure reasons.
- The resolution engine reads `permissions`, `role_permissions`, `permission_patterns`, `memberships`, and live grants at runtime. The personalised check therefore does not depend on the documented five-role matrix.
- I implemented the precedence as: inactive/suspended identity gate, explicit deny, allow grant, role baseline, implicit deny. Device-scoped grants are considered in the exact device question; the org-level view is a union used for navigation.

## Phase 3 — orgs, members, invites

- Role changes and membership status changes bump `perm_version`; the next request therefore detects a stale token instead of waiting for JWT expiry.
- I kept the last-owner rule in one lifecycle helper because role change, suspension, removal, and self-leave all have the same invariant.
- Invite tokens are generated once and stored only as hashes. The raw token is returned from the creation endpoint and is never written to the audit log.

## Phase 4 — devices and grants

- The device list uses the server-resolved permission set for each row. A device without `device:view` is filtered out rather than rendered with redacted data.
- I changed the list path to use `resolveDevices` so the grant query is batched rather than performing a separate grant query for every device row.
- Grant validation uses the database foreign key for the final permission-pattern check and maps an unknown pattern to `400 unknown_permission`; the connection already enables `foreign_keys` in `server/db.js`.

## Phase 5 — sessions

- Session creation checks `session:start` and the mode-specific device permission separately. This preserves the required distinction between `missing_permission` and `missing_device_permission`.
- The database's partial unique index is the concurrency guard for exclusive sessions. The route translates the resulting SQLite constraint failure into `409 DEVICE_BUSY` rather than doing a check-then-insert race.
- Session authority is snapshotted in `authorized_by`. Permission changes do not terminate active sessions; suspension, membership removal, and device tenancy changes do.

## Phase 6 — audit

- I record denied permission-gated operations through `auditDenials` and successful mutations at the point the mutation succeeds.
- I did not add update/delete helpers for audit events. The schema triggers are the storage-level protection, so the application only appends.

## Phase 7 — the console

- The React console does not contain a role-to-permission matrix. It renders the permission objects returned by the API.
- During the UI pass I caught an implementation bug before testing: I had put `data-permission` on both a capability chip and its Control button, which would have made the contract selector return two elements. I removed the attribute from the informational chip so the button is the single permission-gated control.
- Access tokens are kept in React state. Refresh is performed through the `HttpOnly` cookie, with no localStorage or sessionStorage persistence.

## Phase 8 — hardening

- `node --check` passes for the newly written server modules.
- The JWT suite is green at 43/43. Full SQLite/API/Playwright execution is pending the native `better-sqlite3` build completing in this environment.
- I deliberately did not add remote-control functionality, shell execution, screen capture, or other features outside the assignment's stated record-only session model.

## Open threads

- The final submission still needs to be placed into the candidate's own Git repository with genuine incremental commits and pushed publicly before the deadline.
- Full API and Playwright suites must be run on a machine where `npm ci` completes successfully; the code should not be treated as fully verified until those suites are green.
