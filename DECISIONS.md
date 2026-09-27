
DECISIONS
Permission resolution is data-driven, not role-driven
What I chose: Read the permission catalogue and role baselines from SQLite on every resolution path.

Why: The personalised verification introduces database data that is not safe to represent as the documented role matrix. The implementation therefore reads permissions, role_permissions, permission_patterns, memberships, and grants at runtime. The final personalisation suite passed 18/18, which is evidence that the resolver is using the runtime data rather than only the prose matrix.

What I rejected: A JavaScript object containing the documented roles and permissions. That would make the application depend on a static copy of the fixture.

What would change my mind: A future grading contract that explicitly made the database reference data immutable and required a generated static authorization matrix.

Explicit deny is checked before an allow
What I chose: An applicable deny grant is resolved before an allow grant or role baseline.

Why: The implementation had to handle the seeded org-wide deny case without allowing another applicable allow to make the denied capability appear. The Playwright test an org-wide deny removes the entry the baseline granted passes with the denied control absent, while the device permission tests also verify that unrelated permissions remain available.

What I rejected: Letting a more-specific allow automatically override an org-wide deny.

What would change my mind: A fixture or test explicitly establishing that scope specificity is an approved exception to deny precedence.

Roles are bundles; rank is only for administration
What I chose: roles.rank is used for administration/lifecycle checks, while permission resolution uses the role's permission rows.

Why: The same user can have different roles in different organisations. The Playwright test auditor and operator see different cards verifies that Sam's operator permissions in Acme and auditor permissions in Globex produce different UI capabilities. Treating rank as an inherited permission ladder would collapse those distinct bundles.

What I rejected: A general callerRank >= targetRank authorization rule.

What would change my mind: A schema change explicitly defining role rank as a permission inheritance hierarchy.

Cross-organisation access is invisible
What I chose: The token's organisation claim is the structural tenant boundary, and a request for a different organisation follows the 404 path.

Why: server/context.js checks the path organisation before downstream resource resolution. The UI test no other org's content appears anywhere in the DOM also verifies that switching organisations does not leave the previous organisation's device content in the rendered page.

What I rejected: Fetching another organisation's data first and relying on downstream UI filtering, or returning a cross-org 403 that would reveal that the tenant exists.

What would change my mind: An API contract that intentionally exposed cross-organisation resource existence.

Permission changes invalidate the next request, not an active session
What I chose: Membership/role lifecycle mutations bump perm_version; active sessions keep their authorization snapshot unless an account or tenancy event ends them.

Why: The implementation uses memberships.perm_version for access-token freshness and sessions.authorized_by as the session snapshot. This separates current permission resolution from the authority already recorded for an active session.

What I rejected: Re-resolving every permission on every active-session request.

What would change my mind: A revised session contract that explicitly required live permission re-evaluation for every active session operation.

The database arbitrates exclusive sessions
What I chose: Let the database partial unique index reject a second exclusive session.

Why: The schema's one_exclusive_session_per_device constraint is a concurrency guarantee. A preliminary SELECT followed by INSERT would leave a race between the two operations. The route translates the resulting SQLite constraint failure into 409 DEVICE_BUSY.

What I rejected: SELECT active session -> if none INSERT.

What would change my mind: Removal of the unique constraint or a storage layer that could not enforce the invariant transactionally.

The console renders server answers instead of reconstructing authorization
What I chose: React renders from permission objects returned by the API rather than maintaining its own role matrix.

Why: The architecture test an element vanishes when the server withdraws the permission modifies the devices API response so device:control is denied and then remounts the view. The control must disappear. That test would be meaningless if the UI independently reconstructed authorization from the user's role.

What I rejected: if (role === 'owner') / if (role === 'operator') checks in React.

What would change my mind: A product contract that intentionally moved authorization decisions into a trusted client, which is not the current architecture.

Tokens are memory-only on the client
What I chose: Keep the access token in React state and use the HttpOnly refresh cookie for reload recovery.

Why: The UI test no token is persisted in web storage passes, and a reload restores the session from the refresh cookie also passes. This gives reload recovery without putting the bearer access token in localStorage or sessionStorage.

What I rejected: Persisting the JWT in localStorage for convenience.

What would change my mind: A revised security requirement that explicitly permitted persistent browser storage for access tokens.

Permission selectors belong to the actual UI capability
What I chose: Keep data-permission="device:control" on the actual Control button only, while keeping permission attributes on other informational chips that are directly asserted by the UI contract.

Why: The first Playwright run exposed a concrete bug: selectors for device:control resolved to 2 elements instead of 1. After removing the attribute from the Control chip, five UI failures were eliminated. The next run exposed the complementary requirement for device:terminal, where the test expected 1 element and received 0. The final implementation distinguishes the actionable Control button from the other capability chips.

What I rejected: Putting the same permission selector on both a capability indicator and its actionable control.

What would change my mind: A revised UI contract that explicitly required both the indicator and control to carry the same permission selector.

Where this repo argues with itself
The implementation comments and API terminology have a small ambiguity around “org-level” permission views. An organisation-level navigation result is not only the role baseline: a device-scoped grant can make a capability available on one device. I therefore treat the organisation-level result as a union useful for navigation, while exact device actions use the device-scoped result. This is reflected in the device-scoped Playwright tests rather than being inferred from a role matrix.

Deliberately not built
Remote screen streaming, keyboard/mouse injection, shell execution, and screen capture were not built because sessions are records only.

Rate limiting, password reset, email delivery, and multi-region infrastructure were not added because they are outside the assignment scope.

I did not alter db/schema.sql or db/reference.sql to move application invariants into code; the existing database constraints remain database responsibilities.

Final evidence
node scripts/check-jwt.js: 43 passed, 0 failed

node scripts/check-permissions.js: 35 passed, 0 failed

node scripts/check-api.js: 66 passed, 0 failed

node scripts/check-personalisation.js: 18 passed, 0 failed

npm run build: passed

npx playwright test: 25 passed, 0 failed