BUILD-LOG

Phase 0 — orientation

Prediction: I initially expected the existing starter to be enough to begin running the verification suites. The first practical blocker was the native better-sqlite3 dependency: npm ci could not use a Node 24 prebuilt binary and fell back to node-gyp, which failed because the required Visual Studio C++ build tools were not installed.

What I learned: I verified the database driver separately with better-sqlite3@12.10.0; the check returned SQLite OK, which gave me a working local database path without changing the application architecture.

Open point from the repository: the personalised check was designed to introduce database roles/permissions not present in the prose. I therefore treated SQLite as the source of truth for roles, permissions, and grants instead of creating a JavaScript role matrix.

Phase 1 — token verification

I implemented the verifier in server/auth.js and ran node scripts/check-jwt.js: 43 passed, 0 failed.

Wrong implementation detail caught while reasoning about the verifier: timingSafeEqual cannot safely be called on buffers of different lengths. I added a length check before comparing the signature bytes.

I validate the JWT header before accepting the algorithm, verify the HS256 signature, and then validate the claims. This keeps alg: none and algorithm-substitution paths out of the accepted path.

The useful measurement here was the complete JWT suite result: 43/43, rather than relying on a single happy-path token.

Phase 2 — caller context and permission resolution

Decision I had to settle: whether role names/ranks should directly determine permissions. I rejected that model because the personalised database contains an additional role and permission. The resolver instead reads permissions, role_permissions, permission_patterns, memberships, and grants at runtime.

I made the organisation in the access token the request boundary. server/context.js checks the URL organisation against the token scope before downstream permission resolution.

Bug found in my own implementation: assertCanStartSession was resolving the same device twice. I removed the duplicate lookup so the compound check uses one resolved device set while preserving separate missing_permission and missing_device_permission outcomes.

The final permission suite measured 35 passed, 0 failed.

Phase 3 — orgs, members, and invites

I kept role/member lifecycle rules in server/lifecycle.js so role changes, suspension, removal, and owner protection use the same invariant instead of separate route-specific checks.

Open point I had to settle: whether an accepted invite should remain reusable and what status the acceptance endpoint should return. The API verification established the expected behaviour, so the invite route was adjusted to return the expected successful status and conflict on reuse.

Invite tokens are generated once and stored as hashes; the raw token is returned only from the creation response and is not written to the audit log.

The final Playwright test an invite link can be redeemed passed.

Phase 4 — devices and grants

The device list uses server-resolved permissions. A device without device:view is omitted rather than rendered as a redacted row.

I changed the device resolution path to use resolveDevices, allowing the grant information to be resolved as a batch rather than issuing a separate grant lookup for every device row.

Database guarantee I relied on: grant permission validation ultimately uses the database permission-pattern data and foreign-key enforcement. The route maps an unknown permission pattern to 400 unknown_permission instead of maintaining a second hardcoded permission list.

The final UI tests covered device-scoped grants, org-wide deny precedence, grant listing, and creating a grant through the UI.

Phase 5 — sessions

Session creation checks the general session:start permission separately from the mode-specific device permission. This preserves the distinction between missing_permission and missing_device_permission.

Decision reversed: I did not implement exclusive-session protection as SELECT active session -> INSERT. The database already has the partial unique index one_exclusive_session_per_device; relying on that constraint avoids a check-then-insert race.

The route translates the resulting SQLite constraint failure into 409 DEVICE_BUSY.

sessions.authorized_by is treated as the authorization snapshot for an active session. Ordinary permission changes do not rewrite that snapshot; suspension, membership removal, and device-tenancy changes are handled as session-ending lifecycle events.

Phase 6 — audit

Denied permission-gated operations are recorded through auditDenials, while successful mutations are recorded after the mutation succeeds.

I deliberately did not create application update/delete helpers for audit events. The schema triggers provide the storage-level protection, so the application treats audit events as append-only.

The relevant design check is therefore not an application-side delete guard but whether the database invariant remains intact.

Phase 7 — console and UI verification

The React console does not contain a role-to-permission matrix. It consumes permission objects returned by /auth/me and the device API.

Bug found by the Playwright suite: the device:control permission attribute was initially present on both the informational capability chip and the Control button. The test auditor and operator see different cards and the related device tests reported Expected: 1, Received: 2. I removed data-permission="device:control" from the informational chip and kept it on the actual Control button.

That fix exposed a second UI-contract detail: device:terminal still needed its own data-permission attribute. The test a grant created through the UI surfaces the item it grants reported Expected: 1, Received: 0. I restored the attribute for non-control permission chips while leaving the Control selector unique.

Measured result: after those fixes, the Playwright suite went from 19/25, to 24/25, to the final 25/25.

The invite flow also had a UI-state bug: after successful acceptance it showed a static “Invite accepted” message, while the test expected the normal login-form. I changed the successful state to render the sign-in form; an invite link can be redeemed then passed.

Access tokens remain in React state. Reload recovery uses the HttpOnly refresh cookie, and the test no token is persisted in web storage passed.

Phase 8 — Windows/runtime hardening

Environment-specific failure: the original scripts/load-db.js used new URL(...).pathname, which produced a path form that failed on Windows. I changed the path handling to use fileURLToPath.

After that change, npm run db:reset completed and reported the seeded counts: 3 organizations, 8 users, 10 memberships, 9 devices, 6 grants, 3 sessions, 7 audit events, 20 permissions, and 27 patterns.

npx playwright install chromium completed successfully.

npm run build passed with Vite 6.4.3.

Final verification

All supplied automated verification completed successfully:

JWT: 43/43 passed

Permissions: 35/35 passed

API: 66/66 passed

Personalisation: 18/18 passed

Production build: PASS

Playwright UI: 25/25 passed

Final Playwright runtime: 18.2 seconds

The remaining work is repository hygiene, preserving genuine incremental Git history, pushing the candidate repository publicly, and completing the submission form.