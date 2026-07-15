# External TestFlight beta and metadata/privacy review — M6

## Entry contract

Enter external beta only when the same signed release has immutable `REL-001`, `REL-002`, `REL-003`, `REL-008`, and `REL-004` artifacts:

```text
Evidence/manifests/m6-readiness.json                 REL-001
Evidence/runtime/REL-002.json                        predeploy-disabled
Evidence/runtime/REL-003.json                        compatibility
Evidence/runtime/REL-008.json                        PITR proof
Evidence/runtime/REL-004.json                        internal alpha
```

Their tag, commit, release ID, dataset SHA, migration SHA, and source checksums must match the protected release job. Neither a local metrics JSON nor a deterministic test record can replace an App Store Connect, Supabase audit/RPC/RLS/revoke, privacy-safe telemetry, or protected synthetic source. Fixtures are negative tests only and must never be supplied as a source manifest.

Only Product, Security, and Ops are approval roles. Every named approval below is a fresh, immutable record with exactly one distinct, current active member from each role. A workflow environment reviewer, Release Engineering, QA, a prior approval, or a second person from an existing role is not a fourth approval or a substitute.

## Ratify non-waivable floors before beta

Product, Security, and Ops first post fresh canonical approval comments on the protected release Issue. The protected job verifies each current active team membership and then writes the one allowed threshold approval path:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate threshold \
  --issue-url "$RELEASE_ISSUE_URL" \
  --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" \
  --manifest-sha "$READINESS_SHA" \
  --transition threshold-ratification \
  --metric-sha "$REL_004_SHA" \
  --output Evidence/runtime/approvals/threshold.json
```

The protected `threshold-ratification` gate validates that approval and writes `Evidence/runtime/OPS-005.json`. `OPS-005` may preserve or tighten floors only; it cannot lower a value, omit a source/window/denominator, add an exclusion outside the approved list, or waive a P0/P1/zero-tolerance result.

For the `REL-005` beta source, all of these immutable minimums apply to a continuous **at-least-seven-day (>=7d)** window:

| Metric | Required beta floor |
|---|---:|
| Crash-free sessions | at least 99.5% |
| Map p95 | at most 2.5 s |
| Bootstrap p95 | at most 3.0 s |
| Authentication success | at least 99.0% |
| Bootstrap success | at least 99.0% |
| Manual mutation success | at least 99.0% |
| P0 | 0 |
| Unresolved P1 | 0 |
| Authentication bypass | 0 |
| Raw GPS persistence | 0 |

The only permitted exclusions are user cancellation, intentional offline-pending work, generic blocked lookup denial, and intended fail-closed unavailability. Missing source data, an incomplete seven-day window, a changed denominator, any lower floor, an unapproved exclusion, a P0, or unresolved P1 is a hard stop and must create no `REL-005`, RC, M6-EXIT, or phase artifact.

## Run external beta

1. **Ops** performs the human-only App Store Connect action to submit the exact internal-alpha build to external TestFlight beta and records the real TestFlight build/version identity in the protected source manifest. Do not use a local API response, simulator, fixture, or copied alpha receipt as proof.
2. **Product** owns tester recruitment and the customer-facing beta feedback channel. **Security** verifies that the beta charter exercises authorization, generic blocked friend-code responses, revocation fail-close, social zeroization, manual GPS fallback, and no raw-GPS persistence. These are release observations, not a weaker approval model.
3. Keep the beta live for at least seven complete days. Ops obtains the protected App Store Connect crash/build source, Supabase audit/RPC/RLS/revoke source, privacy-safe telemetry source, and protected synthetic source; their exact query/window/denominator/exclusions/checksums form `Evidence/manifests/observed-beta.json`.
4. The protected `external-beta` gate invokes the floor validator; it writes only the live runtime artifact:

```bash
Scripts/release/validate-runtime-floors.py \
  --id REL-005 \
  --source-manifest Evidence/manifests/observed-beta.json \
  --threshold Evidence/runtime/OPS-005.json \
  --schema Docs/evidence/schemas/threshold-ratification.schema.json \
  --output Evidence/runtime/REL-005.json
```

`REL-005` is the beta-floor pass, not merely a metrics export. A checksum-valid source that is below a fixed floor fails. The validator must fail closed and leave no output, manifest, or transition on all rejection paths.

## Metadata and privacy review

In parallel with the seven-day beta, Product and Security complete a real App Store Connect metadata/privacy review for the exact release version:

1. **Product** enters the App Store name, subtitle, description, support URL, screenshots, age rating, review notes, and release contact in App Store Connect. The text must not promise public profiles, contact/email/phone/username discovery, persistent/offline friend data, mandatory GPS, anti-cheat, or a server-side downgrade capability.
2. **Security** compares the live App Store privacy answers, purpose strings, account deletion/support material, Sign in with Apple configuration, and data-collection disclosure against the signed build and backend behavior. Raw GPS samples are transient and discarded; privacy metadata must not claim raw location persistence. Friend-code lookup is named-only and generic-unavailable for missing, blocked, and rate-limited requests.
3. **Ops** captures the protected App Store Connect version/build response and the reviewed metadata/privacy source hashes. The protected `metadata-review` gate writes `Evidence/runtime/REL-006.json` only when the live version/build, tag, commit, disclosure review, and source checksums all match.

`REL-006` requires the protected Apple source. A local plist, static metadata draft, screenshot, fixture, or passing UI test does not satisfy it. A changed disclosure or build invalidates the review; update the live App Store record, collect a new source, and rerun the protected gate rather than editing a prior receipt.

## Exit and no-substitution rules

External beta can feed final RC only when both `REL-005` and `REL-006` exist for the same release and `REL-005` is a current seven-day floor pass. `REL-004` cannot substitute for `REL-005`; threshold approval cannot substitute for the runtime floor pass; metadata review cannot substitute for privacy behavior; and M3 preflight `AUTH-005-PREFLIGHT*` cannot substitute for final RC authentication evidence.

A beta or metadata problem is contained under `incident-containment.md`. Do not remotely downgrade an installed app or relax DML/RLS/auth/privacy/revocation checks to preserve beta availability. Use stop/hold, remove from TestFlight when appropriate, fail closed, preserve queued self writes, and ship only a forward-compatible hotfix.
