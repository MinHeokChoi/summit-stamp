# Incident containment, PITR, tabletop, and communications — M6 to M7

## Severity, command authority, and timing

**P0** is a confirmed authentication or privacy exposure, raw GPS persistence, direct base-table DML path, data corruption, or unsafe outage. The Incident Commander must immediately stop the affected TestFlight/App Store promotion and invoke containment. No approval collection, metric window, or normal change window delays that action.

**P1** is a contained correctness or availability incident. **Product and Ops** must place the release on hold within four hours (<=4h). Security joins whenever the incident could involve authorization, privacy, GPS, social data, revocation, audit evidence, or a provider control. The hold remains until the protected incident record proves resolution and the normal release gates are satisfied again; a P1 is not self-cleared by an elapsed timer.

**Material burn** is any P0, any zero-tolerance incident, or two consecutive below-floor production phase windows. Material burn stops further rollout and triggers this runbook even when the current percentage remains technically available.

The roles are fixed:

| Role | Incident responsibility |
|---|---|
| Product | Declares customer-impact hold, owns status and release messaging, and joins P1 hold within four hours. |
| Security | Classifies security/privacy exposure, preserves audit evidence, verifies authorization is not weakened, and approves security-sensitive containment. |
| Ops | Stops/holds the release in protected consoles, operates provider controls and PITR, preserves runtime evidence, and maintains the incident timeline. |
| Incident Commander | Coordinates the above roles; cannot replace their approval identity or create a release approval alone. |

There are exactly three approval roles—Product, Security, Ops. Incident authority does not create an alternate fourth role, five-owner model, or a way to reuse an old approval. Human-only provider actions remain human-only if a protected console, credential, or workflow is unavailable; fail closed and record unavailability rather than fabricating a receipt.

## Immediate stop and containment procedure

1. **Ops** records the release ID, signed tag, commit, current canonical transition event SHA/sequence, App Store percentage, build/version, detection time in UTC, and protected source links in the incident Issue. The source can be App Store Connect, Supabase audit/RPC/RLS/revoke, privacy-safe telemetry, protected synthetics, or GitHub protected workflow data. Do not place raw GPS, tokens, credentials, email, phone, or friend-code values in the Issue.
2. **Ops** immediately stops the ongoing phased-release advance or removes the app from sale when the P0 blast radius requires it. This is a real App Store Connect action. A local command, test, screenshot, fixture, mocked Apple response, or state file does not prove that Apple stopped distribution.
3. **Ops** sets the server/app containment configuration to fail closed without changing authority. **Security** verifies direct base-table DML remains denied, RLS remains defense-in-depth, the fixed-search-path security-definer RPC set remains narrow, JWT actor derivation remains enforced, and revocation still terminates access.
4. **Product** posts the customer-facing holding message under the communications procedure below. For P0, do this without waiting for root cause. For P1, do it no later than the four-hour hold deadline when users are affected.
5. Preserve the immutable release artifacts and append-only audit data. Do not edit a prior approval, RC, M6-EXIT, event, metric source, or incident evidence file to make a gate pass. If a correction changes tag/commit/build/source binding, release a forward-compatible hotfix under a new signed release lineage.

## Kill-switch doctrine: contain without reducing authority

Containment behavior is constrained by the product authorization contract:

| Surface | Required containment behavior | Forbidden response |
|---|---|---|
| Self writes | A write pause returns explicit retry/unavailable and preserves the encrypted manual outbox queue; no automatic discard. | Deleting queued self writes, silently acknowledging them, or opening direct DML. |
| Social/friend data | Immediately zeroize in-memory friend data and fail closed on event/loss/gap/lifecycle/403/expiry. | Caching/persisting friend bytes, returning stale social data, or extending the 30-second lease. |
| GPS | Disable advisory GPS completion and leave manual completion available. Raw samples remain transient and are discarded. | Requiring GPS, storing raw GPS, or treating GPS failure as a denial of manual completion. |
| Friend-code lookup | Return only the generic unavailable response for missing, blocked, rate-limited, or containment-disabled lookup. | Revealing whether a code exists, exposing a blocked account, or enabling email/phone/username/contact/public-profile search. |
| Migration/data contract | Keep deny-preserving schema/RPC state and fail closed. | Remote downgrade, destructive rollback that weakens compatibility, relaxation of RLS/auth/DML/privacy/revocation, or runtime catalog replacement. |

There is no remote downgrade for an installed App Store build. The allowed recovery set is: contain, stop/hold, remove from sale, fail closed, preserve queued self writes, and ship a forward-compatible hotfix. A purported “rollback” that disables authorization, restores a weaker server behavior, removes audit history, or changes the fixed 100-mountain dataset is not containment and must not be executed.

## Protected PITR proof and recovery

`REL-008` is the protected pre-release PITR proof, not a local database restore. Its immutable source is `Evidence/manifests/observed-pitr.json`, containing the protected provider restore receipt plus `MIG-005` and restored grants/RPC/projection/history/audit checks. It is bound to a fresh exactly-three-role approval at `Evidence/runtime/approvals/pitr-proof.json` and the prior `REL-003` canonical event SHA.

The protected transition command is:

```bash
Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state pitr-proof --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state disabled \
  --expected-sequence 2 --expected-event-sha "$REL_003_EVENT_SHA" \
  --approval Evidence/runtime/approvals/pitr-proof.json --approval-sha "$PITR_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-pitr.json --observed-input-sha "$OBSERVED_PITR_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output Evidence/runtime/REL-008.json
```

For a live incident recovery, Ops performs the real provider PITR action only after Security confirms the recovery point and authorization/audit preservation requirements. The incident Issue records the protected provider receipt, recovery-point time, release ID, actor, source checksum, and restored verification. A local Supabase/PostgreSQL fixture, dump/restore test, or `MIG-005` test output cannot claim the live recovery happened.

If recovery requires a schema or app change, keep old-client compatibility, outbox/history reconstruction, DML denial, RLS, audit, and revocation behavior intact. Use a forward-compatible hotfix. Do not reuse the pre-release `pitr-proof` approval or `REL-008` event as an authorization for a new recovery operation.

## Tabletop and incident communication evidence

After a containment or planned exercise, the protected `rollback-tabletop` gate writes `Evidence/runtime/REL-012.json` from real protected sources. Its scenario must exercise all of: App Store stop/hold or remove-from-sale decision, self write-pause queue preservation, social zeroization, GPS manual fallback, generic friend-code unavailable behavior, provider recovery decision, authorization-preservation checks, and a forward-hotfix path. A static tabletop template or fixture is not `REL-012`.

The protected `incident-comms` gate writes `Evidence/runtime/REL-013.json` from the protected release/incident Issue and actual communication timeline. The record is redacted and binds the release/tag/commit, incident classification, decision times, message checksums, actors, and source references. It must never contain secrets, raw GPS, friend data, personal contact information, or provider credentials.

Product sends a factual customer message stating the current status, affected feature or availability scope without account-identifying detail, containment action, supported customer guidance, and the next UTC update time. Every statement must be drawn from the protected incident record; the message checksum, sender, time, and source record are inputs to `REL-013`. Never claim an Apple stop, recovery, exposure scope, or resolution that has not been confirmed by its protected source.

## Resume criteria and negative expectations

A stopped/held release does not resume because an incident Issue was closed or an operator says it is safe. Resume only through the normal immutable lineage: correct the cause, obtain real protected sources, pass the applicable fixed floor window, collect a fresh exactly-three-role gate approval, and pass controller CAS with the immediate predecessor event SHA. `M6-EXIT` does not waive a later P0/P1 or material burn.

A P0/P1/metric-floor/source/CAS/approval failure must have these negative outcomes: no approval overwrite, no controller event, no phase advance, no contract removal, no local artifact treated as protected evidence, and no authorization downgrade. Preserve evidence and containment state until the 7-day/30-day review and retention requirements are complete.
