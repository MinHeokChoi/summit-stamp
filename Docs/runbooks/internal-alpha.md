# Internal TestFlight alpha — M6

## Authority and evidence boundary

This runbook creates the M6 readiness and internal-alpha portion of the release lineage for one signed tag. The protected release job supplies `RELEASE_ID`, `GITHUB_REF_NAME`, `GITHUB_SHA`, `GITHUB_ACTOR`, `DATASET_SHA`, `MIGRATION_SHA`, `RELEASE_ISSUE_URL`, and the SHA-256 values named below. `GITHUB_REF_NAME` must resolve to `GITHUB_SHA`; a tag, commit, dataset SHA, migration SHA, release ID, or approval from another release is rejected.

Only three approval roles exist: **Product**, **Security**, and **Ops**. Each approval record requires exactly one distinct, current active member of each role. QA and Release Engineering may prepare deterministic evidence; they cannot replace a role, approve a gate, invoke a protected provider action, or write a transition event.

`Evidence/tests/*.json` and local deterministic validation prove only their declared test assertions. Fixtures in `Docs/evidence/fixtures/` are negative-validator inputs, never alpha, Apple, Supabase, App Store, approval, PITR, or promotion evidence. A local file, screenshot, mocked response, or successful dry run does not substitute for a protected TestFlight, Supabase, GitHub Environment, or App Store action.

All commands below run only in the protected release workflow at the named gate. A command failure is a stop: it must produce no new immutable approval, manifest, transition event, or output evidence. Never delete or overwrite an existing immutable output to retry; diagnose, make a forward-compatible correction, and start a new release when the immutable binding no longer matches.

## Preconditions and immutable inputs

Before alpha, the protected `readiness` gate must make `REL-001` at `Evidence/manifests/m6-readiness.json` with only M0–M5 and M2A evidence. It must include the real `AUTH-APPLE-STAGING` receipt, not local Apple/auth evidence, and must not contain `REL-004` through `REL-014`, `REL-007`, or `M6-EXIT`.

The following inputs are mandatory and non-substitutable:

| Artifact or input | Responsible role | Required condition |
|---|---|---|
| `REL-001` / `Evidence/manifests/m6-readiness.json` | Release Engineering prepares; protected workflow assembles | Write once; same signed tag, commit, release ID, dataset SHA, and migration SHA. |
| `Evidence/manifests/observed-predeploy.json` | Security + Ops | Protected source manifest for signed migration, `AUTH-003`, `AUTH-004`, and `MIG-004`; no enabled write path. |
| `Evidence/runtime/approvals/predeploy.json` | Product + Security + Ops | Fresh, write-once, exactly-three-role approval bound to readiness SHA and the predeploy observed-manifest SHA. |
| `REL-002` / `Evidence/runtime/REL-002.json` | Ops protected job | First event only: `none → predeploy-disabled`; switch is `disabled`. |
| `Evidence/manifests/observed-compatibility.json` | Product + Security + Ops | Protected old/new-client authentication, DML-denial, RPC, and outbox compatibility source. |
| `Evidence/runtime/approvals/compatibility.json` and `REL-003` | Product + Security + Ops; Ops protected job | Fresh compatibility approval and the only permitted `predeploy-disabled → compatibility` event. |
| `Evidence/manifests/observed-pitr.json` | Security + Ops | Protected restore receipt plus `MIG-005`, restored grants/RPC/projection/history/audit evidence. |
| `Evidence/runtime/approvals/pitr-proof.json` and `REL-008` | Product + Security + Ops; Ops protected job | Fresh PITR approval and the only permitted `compatibility → pitr-proof` event. |

Run `Scripts/release/assemble-readiness.sh` only in the protected `readiness` workflow gate with the M0–M5/M2A inputs above. Its sole output is `Evidence/manifests/m6-readiness.json` (`REL-001`). The gate rejects incomplete, future, stale, cross-tag, or overwrite input; it has no Apple, Supabase, or App Store side effect.

## Disabled predeploy, compatibility, and PITR transition

`GENESIS_SENTINEL_SHA` is the SHA-256 of canonical JSON containing exactly `schemaVersion`, `releaseID`, `tag`, `commit`, `datasetSHA`, and `migrationSHA`. It is a schema-defined predecessor, not a row, file, event, manifest, or human-written genesis artifact. It is valid only for the first transition.

Collect the predeploy approval after `observed-predeploy.json` is immutable:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate predeploy \
  --issue-url "$RELEASE_ISSUE_URL" \
  --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" \
  --manifest-sha "$READINESS_SHA" \
  --transition predeploy-disabled \
  --metric-sha "$OBSERVED_PREDEPLOY_SHA" \
  --output Evidence/runtime/approvals/predeploy.json
```

The protected job then performs the first and only sentinel transition:

```bash
Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state predeploy-disabled --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" --switch-state disabled \
  --expected-sequence 0 --expected-event-sha "$GENESIS_SENTINEL_SHA" \
  --approval Evidence/runtime/approvals/predeploy.json --approval-sha "$PREDEPLOY_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-predeploy.json --observed-input-sha "$OBSERVED_PREDEPLOY_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" \
  --actor "$GITHUB_ACTOR" --output Evidence/runtime/REL-002.json
```

A wrong sentinel, any existing first event, nonzero first sequence, mismatched release context, replay, or concurrency failure is nonzero and writes no event. `REL-002` leaves the migration additive, deny-preserving, and disabled.

For compatibility and PITR, repeat the exact three-role collection with the stated gate/path and then invoke the controller with the prior canonical event SHA:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate compatibility --issue-url "$RELEASE_ISSUE_URL" --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" \
  --manifest-sha "$READINESS_SHA" --transition compatibility --metric-sha "$OBSERVED_COMPATIBILITY_SHA" \
  --output Evidence/runtime/approvals/compatibility.json

Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state compatibility --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state disabled \
  --expected-sequence 1 --expected-event-sha "$REL_002_EVENT_SHA" \
  --approval Evidence/runtime/approvals/compatibility.json --approval-sha "$COMPATIBILITY_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-compatibility.json --observed-input-sha "$OBSERVED_COMPATIBILITY_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output Evidence/runtime/REL-003.json

Scripts/release/collect-role-approvals.sh \
  --gate pitr-proof --issue-url "$RELEASE_ISSUE_URL" --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" \
  --manifest-sha "$READINESS_SHA" --transition pitr-proof --metric-sha "$OBSERVED_PITR_SHA" \
  --output Evidence/runtime/approvals/pitr-proof.json

Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state pitr-proof --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state disabled \
  --expected-sequence 2 --expected-event-sha "$REL_003_EVENT_SHA" \
  --approval Evidence/runtime/approvals/pitr-proof.json --approval-sha "$PITR_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-pitr.json --observed-input-sha "$OBSERVED_PITR_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output Evidence/runtime/REL-008.json
```

The controller accepts only `none → predeploy-disabled → compatibility → pitr-proof` at this point. The sentinel is never accepted after `REL-002`; an approval path is consumed only by its named state and cannot be reused.

## Human-only TestFlight alpha

1. **Ops** uploads the exact signed tag/build to the internal TestFlight group in App Store Connect. This is a human-only Apple action performed with the approved production App Store Connect account; no local CLI, fixture, simulator, or App Store Connect mock can claim it occurred.
2. **Product** selects internal testers and confirms the build/tag/build-digest shown by TestFlight matches the protected build. **Security** confirms the alpha test charter includes auth/revocation, direct-DML denial, raw-GPS non-persistence, and fail-closed behavior. Their observations are inputs to the protected `internal-alpha` workflow gate, not alternate approvals.
3. The protected gate queries/records the real TestFlight build, tester window, real staging/synthetic outcomes, incident state, tag, commit, and source checksums. It writes `Evidence/runtime/REL-004.json` only on a real, matching source. `REL-004` is the live internal-alpha evidence.
4. Alpha is stopped immediately for a P0 and held for a P1 under `incident-containment.md`. An alpha with a provider query failure, mismatched build, unresolved P0/P1, or missing live source produces no `REL-004`.

Alpha does not enable the migration, grant broader access, or admit M7. The only allowed recovery is containment, a deny-preserving/fail-closed configuration, or a forward-compatible hotfix; it is never a remote downgrade or an authorization relaxation.
