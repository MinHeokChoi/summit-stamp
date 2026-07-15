# Final RC and App Store phased release — M6 to M7

## Non-negotiable release lineage

This runbook is for one protected release ID, signed tag, and resolved commit. The only permitted state path is:

```text
none → predeploy-disabled → compatibility → pitr-proof → activate-1pct
     → phase-5 → phase-25 → phase-50 → phase-100 → contract-remove-old
```

`release_transition_events` is authoritative. Every event carries the exact prior sequence and canonical prior event SHA under a per-release CAS lock. No local evidence file, GitHub Actions artifact, fixture, dry run, copied approval, or manually written event may replace a controller event. A rejected CAS, replay, stale predecessor, cross-release input, invalid tag/commit/dataset/migration context, missing protected environment, or illegal state produces nonzero/no event/no output.

The controller command has this full required context for every state transition:

```bash
Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state "$STATE" --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" --switch-state "$SWITCH_STATE" \
  --expected-sequence "$EXPECTED_SEQUENCE" --expected-event-sha "$EXPECTED_EVENT_SHA" \
  --approval "$APPROVAL_PATH" --approval-sha "$APPROVAL_SHA" \
  --observed-input-manifest "$OBSERVED_MANIFEST" --observed-input-sha "$OBSERVED_MANIFEST_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" \
  --actor "$GITHUB_ACTOR" --output "$OUTPUT"
```

For `activate-1pct`, each phase, and `contract-remove-old`, append both immutable M7 roots:

```bash
  --rc-manifest Evidence/manifests/rc.json --rc-manifest-sha "$RC_SHA" \
  --m6-exit Evidence/runtime/M6-EXIT.json --m6-exit-sha "$M6_EXIT_SHA"
```

For `phase-5`, `phase-25`, `phase-50`, and `phase-100`, also append the matching current floor result:

```bash
  --phase-floor "Evidence/runtime/REL-011-$NN.json" --phase-floor-sha "$PHASE_FLOOR_SHA"
```

`NN` is exactly `05`, `25`, `50`, or `100`. The pre-M7 controller states (`predeploy-disabled`, `compatibility`, and `pitr-proof`) must omit all six M7/phase options. Any other option set is rejected.

The protected workflow supplies `HIKER_RELEASE_BUILD_DIGEST`; the controller rejects a missing or malformed value and requires the approval and observed-input manifest to carry the same `buildDigest`. It always invokes the root-owned `0755` helper at `/usr/local/bin/hiker-release-rpc`; it does not accept `MIGRATION_APPROVED_RPC_COMMAND` or any caller-selected executable. That helper forwards its fixed argument vector only to `/usr/local/bin/hiker-append-release-transition`, with no `eval`, command string, or fallback transport.

Every transition approval has exactly these base top-level fields, with no unknown fields: `schemaVersion`, `artifactType`, `gate`, `issueURL`, `releaseTag`, `commitSHA`, `buildDigest`, `observedInputSHA256`, `transition`, `predecessorEventSHA256`, `githubRunId`, `createdAt`, `issueSnapshotSHA256`, `teamSnapshotSHA256`, `teamSnapshots`, and `approvals`. `approvals` contains exactly one active, current Product, Security, and Ops record; each record contains its own `approvalDigest`. M7 approvals additionally require exact `rcManifestSHA256` and `m6ExitSHA256`; phase approvals additionally require exact `phaseFloorSHA256`. The controller canonically reads each named artifact, verifies its sidecar, and rejects any digest, tag, commit, build, predecessor, M6-exit, observed-input, or phase-floor mismatch. A copied approval cannot be reused across transitions, phases, releases, or predecessor events.
### Genesis sentinel byte vector

The initial `predeploy-disabled` transition uses sequence `0` and the SHA-256 of the **exact UTF-8 bytes below**, with no trailing newline, BOM, whitespace, reordered fields, or generic JSON reserialization:

```text
{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","datasetSHA":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","migrationSHA":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","releaseID":"release-genesis","schemaVersion":"m6-release-transition-v1","tag":"v1.2.3"}
```

This is the SQL `m6_private.release_transition_sentinel_sha` test vector: `releaseID=release-genesis`, `tag=v1.2.3`, `commit=a×40`, `datasetSHA=c×64`, and `migrationSHA=b×64`. Its SHA-256 is `b7b40ff308729f76a8d03479138e81d52bc0e5139d84f5e367fd76db02e912f9`, the only valid `--expected-event-sha` for that vector. `schemaVersion` is the literal string `m6-release-transition-v1`, not numeric `1`; the database and controller both hash the shown byte sequence.

## Final RC and M6 exit

### Required final RC inputs

The protected `final-rc` gate runs `Scripts/release/assemble-rc.sh` with the following required immutable inputs and writes only `Evidence/manifests/rc.json` plus `Evidence/runtime/REL-007.json`:

```text
Evidence/manifests/m6-readiness.json                  REL-001
Evidence/runtime/REL-002.json                          predeploy-disabled
Evidence/runtime/REL-003.json                          compatibility
Evidence/runtime/REL-004.json                          internal alpha
Evidence/runtime/REL-005.json                          seven-day beta floor pass
Evidence/runtime/REL-006.json                          live metadata/privacy review
Evidence/runtime/REL-008.json                          protected PITR proof
Evidence/runtime/REL-009.json                          read-only switch drill
Evidence/runtime/OPS-005.json                          threshold ratification
Evidence/tests/PERF-001.json                           final RC performance proof
Evidence/runtime/AUTH-005-RC-SERVER.json               final-tag server issuer rejection
Evidence/runtime/AUTH-005-RC-ARCHIVE.json              final-build archive no-bypass proof
Evidence/runtime/AUTH-005-RC.json                      exact final-tag/commit/build aggregate
Evidence/runtime/approvals/threshold.json              exact threshold approval
```

`AUTH-005-RC-SERVER`, `AUTH-005-RC-ARCHIVE`, and `AUTH-005-RC` are regenerated for the exact final tag, commit, and build digest. M3 `AUTH-005-PREFLIGHT-SERVER`, `AUTH-005-PREFLIGHT-ARCHIVE`, and `AUTH-005-PREFLIGHT` are staging evidence and are rejected as RC inputs. `REL-007` is an output only; no RC input may be self-referential or from M7.

The kill-switch drill is intentionally read-only and cannot advance release state:

```bash
Scripts/release/produce-switch-drill-evidence.sh \
  --previous-event-sha "$REL_008_EVENT_SHA" \
  --output Evidence/runtime/REL-009.json
```

The protected drill verifies that a self write pause returns an explicit retry and preserves the encrypted outbox queue; social reads zeroize in-memory data; GPS disables to manual completion; and missing/blocked/rate-limited friend-code lookup is generic unavailable. It also verifies no direct DML/RLS/auth/privacy/revocation bypass. It calls no transition RPC and creates no release state event.

After the RC exists, **Ops** conducts the real alert/suppression drill and the protected `alert-drill` gate writes `Evidence/runtime/OPS-003.json`. **Ops and Security** attach the redacted Release/Issue and encrypted WORM disposition evidence under the `evidence-disposition` gate, which writes `Evidence/runtime/OPS-004.json`. These are protected runtime sources, not locally generated receipts.

Collect the only M6-exit approval after final RC, `PERF-001`, `REL-005`, `OPS-003`, and `OPS-004` exist:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate m6-exit \
  --issue-url "$RELEASE_ISSUE_URL" \
  --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" \
  --manifest-sha "$RC_SHA" \
  --transition m6-exit \
  --metric-sha "$M6_EXIT_METRICS_SHA" \
  --output Evidence/runtime/approvals/m6-exit.json

Scripts/release/assemble-m6-exit.sh \
  --rc Evidence/manifests/rc.json \
  --ops-003 Evidence/runtime/OPS-003.json \
  --ops-004 Evidence/runtime/OPS-004.json \
  --perf Evidence/tests/PERF-001.json \
  --beta Evidence/runtime/REL-005.json \
  --threshold Evidence/runtime/OPS-005.json \
  --auth Evidence/runtime/AUTH-005-RC.json \
  --approval Evidence/runtime/approvals/m6-exit.json \
  --output Evidence/runtime/M6-EXIT.json
```

The assembler validates schema/checksum/tag/commit bindings, final RC floors, no P0/unresolved P1 source, and exactly the three required roles. Missing, stale, duplicate, cross-tag, or cross-RC approval means no `M6-EXIT`. M7 has no admission path other than the exact SHA of `Evidence/runtime/M6-EXIT.json`; `REL-007`, a threshold approval, or a successful Apple console action is not an admission substitute.

Run `Scripts/release/validate-release-lineage.py` only in the protected `m6-exit` and M7 workflow gates with the required final RC, M6-EXIT, approval, observed-manifest, and predecessor artifacts. It validates release/tag/commit/checksum/state/CAS lineage; it is a validator and does not perform an Apple or Supabase action.

## Human-only App Store rollout and 1% activation

App Store Connect phased-release changes are human-only. **Ops** makes the console change using the approved production App Store Connect account; **Product** confirms customer impact and release notes; **Security** confirms no requested action would weaken authorization. The protected job records the real App Store Connect source/checksum in the applicable immutable observed manifest. A script, local source JSON, screenshot, simulator, fixture, or a GitHub environment approval cannot claim that Apple made the change.

Before 1%, collect fresh approval and create `REL-010`:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate activate-1pct --issue-url "$RELEASE_ISSUE_URL" --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" \
  --manifest-sha "$RC_SHA" --transition activate-1pct --metric-sha "$M6_EXIT_SHA" \
  --output Evidence/runtime/approvals/activate-1pct.json

Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state activate-1pct --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state enabled \
  --expected-sequence 3 --expected-event-sha "$REL_008_EVENT_SHA" \
  --approval Evidence/runtime/approvals/activate-1pct.json --approval-sha "$ACTIVATE_1PCT_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-activate-1pct.json --observed-input-sha "$OBSERVED_ACTIVATE_1PCT_SHA" \
  --rc-manifest Evidence/manifests/rc.json --rc-manifest-sha "$RC_SHA" \
  --m6-exit Evidence/runtime/M6-EXIT.json --m6-exit-sha "$M6_EXIT_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output Evidence/runtime/REL-010.json
```

The observed manifest binds the exact `M6-EXIT` SHA and real App Store 1% setting. Keep 1% live for at least 24 continuous hours. Do not progress during an incomplete window, P0, unresolved P1, floor failure, source mismatch, failed query, or material burn.
### Lost response or timeout: reconcile, never blind retry

A timeout, connection reset, malformed receipt, or missing local controller output is **not** proof that the append failed. Do not rerun the controller, regenerate the observed manifest, reuse the approval, or issue a new transition request.

Ops must use the approved read-only release-ledger reconciliation channel to locate the event by the exact `releaseID`, requested `state`, `expectedSequence`, `expectedEventSHA256`, `approvalSHA256`, and `observedInputSHA256`. Reconcile the returned sequence, prior-event SHA, event SHA, tag, commit, and audit event ID against the immutable inputs and recover the controller receipt through the protected evidence process. A matching append is final; continue from its canonical event SHA.

If reconciliation proves that no matching event exists, preserve the failed-attempt record and investigate the transport/service failure before any new protected attempt. A subsequent request requires fresh observed input and a fresh three-role approval bound to the still-current predecessor. Never retry because a response was lost.

## Phased 5/25/50/100 rollout

Every percentage in the **1/5/25/50/100** sequence remains at that percentage for at least 24 continuous hours (>=24h) before the next percentage is requested. For every phase window, Ops obtains real App Store Connect crash/user rollout data, Supabase audit/RPC/RLS/revoke data, privacy-safe telemetry, and protected synthetics. The production floors are fixed:

| Metric for every >=24 h phase window | Required floor |
|---|---:|
| Crash-free sessions | at least 99.7% |
| Crash-free users | at least 99.5% |
| Server 5xx | less than 0.5% |
| Mutation success | at least 99.5% |
| Manual online acknowledgement p95 | at most 2.0 s |
| Revoke-event p95 | at most 5 s |
| Fail-closed lease | at most 30 s |
| Direct DML/privacy/auth bypass, revocation exposure, raw GPS persistence | 0 |

The permitted exclusions remain user cancellation, intentional offline pending, generic blocked lookup denial, and intended fail-closed unavailable only. Floors cannot be lowered, a source cannot be replaced, and a newly invented metric can only be additive.

For each percentage `NN` in `05`, `25`, `50`, and `100`, the protected `rollout-review-NN` gate validates the real >=24-hour source and writes `Evidence/runtime/REL-011-NN.json` using the floor validator:

```bash
Scripts/release/validate-runtime-floors.py \
  --id "REL-011-$NN" \
  --source-manifest "Evidence/manifests/observed-phase-$NN.json" \
  --threshold Evidence/runtime/OPS-005.json \
  --schema Docs/evidence/schemas/threshold-ratification.schema.json \
  --output "Evidence/runtime/REL-011-$NN.json"
```

After that exact phase result exists, collect a new approval at `Evidence/runtime/approvals/phase-NN.json`; then create the matching CAS event at `Evidence/runtime/REL-PHASE-NN.json`. `NN` is exactly `05`, `25`, `50`, or `100`; `STATE` is exactly `phase-5`, `phase-25`, `phase-50`, or `phase-100`; `EXPECTED_SEQUENCE` and `EXPECTED_EVENT_SHA` are the immediately prior canonical event values, not an inferred percentage or a prior manifest SHA.

```bash
Scripts/release/collect-role-approvals.sh \
  --gate "phase-$NN" --issue-url "$RELEASE_ISSUE_URL" --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" \
  --manifest-sha "$RC_SHA" --transition "$STATE" --metric-sha "$PHASE_FLOOR_SHA" \
  --output "Evidence/runtime/approvals/phase-$NN.json"

Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state "$STATE" --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state enabled \
  --expected-sequence "$EXPECTED_SEQUENCE" --expected-event-sha "$EXPECTED_EVENT_SHA" \
  --approval "Evidence/runtime/approvals/phase-$NN.json" --approval-sha "$PHASE_APPROVAL_SHA" \
  --observed-input-manifest "Evidence/manifests/observed-phase-$NN.json" --observed-input-sha "$OBSERVED_PHASE_SHA" \
  --rc-manifest Evidence/manifests/rc.json --rc-manifest-sha "$RC_SHA" \
  --m6-exit Evidence/runtime/M6-EXIT.json --m6-exit-sha "$M6_EXIT_SHA" \
  --phase-floor "Evidence/runtime/REL-011-$NN.json" --phase-floor-sha "$PHASE_FLOOR_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output "Evidence/runtime/REL-PHASE-$NN.json"
```

`REL-011-NN` must be a current passing floor result for the same release and phase observed-manifest SHA; an approval or event from another phase cannot substitute. The expected phase outputs are precisely `REL-011-05`/`REL-PHASE-05`, `REL-011-25`/`REL-PHASE-25`, `REL-011-50`/`REL-PHASE-50`, and `REL-011-100`/`REL-PHASE-100`.

## Stop rather than weaken

Use the stop/hold rules in `incident-containment.md` at any phase. App Store does not provide a remote downgrade of installed builds. Do not claim otherwise and do not respond by weakening RLS, DML denial, auth, privacy, revocation, lease expiry, or dataset authority. The permitted actions are containment, remove from sale/stop the phased release, fail closed, preserve the self-write queue during pause, zeroize social data, retain GPS manual completion, make friend-code lookup generic unavailable, and ship a forward-compatible hotfix.
