# Evidence retention, post-release review, and delayed contract removal — M7

## Retention classes and owners

Evidence is classified by where it was produced; local deterministic evidence is not upgraded into protected runtime evidence by copying it to an archive.

| Evidence class | Exact artifacts | Retention and owner |
|---|---|---|
| Local deterministic test evidence | `Evidence/tests/<ID>.json`, including `PERF-001` and `MIG-005` | Retain with its immutable release bundle when it is an RC input; it proves only the named deterministic assertion. |
| Transient workflow artifacts | GitHub Actions build logs, result bundles, upload artifacts | Retain 90 days. They do not substitute for canonical release evidence after expiration. |
| Canonical protected release evidence | `REL-001`, `REL-002`, `REL-003`, `REL-004`, `REL-005`, `REL-006`, `REL-007`, `REL-008`, `REL-009`, `OPS-003`, `OPS-004`, `OPS-005`, `M6-EXIT`, `REL-010`, `REL-011-05`, `REL-PHASE-05`, `REL-011-25`, `REL-PHASE-25`, `REL-011-50`, `REL-PHASE-50`, `REL-011-100`, `REL-PHASE-100`, `REL-012`, `REL-013`, `REL-014`, and `REL-CONTRACT` | Attach redacted canonical evidence and checksum inventory to the protected GitHub Release and protected release/incident Issue; copy to approved encrypted WORM/object-lock storage for seven years (7-year retention). |
| Approval and transition authority | `Evidence/runtime/approvals/{predeploy,compatibility,pitr-proof,threshold,m6-exit,activate-1pct,phase-05,phase-25,phase-50,phase-100,contract}.json` and authoritative release transition events | Seven-year (7-year) protected retention with the same release bundle; write once and never reused for another gate. |

**Product** may read customer/release context; **Security and Ops** administer protected archive access and disposition. Release evidence access is least-privilege, logged, and redacted. Raw GPS, secrets, tokens, credentials, personal contact data, friend-code values, and persistent friend data are never retained in a release bundle, GitHub Issue, Release asset, or WORM archive.

## Required disposition evidence

After final RC and before M6 exit, Ops and Security perform the real protected GitHub Release/Issue attachment and encrypted object-lock archive action. The protected `evidence-disposition` workflow gate writes `Evidence/runtime/OPS-004.json` only after validating the live Release, Issue, archive/object-lock receipt, encryption/access disposition, checksum inventory, tag, commit, and release ID.

`OPS-004` is required by `Scripts/release/assemble-m6-exit.sh`; it is not a local archival script result. A directory copy, local checksum, fixture, mock WORM receipt, or Actions artifact upload cannot prove protected Release/Issue status or object-lock retention. If the protected archive service is unavailable, fail closed: do not create `OPS-004`, `M6-EXIT`, a rollout event, or a claim that seven-year retention exists.

The M6 exit assembler remains the only command that joins RC, beta floors, performance, final auth, alert drill, disposition, and the exact three-role approval:

```bash
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

The output is write once. Its SHA is the sole M7 admission reference; a retained RC, prior Release asset, protected Issue comment, environment review, or local archive does not substitute.

## Seven-day and thirty-day post-release reviews

At seven days and again at thirty days after the 100% phase begins, Product, Security, and Ops conduct a protected review. The protected `postrelease-review` gate writes one current `Evidence/runtime/REL-014.json` only when its live source identifies both completed review points and their records. The review source contains:

- exact release ID, tag, commit, final RC SHA, `M6-EXIT` SHA, and the immediate predecessor release manifest SHA;
- App Store Connect rollout/crash/build status; Supabase audit/RPC/RLS/revoke results; privacy-safe telemetry; protected synthetics; and the query/window/denominator/exclusion/checksums for each source;
- open/closed P0/P1 state, material-burn decisions, customer impact, alert effectiveness, support/communication record checksums, and ownership of any forward-compatible hotfix;
- retention confirmation for the protected Release/Issue, encrypted WORM object-lock bundle, access log, and the required 90-day transient artifact setting;
- confirmation that no raw GPS, secret, personal contact information, friend-code value, or persistent friend bytes entered canonical evidence.

`REL-014` is protected runtime review evidence, not a locally written retrospective. A closed Issue, a calendar entry, a local report, or a seven-day-only review fails the 30-day requirement and must not create `REL-014`.

## Delayed contract removal

`contract-remove-old` is allowed only after all of the following are protected, immutable inputs for the same release:

1. `REL-PHASE-100` is the immediate prior canonical controller event and 100% has satisfied its required at-least-24-hour production window.
2. The minimum supported build adoption source demonstrates the declared adoption threshold. No inferred, sampled, or local estimate substitutes for the protected App Store/build source.
3. The 90-day history/outbox retention interval is complete. Existing history remains immutable; outbox expiry continues to require explicit user export or discard and has no automatic discard.
4. Migration compatibility, PITR, and containment/tabletop sources are current and checksum-bound. The source includes `MIG-002`, `MIG-003`, `MIG-004`, `MIG-005`, `REL-008`, `REL-012`, and the 7-day/30-day `REL-014` review.
5. Product, Security, and Ops each supply one distinct current active approval comment for the dedicated contract gate. No prior phase, M6-exit, or threshold approval may be reused.

Collect the dedicated approval only after the contract observed manifest is immutable:

```bash
Scripts/release/collect-role-approvals.sh \
  --gate contract \
  --issue-url "$RELEASE_ISSUE_URL" \
  --tag "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" \
  --manifest-sha "$RC_SHA" \
  --transition contract-remove-old \
  --metric-sha "$OBSERVED_CONTRACT_SHA" \
  --output Evidence/runtime/approvals/contract.json
```

Then the protected controller makes the only allowed delayed-removal transition:

```bash
Scripts/release/migration-controller.sh \
  --release-id "$RELEASE_ID" --state contract-remove-old --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --switch-state enabled \
  --expected-sequence 8 --expected-event-sha "$REL_PHASE_100_EVENT_SHA" \
  --approval Evidence/runtime/approvals/contract.json --approval-sha "$CONTRACT_APPROVAL_SHA" \
  --observed-input-manifest Evidence/manifests/observed-contract.json --observed-input-sha "$OBSERVED_CONTRACT_SHA" \
  --data-sha "$DATASET_SHA" --migration-sha "$MIGRATION_SHA" --actor "$GITHUB_ACTOR" \
  --output Evidence/runtime/REL-CONTRACT.json
```

The observed contract manifest binds the final RC SHA, minimum-build adoption result, 90-day retention proof, migration/PITR/tabletop source checksums, and immediate predecessor. It rejects an early window, missing source, stale approval, cross-tag/commit/release artifact, prior event other than `REL-PHASE-100`, or an attempt to remove a contract that old clients still require. The operation is delayed compatibility removal only; it never deletes immutable audit history or reduces authorization/privacy protections.

Run `Scripts/release/validate-release-lineage.py` only in the protected contract workflow gate with the final RC, exact `M6-EXIT`, `REL-PHASE-100`, fresh contract approval, observed contract manifest, and resulting `REL-CONTRACT` output. It validates checksum/tag/commit/state/predecessor lineage and has no provider-side promotion or deletion effect.

## Deletion and access-disposition audit

Seven-year protected evidence is not deleted for convenience, storage pressure, a closed Issue, an expired Actions artifact, or a local request. A deletion/disposition action requires all of the following in the protected release or incident Issue before any archive mutation:

1. a distinct current **Ops** actor and a distinct current **Security** actor;
2. Issue URL/number, release ID, artifact path, existing checksum, archive/object-lock location, actor identities, and UTC timestamps;
3. a concrete retention/legal reason, the exact replacement location and replacement checksum when a replacement is permitted, and confirmation that no legal/security/incident hold applies;
4. protected archive and GitHub Release/Issue access records proving the authorized action; and
5. a new immutable disposition receipt checked by the protected `evidence-disposition` gate.

No single administrator, Product actor, workflow, local delete command, or mutable spreadsheet can authorize deletion. Object-lock retention must make premature deletion fail. A failed deletion attempt is retained as an access/disposition audit fact; it must not remove the canonical artifact or alter its checksum history.

## Negative expectations

Any failed archive query, encryption/object-lock check, required review, approval membership check, retention window, source checksum, floor result, or CAS validation is nonzero/no-write: no `OPS-004`, no `REL-014`, no `REL-CONTRACT`, no Release-state advance, and no claim that retention/deletion succeeded. Preserve the existing protected evidence, fail closed, and use the incident runbook for containment.
