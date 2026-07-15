#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: run-evidence-profile.sh --profiles Docs/evidence/evidence-profiles.yml --id ID'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

profiles=''
id=''
while (($#)); do
  case "$1" in
    --profiles)
      (($# >= 2)) || die 'missing value for --profiles'
      profiles="$2"
      shift 2
      ;;
    --id)
      (($# >= 2)) || die 'missing value for --id'
      id="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die 'unsupported argument'
      ;;
  esac
done

[[ -n "$profiles" ]] || die 'missing --profiles'
[[ -n "$id" ]] || die 'missing --id'

profile_json="$(python3 - "$repo_root" "$profiles" "$id" <<'PY'
import json
import re
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
profiles_path = sys.argv[2]
requested_id = sys.argv[3]
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
METADATA_FIELDS = {"workflow", "job", "owner", "gate", "assertion"}
RUNNERS = {
    "swift": {"package", "filter"},
    "xcode": {"workspace", "scheme", "destination", "filter", "result"},
    "xctest": {"workspace", "scheme", "manifest", "xctestrun", "filter", "destination", "result"},
    "ui-build": {"workspace", "scheme", "destination", "result"},
    "bijection-negative": {"file", "invalidDirectory", "validator"},
    "pgtap": {"file", "shard"},
    "runtime": {"checkKind"},
    "apple-staging": {"receipt", "approval", "buildProvenance", "testFlightProvenance"},
}
PATH_FIELDS = {
    "swift": {"package"},
    "xcode": {"workspace", "result"},
    "xctest": {"workspace", "manifest", "xctestrun", "result"},
    "ui-build": {"workspace", "result"},
    "bijection-negative": {"file", "invalidDirectory", "validator"},
    "pgtap": {"file"},
    "runtime": set(),
    "apple-staging": {"receipt", "approval", "buildProvenance", "testFlightProvenance"},
}
RUNTIME_PROFILES = {
    "OPS-001": {"checkKind": "toolchain-contract", "output": "Evidence/runtime/OPS-001.json", "workflow": "ci-security", "job": "toolchain-provider"},
    "OPS-002": {"checkKind": "provider-approval", "output": "Evidence/runtime/OPS-002.json", "workflow": "ci-security", "job": "environment-provider-gate"},
    "AUTH-005-PREFLIGHT-SERVER": {"checkKind": "protected-auth-preflight-server", "output": "Evidence/runtime/AUTH-005-PREFLIGHT-SERVER.json", "workflow": "ci-security", "job": "preflight-auth-server"},
    "AUTH-005-PREFLIGHT-ARCHIVE": {"checkKind": "protected-auth-preflight-archive", "output": "Evidence/runtime/AUTH-005-PREFLIGHT-ARCHIVE.json", "workflow": "ci-security", "job": "preflight-auth-archive"},
    "AUTH-005-PREFLIGHT": {"checkKind": "protected-auth-preflight-aggregate", "output": "Evidence/runtime/AUTH-005-PREFLIGHT.json", "workflow": "ci-security", "job": "preflight-auth-aggregate"},
    "MIG-005-PROTECTED": {"checkKind": "protected-pitr-restore", "output": "Evidence/runtime/MIG-005-PROTECTED.json", "workflow": "ci-security", "job": "protected-pitr-restore"},
    "AUTH-005-RC-SERVER": {"checkKind": "protected-rc-auth-server", "output": "Evidence/runtime/AUTH-005-RC-SERVER.json", "workflow": "release-evidence", "job": "rc-auth-server"},
    "AUTH-005-RC-ARCHIVE": {"checkKind": "protected-rc-auth-archive", "output": "Evidence/runtime/AUTH-005-RC-ARCHIVE.json", "workflow": "release-evidence", "job": "rc-auth-archive"},
    "AUTH-005-RC": {"checkKind": "protected-rc-auth-aggregate", "output": "Evidence/runtime/AUTH-005-RC.json", "workflow": "release-evidence", "job": "rc-auth-aggregate"},
    "OPS-003": {"checkKind": "protected-alert-drill", "output": "Evidence/runtime/OPS-003.json", "workflow": "release-evidence", "job": "alert-drill"},
    "OPS-004": {"checkKind": "protected-evidence-disposition", "output": "Evidence/runtime/OPS-004.json", "workflow": "release-evidence", "job": "evidence-disposition"},
    "OPS-005": {"checkKind": "protected-threshold-ratification", "output": "Evidence/runtime/OPS-005.json", "workflow": "release-evidence", "job": "threshold-ratification"},
    "REL-001": {"checkKind": "release-readiness-assembly", "output": "Evidence/manifests/m6-readiness.json", "workflow": "release-evidence", "job": "readiness"},
    "REL-002": {"checkKind": "release-transition-predeploy", "output": "Evidence/runtime/REL-002.json", "workflow": "release-evidence", "job": "migration-predeploy"},
    "REL-003": {"checkKind": "release-transition-compatibility", "output": "Evidence/runtime/REL-003.json", "workflow": "release-evidence", "job": "compat-synthetics"},
    "REL-004": {"checkKind": "protected-alpha-observation", "output": "Evidence/runtime/REL-004.json", "workflow": "release-evidence", "job": "internal-alpha"},
    "REL-005": {"checkKind": "release-beta-floors", "output": "Evidence/runtime/REL-005.json", "workflow": "release-evidence", "job": "external-beta"},
    "REL-006": {"checkKind": "protected-metadata-observation", "output": "Evidence/runtime/REL-006.json", "workflow": "release-evidence", "job": "metadata-review"},
    "REL-007": {"checkKind": "release-rc-assembly", "output": "Evidence/runtime/REL-007.json", "workflow": "release-evidence", "job": "rc-freeze"},
    "REL-008": {"checkKind": "release-transition-pitr", "output": "Evidence/runtime/REL-008.json", "workflow": "release-evidence", "job": "pitr-drill"},
    "REL-009": {"checkKind": "release-switch-drill", "output": "Evidence/runtime/REL-009.json", "workflow": "release-evidence", "job": "kill-switch-drill"},
    "M6-EXIT": {"checkKind": "release-m6-exit-assembly", "output": "Evidence/runtime/M6-EXIT.json", "workflow": "release-evidence", "job": "m6-exit"},
    "REL-010": {"checkKind": "release-transition-activate-1pct", "output": "Evidence/runtime/REL-010.json", "workflow": "release-evidence", "job": "rollout-1pct"},
    "REL-011-05": {"checkKind": "release-phase-floors-05", "output": "Evidence/runtime/REL-011-05.json", "workflow": "release-evidence", "job": "rollout-review-05"},
    "REL-PHASE-05": {"checkKind": "release-transition-phase-05", "output": "Evidence/runtime/REL-PHASE-05.json", "workflow": "release-evidence", "job": "rollout-phase-05"},
    "REL-011-25": {"checkKind": "release-phase-floors-25", "output": "Evidence/runtime/REL-011-25.json", "workflow": "release-evidence", "job": "rollout-review-25"},
    "REL-PHASE-25": {"checkKind": "release-transition-phase-25", "output": "Evidence/runtime/REL-PHASE-25.json", "workflow": "release-evidence", "job": "rollout-phase-25"},
    "REL-011-50": {"checkKind": "release-phase-floors-50", "output": "Evidence/runtime/REL-011-50.json", "workflow": "release-evidence", "job": "rollout-review-50"},
    "REL-PHASE-50": {"checkKind": "release-transition-phase-50", "output": "Evidence/runtime/REL-PHASE-50.json", "workflow": "release-evidence", "job": "rollout-phase-50"},
    "REL-011-100": {"checkKind": "release-phase-floors-100", "output": "Evidence/runtime/REL-011-100.json", "workflow": "release-evidence", "job": "rollout-review-100"},
    "REL-PHASE-100": {"checkKind": "release-transition-phase-100", "output": "Evidence/runtime/REL-PHASE-100.json", "workflow": "release-evidence", "job": "rollout-phase-100"},
    "REL-012": {"checkKind": "protected-tabletop-observation", "output": "Evidence/runtime/REL-012.json", "workflow": "release-evidence", "job": "rollback-tabletop"},
    "REL-013": {"checkKind": "protected-incident-observation", "output": "Evidence/runtime/REL-013.json", "workflow": "release-evidence", "job": "incident-comms"},
    "REL-014": {"checkKind": "protected-postrelease-observation", "output": "Evidence/runtime/REL-014.json", "workflow": "release-evidence", "job": "postrelease-review"},
    "REL-CONTRACT": {"checkKind": "release-transition-contract", "output": "Evidence/runtime/REL-CONTRACT.json", "workflow": "release-evidence", "job": "contract-remove-old"},
}


def fail() -> None:
    raise ValueError


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail()
        value[key] = item
    return value


def reject_constant(_value):
    fail()


def text(value):
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        fail()
    return value


def safe_path(value):
    value = text(value)
    if "\\" in value:
        fail()
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
    ):
        fail()
    try:
        (root.joinpath(*relative.parts)).resolve(strict=False).relative_to(root)
    except ValueError:
        fail()
    return value


try:
    if profiles_path != "Docs/evidence/evidence-profiles.yml" or not ID_RE.fullmatch(requested_id):
        fail()
    source_profiles = root / profiles_path
    if source_profiles.is_symlink():
        fail()
    resolved_profiles = source_profiles.resolve(strict=True)
    resolved_profiles.relative_to(root)
    if not resolved_profiles.is_file():
        fail()
    document = json.loads(
        resolved_profiles.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "profiles"}:
        fail()
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1 or not isinstance(document["profiles"], dict) or not document["profiles"]:
        fail()

    profiles_by_id = document["profiles"]
    outputs = set()
    selected = None
    for evidence_id, profile in profiles_by_id.items():
        if not isinstance(evidence_id, str) or not ID_RE.fullmatch(evidence_id):
            fail()
        if not isinstance(profile, dict):
            fail()
        runner = profile.get("runner")
        if runner not in RUNNERS:
            fail()
        required = {"runner", "output"} | METADATA_FIELDS | RUNNERS[runner]
        if set(profile) != required:
            fail()
        for field, value in profile.items():
            text(value)
            if field in PATH_FIELDS[runner] or field == "output":
                safe_path(value)
        output = profile["output"]
        if runner == "runtime":
            expected_runtime = RUNTIME_PROFILES.get(evidence_id)
            if expected_runtime is None or output != expected_runtime["output"] or output in outputs:
                fail()
        elif output != f"{'Evidence/runtime' if runner == 'apple-staging' else 'Evidence/tests'}/{evidence_id}.json" or output in outputs:
            fail()
        outputs.add(output)
        if runner == "runtime":
            expected_runtime = RUNTIME_PROFILES.get(evidence_id)
            if expected_runtime is None or any(profile[field] != value for field, value in expected_runtime.items()):
                fail()
        if runner in {"xcode", "xctest", "ui-build"}:
            if not profile["workspace"].endswith(".xcworkspace") or not profile["result"].endswith(".xcresult"):
                fail()
        if runner == "xctest" and (
            not profile["manifest"].endswith(".json") or not profile["xctestrun"].endswith(".xctestrun")
        ):
            fail()
        if runner == "bijection-negative" and (
            not profile["file"].endswith(".json") or not profile["validator"].endswith(".sh")
        ):
            fail()
        if runner == "pgtap" and not profile["file"].endswith(".sql"):
            fail()
        if runner == "apple-staging" and (
            evidence_id != "AUTH-APPLE-STAGING"
            or profile["receipt"] != "Evidence/runtime/AUTH-APPLE-STAGING-source.json"
            or profile["approval"] != "Evidence/runtime/approvals/m2a.json"
            or profile["buildProvenance"] != "Evidence/runtime/M2A-BUILD.json"
            or profile["testFlightProvenance"] != "Evidence/runtime/M2A-UPLOAD.json"
            or profile["output"] != "Evidence/runtime/AUTH-APPLE-STAGING.json"
            or profile["workflow"] != "release-evidence"
            or profile["job"] != "m2a-auth-shell"
            or profile["gate"] != "M2A"
        ):
            fail()
        if evidence_id == requested_id:
            selected = profile

    if selected is None:
        fail()
    print(json.dumps(selected, sort_keys=True, separators=(",", ":")))
except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
    print("error: invalid evidence profile", file=sys.stderr)
    sys.exit(1)
PY
)" || die 'invalid evidence profile'

profile_field() {
  python3 - "$profile_json" "$1" <<'PY'
import json
import sys

try:
    value = json.loads(sys.argv[1])[sys.argv[2]]
except (KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
    raise SystemExit(1)
print(value)
PY
}

runner="$(profile_field runner)" || die 'invalid evidence profile'
output="$(profile_field output)" || die 'invalid evidence profile'
case "$runner" in
  swift)
    package="$(profile_field package)" || die 'invalid evidence profile'
    filter="$(profile_field filter)" || die 'invalid evidence profile'
    exec "$script_dir/run-swift-evidence.sh" --id "$id" --package "$package" --filter "$filter" --output "$output"
    ;;
  xcode)
    workspace="$(profile_field workspace)" || die 'invalid evidence profile'
    scheme="$(profile_field scheme)" || die 'invalid evidence profile'
    destination="$(profile_field destination)" || die 'invalid evidence profile'
    filter="$(profile_field filter)" || die 'invalid evidence profile'
    result="$(profile_field result)" || die 'invalid evidence profile'
    exec "$script_dir/run-xcode-evidence.sh" --id "$id" --workspace "$workspace" --scheme "$scheme" --destination "$destination" --filter "$filter" --result "$result" --output "$output"
    ;;
  xctest)
    workspace="$(profile_field workspace)" || die 'invalid evidence profile'
    scheme="$(profile_field scheme)" || die 'invalid evidence profile'
    manifest="$(profile_field manifest)" || die 'invalid evidence profile'
    xctestrun="$(profile_field xctestrun)" || die 'invalid evidence profile'
    filter="$(profile_field filter)" || die 'invalid evidence profile'
    destination="$(profile_field destination)" || die 'invalid evidence profile'
    result="$(profile_field result)" || die 'invalid evidence profile'
    exec "$script_dir/run-xctest-evidence.sh" --id "$id" --workspace "$workspace" --scheme "$scheme" --manifest "$manifest" --xctestrun "$xctestrun" --filter "$filter" --destination "$destination" --result "$result" --output "$output"
    ;;
  ui-build)
    workspace="$(profile_field workspace)" || die 'invalid evidence profile'
    scheme="$(profile_field scheme)" || die 'invalid evidence profile'
    destination="$(profile_field destination)" || die 'invalid evidence profile'
    result="$(profile_field result)" || die 'invalid evidence profile'
    exec "$script_dir/build-ui-test-artifact.sh" --id "$id" --workspace "$workspace" --scheme "$scheme" --destination "$destination" --result "$result" --output "$output"
    ;;
  bijection-negative)
    file="$(profile_field file)" || die 'invalid evidence profile'
    invalid_directory="$(profile_field invalidDirectory)" || die 'invalid evidence profile'
    validator="$(profile_field validator)" || die 'invalid evidence profile'
    exec "$script_dir/test-evidence-bijection-negative.sh" --id "$id" --profiles "$profiles" --valid "$file" --invalid-dir "$invalid_directory" --validator "$validator" --output "$output"
    ;;
  pgtap)
    file="$(profile_field file)" || die 'invalid evidence profile'
    shard="$(profile_field shard)" || die 'invalid evidence profile'
    exec "$script_dir/run-pgtap-evidence.sh" --id "$id" --file "$file" --shard "$shard" --output "$output"
    ;;
  runtime)
    check_kind="$(profile_field checkKind)" || die 'invalid evidence profile'
    exec "$script_dir/run-runtime-evidence.py" --id "$id" --check-kind "$check_kind" --output "$output"
    ;;
  apple-staging)
    [[ "$id" == "AUTH-APPLE-STAGING" && "$output" == "Evidence/runtime/AUTH-APPLE-STAGING.json" ]] || die 'invalid protected staging auth profile'
    exec env M2A_EVIDENCE_PROFILE_DISPATCH=AUTH-APPLE-STAGING "$script_dir/run-auth-apple-staging-evidence.py" --profile-id "$id" --output "$output"
    ;;
  *)
    die 'unsupported evidence runner'
    ;;
esac
