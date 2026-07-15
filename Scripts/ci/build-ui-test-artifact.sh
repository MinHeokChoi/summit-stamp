#!/usr/bin/env bash
# Build the declared UI-test payload, manifest, and producer evidence.
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: build-ui-test-artifact.sh --id UI-BUILD-PRODUCER --workspace Hiker.xcworkspace --scheme HikerUITests --destination DESTINATION --result .ci/results/ui-build.xcresult --output Evidence/tests/UI-BUILD-PRODUCER.json'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

id='UI-BUILD-PRODUCER'
workspace='Hiker.xcworkspace'
scheme='HikerUITests'
destination='platform=iOS Simulator,name=iPhone 17,OS=26.5,arch=arm64'
result='.ci/results/ui-build.xcresult'
output='Evidence/tests/UI-BUILD-PRODUCER.json'
while (($#)); do
  case "$1" in
    --id|--workspace|--scheme|--destination|--result|--output)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --id) id="$2" ;;
        --workspace) workspace="$2" ;;
        --scheme) scheme="$2" ;;
        --destination) destination="$2" ;;
        --result) result="$2" ;;
        --output) output="$2" ;;
      esac
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

[[ "$id" == 'UI-BUILD-PRODUCER' ]] || die 'unsupported UI build evidence ID'
[[ "$workspace" == *.xcworkspace ]] || die 'invalid workspace path'
[[ "$scheme" == 'HikerUITests' ]] || die 'unsupported UI-test scheme'
[[ -n "$destination" ]] || die 'missing destination'
[[ "$result" == .ci/results/*.xcresult ]] || die 'invalid result path'
[[ "$output" == "Evidence/tests/$id.json" ]] || die 'mismatched evidence output'
command -v xcodebuild >/dev/null || die 'xcodebuild is required'
command -v python3 >/dev/null || die 'python3 is required'

resolve_repo_path() {
  python3 - "$repo_root" "$1" "$2" <<'PY'
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
raw_path = sys.argv[2]
kind = sys.argv[3]
try:
    if not raw_path or "\\" in raw_path or any(ord(character) < 32 for character in raw_path):
        raise ValueError
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != raw_path
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
    ):
        raise ValueError
    candidate = root.joinpath(*relative.parts)
    resolved = candidate.resolve(strict=kind not in {"destination", "create"})
    resolved.relative_to(root)
    if kind == "directory" and (candidate.is_symlink() or not resolved.is_dir()):
        raise ValueError
    if kind == "file" and (candidate.is_symlink() or not resolved.is_file()):
        raise ValueError
    if kind in {"destination", "create"}:
        resolved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved.parent.resolve(strict=True).relative_to(root)
        if kind == "destination" and (candidate.exists() or candidate.is_symlink()):
            raise ValueError
except (OSError, ValueError):
    raise SystemExit(1)
print(resolved)
PY
}

workspace_path="$(resolve_repo_path "$workspace" directory)" || die 'invalid workspace path'
result_path="$(resolve_repo_path "$result" destination)" || die 'invalid result path'
derived_data_path="$(resolve_repo_path '.ci/xctest/DerivedData' create)" || die 'invalid derived-data path'
manifest_path="$(resolve_repo_path '.ci/xctest/manifest.json' destination)" || die 'invalid manifest path'
xctestrun_entrypoint_path="$(resolve_repo_path '.ci/xctest/HikerUITests-ios26.5.xctestrun' destination)" || die 'invalid xctestrun output path'
output_path="$(resolve_repo_path "$output" destination)" || die 'invalid evidence output'
project_path="$(resolve_repo_path 'Hiker.xcodeproj' directory)" || die 'missing project path'
[[ ! -e "$manifest_path.sha256" && ! -L "$manifest_path.sha256" ]] || die 'duplicate manifest output'
[[ ! -e "$output_path.sha256" && ! -L "$output_path.sha256" ]] || die 'duplicate evidence output'

validate_destination() {
  python3 - "$1" <<'PY'
import sys

value = sys.argv[1]
if (
    not value
    or any(ord(character) < 32 for character in value)
    or any(character in value for character in ("/", "\\", "~", "$"))
):
    sys.exit(1)
PY
}
[[ "$workspace" == 'Hiker.xcworkspace' ]] || die 'unsupported UI-test workspace'
[[ "$result" == '.ci/results/ui-build.xcresult' ]] || die 'unsupported UI-test result path'
validate_destination "$destination" || die 'invalid destination'
[[ "$destination" == 'platform=iOS Simulator,name=iPhone 17,OS=26.5,arch=arm64' ]] || die 'unsupported UI-test destination'

log_relative=".ci/logs/$id.log"
log_directory="$repo_root/.ci/logs"
mkdir -p "$log_directory" || die 'unable to create log directory'
python3 - "$repo_root" "$log_directory" <<'PY' || die 'invalid log directory'
import os
import sys

root = os.path.realpath(sys.argv[1])
directory = os.path.realpath(sys.argv[2])
try:
    if os.path.commonpath((root, directory)) != root or not os.path.isdir(directory):
        raise ValueError
except ValueError:
    sys.exit(1)
PY
log_file="$repo_root/$log_relative"
[[ ! -e "$log_file" && ! -L "$log_file" ]] || die 'duplicate evidence log'

umask 077
temporary_log="$(mktemp "$log_directory/.${id}.log.XXXXXX")" || die 'unable to create UI build log'
temporary_log_relative="${temporary_log#"$repo_root/"}"
[[ "$temporary_log_relative" == .ci/logs/* ]] || die 'invalid UI build log'
trap 'if [[ -n "${temporary_log:-}" ]]; then rm -f "$temporary_log"; fi' EXIT

command=(
  xcodebuild clean build-for-testing
  -workspace "$workspace_path"
  -scheme "$scheme"
  -configuration Release
  -destination "$destination"
  -derivedDataPath "$derived_data_path"
  -resultBundlePath "$result_path"
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
)
recorded_command=(
  xcodebuild clean build-for-testing
  -workspace "$workspace"
  -scheme "$scheme"
  -configuration Release
  -destination "$destination"
  -derivedDataPath '.ci/xctest/DerivedData'
  -resultBundlePath "$result"
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
)
command_json="$(python3 - "${recorded_command[@]}" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1:], separators=(",", ":")))
PY
)" || die 'unable to encode build command'
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
"${command[@]}" >"$temporary_log" 2>&1
exit_code=$?
set -e
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! python3 "$script_dir/write-evidence.py" --validate-log "$temporary_log_relative"; then
  rm -f "$temporary_log"
  temporary_log=''
  die 'unsafe UI build log'
fi
if ! ln "$temporary_log" "$log_file"; then
  rm -f "$temporary_log"
  temporary_log=''
  die 'duplicate UI build log'
fi
rm -f "$temporary_log"
temporary_log=''

((exit_code == 0)) || die 'UI build command failed'
[[ -d "$result_path" && ! -L "$result_path" ]] || die 'missing UI build result bundle'

warning_counts="$(python3 - "$log_file" <<'PY'
import re
import sys
import os
from pathlib import Path

SKIP_RE = re.compile(r"(?i)(?:#\s*skip\b|\bskipped\b)")
WARNING_RE = re.compile(r"(?i)\bwarning\s*:")
NO_APPINTENTS_METADATA_RE = re.compile(
    r"(?i).*warning:\s*Metadata extraction skipped\. No AppIntents\.framework dependency found\.\s*(?:\(in target .+\))?\s*$"
)

skipped = 0
compiler_or_test_warnings = 0
xcode_no_appintents_metadata = 0
warning_lines = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
    if WARNING_RE.search(line) and NO_APPINTENTS_METADATA_RE.fullmatch(line):
        xcode_no_appintents_metadata += 1
        continue
    if SKIP_RE.search(line):
        skipped += 1
    if WARNING_RE.search(line):
        compiler_or_test_warnings += 1
        if len(warning_lines) < 20:
            warning_lines.append(line.replace(os.getcwd(), "$REPO"))
for line in warning_lines:
    print(f"xcode warning: {line}", file=sys.stderr)
print(f"{skipped}\t{compiler_or_test_warnings}\t{xcode_no_appintents_metadata}")
PY
)" || die 'unable to inspect UI build log'
IFS=$'\t' read -r skipped_tests compiler_or_test_warnings xcode_no_appintents_metadata <<< "$warning_counts"
[[ "$skipped_tests" =~ ^[0-9]+$ && "$compiler_or_test_warnings" =~ ^[0-9]+$ && "$xcode_no_appintents_metadata" =~ ^[0-9]+$ ]] || die 'invalid UI build log counts'
((skipped_tests == 0)) || die 'UI build log contains skipped tests'
((compiler_or_test_warnings == 0)) || die 'UI build log contains compiler or test warnings'

actual_xctestrun="$(python3 - "$derived_data_path" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
try:
    candidates = sorted(
        path.resolve(strict=True)
        for path in root.glob("Build/Products/**/*.xctestrun")
        if path.is_file() and not path.is_symlink()
    )
    if len(candidates) != 1:
        raise ValueError
    candidates[0].relative_to(root)
except (OSError, ValueError):
    raise SystemExit(1)
print(candidates[0])
PY
)" || die 'expected exactly one UI-test xctestrun product'
cp -p "$actual_xctestrun" "$xctestrun_entrypoint_path" || die 'unable to create xctestrun producer path'

python3 "$script_dir/build-xctest-manifest.py" \
  --derived-data "$derived_data_path" \
  --source-root "$repo_root" \
  --project "$project_path" \
  --output "$manifest_path" || die 'unable to build xctest manifest'
[[ -f "$manifest_path" && ! -L "$manifest_path" && -f "$manifest_path.sha256" && ! -L "$manifest_path.sha256" ]] || die 'missing xctest manifest output'

python3 - "$repo_root" "$id" "$output" "$log_relative" "$result" "$manifest_path" "$command_json" "$started_at" "$finished_at" "$skipped_tests" "$compiler_or_test_warnings" "$xcode_no_appintents_metadata" <<'PY'
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
(
    evidence_id,
    output,
    log,
    result,
    manifest,
    command_json,
    started_at,
    finished_at,
    skipped_tests,
    compiler_or_test_warnings,
    xcode_no_appintents_metadata,
) = sys.argv[2:]


def safe_relative(value):
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ValueError
    return path


def tree_sha256(path):
    digest = hashlib.sha256()

    def record(value):
        digest.update(value.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")

    def visit(current, relative):
        metadata = os.lstat(current)
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISREG(metadata.st_mode):
            record(f"F:{relative}:{mode}")
            with open(current, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
        elif stat.S_ISLNK(metadata.st_mode):
            record(f"L:{relative}:{mode}:{os.readlink(current)}")
        elif stat.S_ISDIR(metadata.st_mode):
            record(f"D:{relative}:{mode}")
            for child in sorted(os.scandir(current), key=lambda item: item.name):
                child_relative = child.name if not relative else f"{relative}/{child.name}"
                visit(child.path, child_relative)
        else:
            raise ValueError

    visit(path, "")
    return digest.hexdigest()


try:
    output_relative = safe_relative(output)
    log_relative = safe_relative(log)
    result_relative = safe_relative(result)
    manifest_path = Path(manifest).resolve(strict=True)
    output_path = root.joinpath(*output_relative.parts)
    log_path = root.joinpath(*log_relative.parts)
    result_path = root.joinpath(*result_relative.parts)
    sidecar_path = output_path.with_name(output_path.name + ".sha256")
    if (
        evidence_id != "UI-BUILD-PRODUCER"
        or output_relative.as_posix() != "Evidence/tests/UI-BUILD-PRODUCER.json"
        or log_relative.as_posix() != ".ci/logs/UI-BUILD-PRODUCER.log"
        or result_relative.as_posix() != ".ci/results/ui-build.xcresult"
        or output_path.exists()
        or output_path.is_symlink()
        or sidecar_path.exists()
        or sidecar_path.is_symlink()
        or not log_path.is_file()
        or log_path.is_symlink()
        or not result_path.is_dir()
        or result_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.is_symlink()
    ):
        raise ValueError
    manifest_relative = manifest_path.relative_to(root).as_posix()
    if manifest_relative != ".ci/xctest/manifest.json":
        raise ValueError
    command = json.loads(command_json)
    if (
        not isinstance(command, list)
        or command[:10] != [
            "xcodebuild",
            "clean",
            "build-for-testing",
            "-workspace",
            "Hiker.xcworkspace",
            "-scheme",
            "HikerUITests",
            "-configuration",
            "Release",
            "-destination",
        ]
        or len(command) != 17
        or command[11:] != [
            "-derivedDataPath",
            ".ci/xctest/DerivedData",
            "-resultBundlePath",
            ".ci/results/ui-build.xcresult",
            "SWIFT_TREAT_WARNINGS_AS_ERRORS=YES",
            "GCC_TREAT_WARNINGS_AS_ERRORS=YES",
        ]
        or not isinstance(command[10], str)
        or "/" in command[10]
        or any(not isinstance(value, str) or value.startswith("/") or "/Users/" in value or "/home/" in value for value in command)
    ):
        raise ValueError
    if any(not re.fullmatch(r"0|[1-9][0-9]*", value) for value in (skipped_tests, compiler_or_test_warnings, xcode_no_appintents_metadata)):
        raise ValueError
    if int(skipped_tests) != 0 or int(compiler_or_test_warnings) != 0:
        raise ValueError
    revision = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], text=True, capture_output=True, check=False)
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], text=True, capture_output=True, check=False)
    candidate_sha = revision.stdout.strip().lower()
    git_sha = candidate_sha if revision.returncode == 0 and status.returncode == 0 and not status.stdout and re.fullmatch(r"[a-f0-9]{40}", candidate_sha) else "uncommitted"
    record = {
        "schemaVersion": 1,
        "id": evidence_id,
        "status": "passed",
        "runner": "ui-build",
        "command": command,
        "exitCode": 0,
        "gitSHA": git_sha,
        "log": {"path": log_relative.as_posix(), "sha256": hashlib.sha256(log_path.read_bytes()).hexdigest()},
        "manifest": {"path": manifest_relative, "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest()},
        "result": {"path": result_relative.as_posix(), "sha256": tree_sha256(result_path)},
        "timestamps": {"startedAt": started_at, "finishedAt": finished_at},
        "output": {"path": output_relative.as_posix()},
        "warningSummary": {
            "compilerOrTestWarnings": int(compiler_or_test_warnings),
            "skippedTests": int(skipped_tests),
            "nonTestToolWarnings": {
                "xcodeNoAppIntentsMetadata": int(xcode_no_appintents_metadata)
            },
        },
    }
    content = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    sidecar = f"{hashlib.sha256(content).hexdigest()}  {output_relative.as_posix()}\n".encode("ascii")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)


def atomic_link(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

try:
    atomic_link(sidecar_path, sidecar)
    try:
        atomic_link(output_path, content)
    except BaseException:
        sidecar_path.unlink(missing_ok=True)
        raise
except (OSError, ValueError):
    raise SystemExit(1)
PY
