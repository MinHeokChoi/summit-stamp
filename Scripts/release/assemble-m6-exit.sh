#!/usr/bin/env bash
# Immutable M6-EXIT admission writer. See validate-release-lineage.py --help.
set -euo pipefail

script_directory="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_directory/validate-release-lineage.py" assemble-m6-exit "$@"
