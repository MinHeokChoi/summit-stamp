#!/usr/bin/env bash
# Immutable REL-001 readiness writer. See validate-release-lineage.py --help.
set -euo pipefail

script_directory="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_directory/validate-release-lineage.py" assemble-readiness "$@"
