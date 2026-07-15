#!/usr/bin/env bash
# Read-only REL-009 writer. This entrypoint never invokes a transition RPC.
set -euo pipefail

script_directory="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_directory/validate-release-lineage.py" produce-switch-drill "$@"
