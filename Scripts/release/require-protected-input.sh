#!/usr/bin/env bash
# Requires explicitly named, non-empty protected inputs without exposing values.
set -euo pipefail

usage() {
    printf 'Usage: %s VARIABLE_NAME [VARIABLE_NAME ...]\n' "${0##*/}" >&2
    printf 'Each variable name must be an uppercase environment variable and have a non-empty value.\n' >&2
    exit 64
}

fail() {
    printf 'protected input error: %s\n' "$1" >&2
    exit 65
}

[[ "$#" -gt 0 ]] || usage

for variable_name in "$@"; do
    [[ "$variable_name" =~ ^[A-Z][A-Z0-9_]*$ ]] || fail "invalid variable name: $variable_name"

    if [[ -z "${!variable_name-}" ]]; then
        fail "required protected input is unset or empty: $variable_name"
    fi
done
