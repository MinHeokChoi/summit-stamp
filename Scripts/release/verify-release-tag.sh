#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: verify-release-tag.sh --tag TAG --commit COMMIT' >&2
}

fail() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

tag=''
commit=''
while (($#)); do
  case "$1" in
    --tag)
      (($# >= 2)) || fail 'missing value for --tag'
      tag="$2"
      shift 2
      ;;
    --commit)
      (($# >= 2)) || fail 'missing value for --commit'
      commit="$2"
      shift 2
      ;;
    *)
      usage
      fail 'unsupported argument'
      ;;
  esac
done

[[ -n "$tag" ]] || fail 'missing --tag'
[[ -n "$commit" ]] || fail 'missing --commit'
[[ "$tag" != -* ]] || fail 'invalid tag'
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail 'commit must be a full lowercase SHA-1'

fingerprint="${HIKER_RELEASE_TAG_SIGNING_FINGERPRINT:-}"
[[ "$fingerprint" =~ ^[A-F0-9]{40,64}$ ]] || fail 'release tag signing fingerprint is unavailable or invalid'

git check-ref-format "refs/tags/$tag" >/dev/null || fail 'invalid tag ref'
object_type="$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" || fail 'tag does not exist'
[[ "$object_type" == 'tag' ]] || fail 'release tag must be annotated'
resolved_commit="$(git rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null)" || fail 'tag does not resolve to a commit'
[[ "$resolved_commit" == "$commit" ]] || fail 'tag does not resolve to the expected commit'

verification=''
if ! verification="$(git verify-tag --raw "refs/tags/$tag" 2>&1)"; then
  fail 'release tag signature verification failed'
fi

valid_signature='false'
while IFS= read -r line; do
  case "$line" in
    '[GNUPG:] VALIDSIG '*)
      read -r _ status signing_fingerprint remainder <<<"$line"
      [[ "$status" == 'VALIDSIG' ]] || continue
      primary_fingerprint=''
      for field in $remainder; do
        primary_fingerprint="$field"
      done
      if [[ "$signing_fingerprint" == "$fingerprint" || "$primary_fingerprint" == "$fingerprint" ]]; then
        [[ "$valid_signature" == 'false' ]] || fail 'multiple matching valid signatures are not allowed'
        valid_signature='true'
      fi
      ;;
  esac
done <<<"$verification"

[[ "$valid_signature" == 'true' ]] || fail 'release tag signer fingerprint does not match the protected configuration'
printf '%s\n' "verified signed release tag $tag at $commit"
