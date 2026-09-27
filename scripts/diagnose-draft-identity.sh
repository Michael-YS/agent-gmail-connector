#!/usr/bin/env bash
# Read-only diagnostic for a single Gmail draft. Never prints mail content,
# headers, tokens, or the Message-ID itself.
set -Eeuo pipefail
umask 077

die() { printf 'draft-identity: %s\n' "$*" >&2; exit 1; }
for name in AGENTMAIL_BASE_URL AGENTMAIL_ACCESS_KEY AGENTMAIL_CONNECTION_ID AGENTMAIL_GMAIL_DRAFT_ID; do
  [[ -n ${!name:-} ]] || die "missing $name"
done
[[ $AGENTMAIL_ACCESS_KEY =~ ^amk_[0-9A-Fa-f-]{36}\.[A-Za-z0-9_-]+$ ]] || die 'invalid Access Key format'
command -v curl >/dev/null || die 'curl is required'
command -v jq >/dev/null || die 'jq is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'

url="$AGENTMAIL_BASE_URL/api/v1/connections/$AGENTMAIL_CONNECTION_ID/drafts/$AGENTMAIL_GMAIL_DRAFT_ID"
result=$(printf 'header = "Authorization: Bearer %s"\n' "$AGENTMAIL_ACCESS_KEY" |
  env -u AGENTMAIL_ACCESS_KEY curl --config - --silent --show-error --request GET \
    --write-out $'\n%{http_code}' "$url") || die 'draft GET failed'
status=${result##*$'\n'}
body=${result%$'\n'*}
if [[ $status != 200 ]]; then
  code=$(jq -r '.error.code // "unknown"' <<<"$body" 2>/dev/null || printf unknown)
  die "draft GET HTTP $status: $code"
fi
jq -e '.draft | type == "object"' <<<"$body" >/dev/null || die 'missing draft object'
identity=$(jq -r '.draft.stable_message_id // ""' <<<"$body")
managed=$(jq -r '.managed_by_agentmail // false' <<<"$body")
digest=$(printf '%s' "$identity" | sha256sum)
printf 'draft-identity: managed=%s identity_present=%s identity_length=%s identity_sha256=%s\n' \
  "$managed" "$([[ -n $identity ]] && printf true || printf false)" "${#identity}" "${digest%% *}"
