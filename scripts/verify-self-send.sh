#!/usr/bin/env bash
# Read-only check of one already-sent self-addressed Gmail message.
set -Eeuo pipefail
umask 077

die() { printf 'verify-self-send: %s\n' "$*" >&2; exit 1; }
for command_name in curl jq; do
  command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required"
done
for variable_name in AGENTMAIL_BASE_URL AGENTMAIL_ACCESS_KEY AGENTMAIL_CONNECTION_ID AGENTMAIL_GMAIL_MESSAGE_ID; do
  [[ -n ${!variable_name:-} ]] || die "missing $variable_name"
done
[[ $AGENTMAIL_ACCESS_KEY =~ ^amk_[0-9A-Fa-f-]{36}\.[A-Za-z0-9_-]+$ ]] || die 'invalid Access Key format'
[[ $AGENTMAIL_GMAIL_MESSAGE_ID =~ ^[A-Za-z0-9_-]+$ ]] || die 'invalid Gmail message ID'

for label in sent inbox; do
  cursor=''
  for page in {1..10}; do
    args=(--get --data-urlencode "q=in:$label" --data-urlencode 'page_size=100')
    [[ -z $cursor ]] || args+=(--data-urlencode "cursor=$cursor")
    response=$(env -u AGENTMAIL_ACCESS_KEY curl --silent --show-error --config /dev/fd/3 \
      "${args[@]}" --write-out $'\n%{http_code}' \
      "$AGENTMAIL_BASE_URL/api/v1/connections/$AGENTMAIL_CONNECTION_ID/messages" \
      3< <(printf 'header = "Authorization: Bearer %s"\n' "$AGENTMAIL_ACCESS_KEY")) \
      || die "$label search request failed"
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    [[ $status == 200 ]] || die "$label search returned HTTP $status"
    found=$(jq -er --arg id "$AGENTMAIL_GMAIL_MESSAGE_ID" \
      '(.messages | if type == "array" then any(.id == $id) else error("messages") end) | tostring' <<<"$body") \
      || die "$label search returned an unexpected response"
    if [[ $found == true ]]; then
      printf 'verify-self-send: %s HTTP 200 message_present=true\n' "$label"
      break
    fi
    cursor=$(jq -er '.next_cursor | if . == null then "" elif type == "string" then . else error("next_cursor") end' <<<"$body") \
      || die "$label search returned an unexpected cursor"
    [[ -n $cursor ]] || die "$label message was not found"
    (( page < 10 )) || die "$label message was not found within 10 pages"
  done
done
