#!/usr/bin/env bash
# Real-Gmail smoke entry point (TESTING_GAPS A2/B6). Run on the VPS; make it
# executable once there: chmod +x scripts/smoke-gmail.sh
#
# Safety: the recipient allowlist is exactly one junk account
# (AGENTMAIL_SELF_ADDRESS); at most one message is sent per run; nothing is
# sent unless --send is given and confirmed (y/N prompt, or --yes when stdin
# is not a TTY). The Access Key and one-time confirmation token are never
# echoed or written to disk.
set -Eeuo pipefail
umask 077

say() { printf 'smoke-gmail: %s\n' "$*"; }
die() { printf 'smoke-gmail: %s\n' "$*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
usage: scripts/smoke-gmail.sh [--prepare-only] | [--send [--yes]]
       scripts/smoke-gmail.sh --resume-draft UUID --run-id UUID [--prepare-only | --send [--yes]]
required environment:
  AGENTMAIL_BASE_URL        e.g. http://127.0.0.1:18080
  AGENTMAIL_ACCESS_KEY      full amk_... credential (never echoed)
  AGENTMAIL_CONNECTION_ID   UUID of the junk-account connection
  AGENTMAIL_SELF_ADDRESS    the junk Gmail address; the only allowed recipient
EOF
}

mode=prepare
assume_yes=false
resume_draft=''
resume_run_id=''
while [[ $# -gt 0 ]]; do
  case $1 in
    --prepare-only) mode=prepare ;;
    --send) mode=send ;;
    --yes) assume_yes=true ;;
    --resume-draft)
      [[ $# -ge 2 ]] || die '--resume-draft requires a UUID'
      resume_draft=$2; shift ;;
    --run-id)
      [[ $# -ge 2 ]] || die '--run-id requires a UUID'
      resume_run_id=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done
[[ $mode == send || $assume_yes == false ]] || die '--yes is only valid together with --send'
if [[ -n $resume_draft || -n $resume_run_id ]]; then
  [[ -n $resume_draft && -n $resume_run_id ]] || die '--resume-draft and --run-id must be supplied together'
  uuid_pattern='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
  [[ $resume_draft =~ $uuid_pattern && $resume_run_id =~ $uuid_pattern ]] || die 'invalid resume UUID'
fi

command -v curl >/dev/null 2>&1 || die 'curl is required'
command -v jq >/dev/null 2>&1 || die 'jq is required'
for var in AGENTMAIL_BASE_URL AGENTMAIL_ACCESS_KEY AGENTMAIL_CONNECTION_ID AGENTMAIL_SELF_ADDRESS; do
  [[ -n ${!var:-} ]] || { printf 'smoke-gmail: missing required environment variable: %s\n' "$var" >&2; usage; exit 2; }
done
[[ $AGENTMAIL_ACCESS_KEY =~ ^amk_[0-9A-Fa-f-]{36}\.[A-Za-z0-9_-]+$ ]] || die 'invalid Access Key format'

uuid4() {
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi
}

# http METHOD PATH [JSON-BODY] [EXTRA-HEADER] -> sets STATUS and BODY.
http() {
  local out
  local args=(--silent --show-error --request "$1")
  [[ -n ${4:-} ]] && args+=(--header "$4")
  if [[ $# -ge 3 && -n $3 ]]; then
    args+=(--header 'Content-Type: application/json' --data-binary @-)
  fi
  out=$(printf '%s' "${3:-}" |
    env -u AGENTMAIL_ACCESS_KEY curl --config /dev/fd/3 "${args[@]}" \
      --write-out $'\n%{http_code}' "$AGENTMAIL_BASE_URL$2" \
      3< <(printf 'header = "Authorization: Bearer %s"\n' "$AGENTMAIL_ACCESS_KEY")) || die "request to $2 failed"
  STATUS=${out##*$'\n'}
  BODY=${out%$'\n'*}
}
check_status() { # check_status WHAT
  [[ $STATUS =~ ^2 ]] && return 0
  local code message
  code=$(jq -r '.error.code // "unknown"' <<<"$BODY" 2>/dev/null || printf unknown)
  message=$(jq -r '.error.message // "no JSON error envelope"' <<<"$BODY" 2>/dev/null || printf 'no JSON error envelope')
  die "HTTP $STATUS during $1: $code: $message"
}

http GET /health/live
check_status 'health/live'
live_status=$STATUS
http GET /health/ready
check_status 'health/ready'
say "health live=$live_status ready=$STATUS"

cid=$AGENTMAIL_CONNECTION_ID
http GET "/api/v1/connections/$cid/messages?q=in%3Ainbox&page_size=1"
check_status 'messages.search'
say "messages.search HTTP $STATUS (q=in:inbox, page_size=1)"

run_id=${resume_run_id:-$(uuid4)}
subject="[AgentMail E2E ${run_id}]"
if [[ -n $resume_draft ]]; then
  draft_id=$resume_draft
  say 'resuming existing managed draft; no draft created'
else
  body_text="AgentMail real-Gmail smoke draft. Run id: ${run_id}. Safe to discard."
  create_body=$(jq -nc --arg to "$AGENTMAIL_SELF_ADDRESS" --arg subject "$subject" --arg body "$body_text" \
    '{to:[$to],subject:$subject,body:$body}')
  idem_key=$(uuid4)
  http POST "/api/v1/connections/$cid/drafts" "$create_body" "Idempotency-Key: $idem_key"
  check_status 'drafts.create'
  draft_id=$(jq -er '.managed_draft.id' <<<"$BODY") || die 'drafts.create response had no managed_draft.id'
  say "drafts.create HTTP $STATUS (idempotency-key $idem_key)"
fi

http POST "/api/v1/connections/$cid/drafts/$draft_id/prepare-send" ''
check_status 'prepare-send'
confirmation_token=$(jq -er '.confirmation_token' <<<"$BODY") || die 'prepare-send response had no confirmation_token'
recipient_count=$(jq -r '[.preview.to[], .preview.cc[], .preview.bcc[]] | length' <<<"$BODY")
all_recipients_match_self=$(jq -r --arg self "$AGENTMAIL_SELF_ADDRESS" \
  '([.preview.to[], .preview.cc[], .preview.bcc[]] | length == 1) and
   ([.preview.to[], .preview.cc[], .preview.bcc[]][] | ascii_downcase == ($self | ascii_downcase))' \
  <<<"$BODY")
sender_matches_self=$(jq -r --arg self "$AGENTMAIL_SELF_ADDRESS" \
  '(.preview.from // "" | ascii_downcase) == ($self | ascii_downcase)' <<<"$BODY")
subject_matches_run=$(jq -r --arg subject "$subject" \
  '.preview.subject == $subject' <<<"$BODY")
# Security boundary: message bodies (and their summaries) must never reach
# logs or CI output. Only metadata — presence and length — is reported.
body_len=$(jq -r '(.preview.body_summary // "") | length' <<<"$BODY")
attachment_count=$(jq -r '(.preview.attachment_names // []) | length' <<<"$BODY")
say "prepare-send HTTP $STATUS"
say "run-id: $run_id"
say "draft id: $draft_id"
say "recipient count: $recipient_count"
say "subject: withheld (script-generated E2E marker; run-id above)"
say "body summary: withheld (present=$([[ $body_len -gt 0 ]] && echo yes || echo no), length=${body_len} chars)"
say "attachment count: $attachment_count"

if [[ $mode == prepare ]]; then
  say 'prepare-only run complete; nothing was sent'
  exit 0
fi

# Hard allowlist: refuse to send to anything but the single self address.
[[ "$all_recipients_match_self" == true ]] \
  || die 'allowlist violation: preview recipients are not exactly one configured self address'
[[ "$sender_matches_self" == true ]] \
  || die 'allowlist violation: preview sender is not the configured self address'
[[ "$subject_matches_run" == true && "$attachment_count" == 0 ]] \
  || die 'preview changed: subject or attachments differ from this smoke run'

if [[ $assume_yes == false ]]; then
  [[ -t 0 ]] || die 'stdin is not a TTY; rerun with --send --yes to confirm non-interactively'
  printf 'smoke-gmail: send 1 message to %s (run-id %s)? [y/N] ' "$AGENTMAIL_SELF_ADDRESS" "$run_id"
  reply=''
  read -r reply || reply=''
  [[ $reply == [yY] ]] || die 'aborted by user; nothing was sent'
fi

send_body=$(jq -nc --arg token "$confirmation_token" '{confirmation_token:$token}')
http POST "/api/v1/connections/$cid/drafts/$draft_id/send" "$send_body"
check_status 'drafts.send'
say "drafts.send HTTP $STATUS outcome=$(jq -r '.outcome // "unknown"' <<<"$BODY") replayed=$(jq -r '.replayed // false' <<<"$BODY")"
