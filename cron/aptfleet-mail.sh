#!/usr/bin/env bash
# Runs aptfleet.py (e.g. from a cron job) and mails the result:
# text report as the mail body, HTML report inline and as an attachment.
#
# Usage: aptfleet-mail.sh [--dry-run] [ENV_FILE]   (default: /etc/aptfleet/mail.env)
#   --dry-run  always build the mail and print it to stdout instead of sending it
# Configuration: see mail.env.sample
#
# Exit code: that of aptfleet.py; 4 if mail delivery fails;
# 5 on configuration errors.
set -uo pipefail

DRY_RUN=0
if [ "${1:-}" = --dry-run ]; then
  DRY_RUN=1
  shift
fi
ENV_FILE="${1:-/etc/aptfleet/mail.env}"
if [ ! -r "$ENV_FILE" ]; then
  echo "aptfleet-mail: cannot read configuration $ENV_FILE" >&2
  exit 5
fi
# shellcheck source=/dev/null
. "$ENV_FILE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APTFLEET="${APTFLEET:-$SCRIPT_DIR/../aptfleet.py}"
PYTHON="${PYTHON:-python3}"
APTFLEET_ARGS="${APTFLEET_ARGS:---local --details}"
MAIL_TO="${MAIL_TO:-}"
MAIL_WHEN="${MAIL_WHEN:-problems}"
MAIL_TRANSPORT="${MAIL_TRANSPORT:-sendmail}"
MAIL_SUBJECT_PREFIX="${MAIL_SUBJECT_PREFIX:-[aptfleet]}"
MAIL_HTML_INLINE="${MAIL_HTML_INLINE:-1}"
SENDMAIL="${SENDMAIL:-/usr/sbin/sendmail}"
REPORT_DIR="${REPORT_DIR:-}"
REPORT_KEEP_DAYS="${REPORT_KEEP_DAYS:-30}"

FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST="${REPORT_NAME:-$(hostname)}"
MAIL_FROM="${MAIL_FROM:-aptfleet@$FQDN}"
if [ "$DRY_RUN" = 1 ]; then
  MAIL_TRANSPORT=print
  MAIL_WHEN=always
fi

die() { echo "aptfleet-mail: $*" >&2; exit 5; }

[ -n "$MAIL_TO" ] || [ "$MAIL_TRANSPORT" = print ] || die "MAIL_TO is not set ($ENV_FILE)"
case "$MAIL_WHEN" in always|problems) ;; *) die "MAIL_WHEN must be always or problems" ;; esac
case "$MAIL_TRANSPORT" in sendmail|smtp|print) ;; *) die "MAIL_TRANSPORT must be sendmail, smtp or print" ;; esac
if [ "$MAIL_TRANSPORT" = smtp ]; then
  [ -n "${SMTP_URL:-}" ] || die "MAIL_TRANSPORT=smtp requires SMTP_URL"
  command -v curl >/dev/null || die "MAIL_TRANSPORT=smtp requires curl"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aptfleet-mail.XXXXXX")" || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

STAMP="$(date +%Y-%m-%d_%H%M)"
HTML_NAME="updates-${HOST}-${STAMP}.html"
HTML_FILE="$WORK/$HTML_NAME"
TEXT_FILE="$WORK/report.txt"

# APTFLEET_ARGS is split on whitespace (so paths containing spaces do not work).
read -r -a args <<< "$APTFLEET_ARGS"
"$PYTHON" "$APTFLEET" ${args[@]+"${args[@]}"} --no-progress --html "$HTML_FILE" \
  >"$TEXT_FILE" 2>&1 </dev/null
rc=$?
# Drop the note about the temporary HTML file (deleted right after) from the mail.
grep -vF "HTML report written: $HTML_FILE" "$TEXT_FILE" > "$TEXT_FILE.tmp"
mv "$TEXT_FILE.tmp" "$TEXT_FILE"

case "$rc" in
  0) status="no urgent updates" ;;
  1) status="security updates or open KEV vulnerability" ;;
  2) status="ERROR: host unreachable or usage error" ;;
  3) status="check incomplete" ;;
  *) status="ERROR: aptfleet.py exited with code $rc" ;;
esac

if [ -n "$REPORT_DIR" ] && [ -f "$HTML_FILE" ]; then
  if mkdir -p "$REPORT_DIR" && cp "$HTML_FILE" "$REPORT_DIR/$HTML_NAME"; then
    find "$REPORT_DIR" -maxdepth 1 -name 'updates-*.html' -mtime "+$REPORT_KEEP_DAYS" -delete 2>/dev/null
  else
    echo "aptfleet-mail: cannot store HTML report in $REPORT_DIR" >&2
  fi
fi

# problems: mail only when action is needed or on errors, i.e. exit code != 0.
if [ "$MAIL_WHEN" = problems ] && [ "$rc" -eq 0 ]; then
  exit 0
fi

b64() { base64 | tr -d '\n' | fold -w 76; echo; }
encode_header() { printf '=?UTF-8?B?%s?=' "$(printf '%s' "$1" | base64 | tr -d '\n')"; }

BOUNDARY_MIXED="mixed-$$-$(date +%s)"
BOUNDARY_ALT="alt-$$-$(date +%s)"
MSG="$WORK/message.eml"
{
  printf 'From: %s\n' "$MAIL_FROM"
  printf 'To: %s\n' "$MAIL_TO"
  printf 'Subject: %s\n' "$(encode_header "$MAIL_SUBJECT_PREFIX $HOST: $status")"
  printf 'Date: %s\n' "$(LC_ALL=C date '+%a, %d %b %Y %H:%M:%S %z')"
  printf 'Message-ID: <aptfleet.%s.%s@%s>\n' "$(date +%s)" "$$" "$FQDN"
  printf 'MIME-Version: 1.0\n'
  printf 'Auto-Submitted: auto-generated\n'
  printf 'Content-Type: multipart/mixed; boundary="%s"\n\n' "$BOUNDARY_MIXED"

  printf -- '--%s\n' "$BOUNDARY_MIXED"
  if [ "$MAIL_HTML_INLINE" = 1 ] && [ -f "$HTML_FILE" ]; then
    printf 'Content-Type: multipart/alternative; boundary="%s"\n\n' "$BOUNDARY_ALT"
    printf -- '--%s\n' "$BOUNDARY_ALT"
  fi
  printf 'Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n'
  b64 < "$TEXT_FILE"
  if [ "$MAIL_HTML_INLINE" = 1 ] && [ -f "$HTML_FILE" ]; then
    printf -- '--%s\n' "$BOUNDARY_ALT"
    printf 'Content-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n'
    b64 < "$HTML_FILE"
    printf -- '--%s--\n' "$BOUNDARY_ALT"
  fi

  if [ -f "$HTML_FILE" ]; then
    printf -- '--%s\n' "$BOUNDARY_MIXED"
    printf 'Content-Type: text/html; charset=utf-8; name="%s"\n' "$HTML_NAME"
    printf 'Content-Disposition: attachment; filename="%s"\n' "$HTML_NAME"
    printf 'Content-Transfer-Encoding: base64\n\n'
    b64 < "$HTML_FILE"
  fi
  printf -- '--%s--\n' "$BOUNDARY_MIXED"
} > "$MSG"

# Recipients for the SMTP envelope: separated by commas and/or spaces.
read -r -a rcpts <<< "${MAIL_TO//,/ }"

case "$MAIL_TRANSPORT" in
  print)
    cat "$MSG"
    ;;
  sendmail)
    # shellcheck disable=SC2086  # SENDMAIL may contain options
    $SENDMAIL -i -f "$MAIL_FROM" -- "${rcpts[@]}" < "$MSG" \
      || { echo "aptfleet-mail: sending mail via $SENDMAIL failed" >&2; exit 4; }
    ;;
  smtp)
    curl_args=(--silent --show-error --url "$SMTP_URL" --mail-from "$MAIL_FROM" --upload-file "$MSG")
    for r in "${rcpts[@]}"; do curl_args+=(--mail-rcpt "$r"); done
    [ "${SMTP_STARTTLS:-0}" = 1 ] && curl_args+=(--ssl-reqd)
    # Pass credentials via a config on stdin, not the command line (otherwise visible in `ps`).
    if [ -n "${SMTP_USER:-}" ]; then
      creds="$SMTP_USER:${SMTP_PASSWORD:-}"
      creds="${creds//\\/\\\\}"; creds="${creds//\"/\\\"}"
      printf 'user = "%s"\n' "$creds" \
        | curl "${curl_args[@]}" --config - \
        || { echo "aptfleet-mail: sending mail via SMTP to $SMTP_URL failed" >&2; exit 4; }
    else
      curl "${curl_args[@]}" \
        || { echo "aptfleet-mail: sending mail via SMTP to $SMTP_URL failed" >&2; exit 4; }
    fi
    ;;
esac
exit "$rc"
