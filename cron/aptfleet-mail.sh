#!/usr/bin/env bash
# Führt aptfleet.py aus (z. B. per Cronjob) und verschickt das Ergebnis per Mail:
# Text-Report als Mailtext, HTML-Report eingebettet und als Anhang.
#
# Aufruf: aptfleet-mail.sh [--dry-run] [ENV-DATEI]   (Default: /etc/aptfleet/mail.env)
#   --dry-run  Mail immer erzeugen und auf stdout ausgeben statt verschicken
# Konfiguration: siehe mail.env.sample
#
# Exit-Code: der von aptfleet.py; 4, wenn der Mailversand fehlschlägt;
# 5 bei Konfigurationsfehlern.
set -uo pipefail

DRY_RUN=0
if [ "${1:-}" = --dry-run ]; then
  DRY_RUN=1
  shift
fi
ENV_FILE="${1:-/etc/aptfleet/mail.env}"
if [ ! -r "$ENV_FILE" ]; then
  echo "aptfleet-mail: Konfiguration $ENV_FILE nicht lesbar" >&2
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
MAIL_SUBJECT_PREFIX="${MAIL_SUBJECT_PREFIX:-[updates]}"
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

[ -n "$MAIL_TO" ] || [ "$MAIL_TRANSPORT" = print ] || die "MAIL_TO ist nicht gesetzt ($ENV_FILE)"
case "$MAIL_WHEN" in always|problems) ;; *) die "MAIL_WHEN muss always oder problems sein" ;; esac
case "$MAIL_TRANSPORT" in sendmail|smtp|print) ;; *) die "MAIL_TRANSPORT muss sendmail, smtp oder print sein" ;; esac
if [ "$MAIL_TRANSPORT" = smtp ]; then
  [ -n "${SMTP_URL:-}" ] || die "MAIL_TRANSPORT=smtp braucht SMTP_URL"
  command -v curl >/dev/null || die "MAIL_TRANSPORT=smtp braucht curl"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aptfleet-mail.XXXXXX")" || die "mktemp fehlgeschlagen"
trap 'rm -rf "$WORK"' EXIT

STAMP="$(date +%Y-%m-%d_%H%M)"
HTML_NAME="updates-${HOST}-${STAMP}.html"
HTML_FILE="$WORK/$HTML_NAME"
TEXT_FILE="$WORK/report.txt"

# APTFLEET_ARGS wird an Leerzeichen getrennt (Pfade mit Leerzeichen gehen also nicht).
read -r -a args <<< "$APTFLEET_ARGS"
"$PYTHON" "$APTFLEET" ${args[@]+"${args[@]}"} --no-progress --html "$HTML_FILE" \
  >"$TEXT_FILE" 2>&1 </dev/null
rc=$?
# Den Hinweis auf die (gleich gelöschte) temporäre HTML-Datei nicht mitschicken.
grep -vF "HTML-Report geschrieben: $HTML_FILE" "$TEXT_FILE" > "$TEXT_FILE.tmp"
mv "$TEXT_FILE.tmp" "$TEXT_FILE"

case "$rc" in
  0) status="keine dringenden Updates" ;;
  1) status="Security-Updates oder offene KEV-Lücke" ;;
  2) status="FEHLER: Host nicht erreichbar oder Aufruffehler" ;;
  3) status="Prüfung unvollständig" ;;
  *) status="FEHLER: aptfleet.py endete mit Code $rc" ;;
esac

if [ -n "$REPORT_DIR" ] && [ -f "$HTML_FILE" ]; then
  if mkdir -p "$REPORT_DIR" && cp "$HTML_FILE" "$REPORT_DIR/$HTML_NAME"; then
    find "$REPORT_DIR" -maxdepth 1 -name 'updates-*.html' -mtime "+$REPORT_KEEP_DAYS" -delete 2>/dev/null
  else
    echo "aptfleet-mail: HTML-Report nicht in $REPORT_DIR ablegbar" >&2
  fi
fi

# problems: Mail nur bei Handlungsbedarf oder Fehlern, also Exit-Code != 0.
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

# Empfänger für die SMTP-Übergabe: durch Komma und/oder Leerzeichen getrennt.
read -r -a rcpts <<< "${MAIL_TO//,/ }"

case "$MAIL_TRANSPORT" in
  print)
    cat "$MSG"
    ;;
  sendmail)
    # shellcheck disable=SC2086  # SENDMAIL darf Optionen enthalten
    $SENDMAIL -i -f "$MAIL_FROM" -- "${rcpts[@]}" < "$MSG" \
      || { echo "aptfleet-mail: Versand per $SENDMAIL fehlgeschlagen" >&2; exit 4; }
    ;;
  smtp)
    curl_args=(--silent --show-error --url "$SMTP_URL" --mail-from "$MAIL_FROM" --upload-file "$MSG")
    for r in "${rcpts[@]}"; do curl_args+=(--mail-rcpt "$r"); done
    [ "${SMTP_STARTTLS:-0}" = 1 ] && curl_args+=(--ssl-reqd)
    # Zugangsdaten per stdin-Config statt Kommandozeile (sonst in `ps` sichtbar).
    if [ -n "${SMTP_USER:-}" ]; then
      creds="$SMTP_USER:${SMTP_PASSWORD:-}"
      creds="${creds//\\/\\\\}"; creds="${creds//\"/\\\"}"
      printf 'user = "%s"\n' "$creds" \
        | curl "${curl_args[@]}" --config - \
        || { echo "aptfleet-mail: SMTP-Versand an $SMTP_URL fehlgeschlagen" >&2; exit 4; }
    else
      curl "${curl_args[@]}" \
        || { echo "aptfleet-mail: SMTP-Versand an $SMTP_URL fehlgeschlagen" >&2; exit 4; }
    fi
    ;;
esac
exit "$rc"
