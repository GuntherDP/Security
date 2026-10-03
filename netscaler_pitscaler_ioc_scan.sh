#!/usr/bin/env bash
#
# netscaler_pitscaler_ioc_scan.sh
#
# Version: 1.0
# Author: Gunther De Poortere - Xcellerate - support@xcellerate.be
# License: MIT (see LICENSE). Provided AS IS, no warranty.
#
# IoC triage scanner for Citrix NetScaler ADC / Gateway:
#   - CVE-2026-88771 / CVE-2026-88772 (bulletin CTX697096)
#   - artefacts tied to the separate SAML issue (Citrix guidance 2 Oct 2026, no CVE yet)
#
# IoC source : PitScaler public IoC list https://pitscaler.com/netscaler-iocs/
#              (snapshot "last updated 3 October 2026, 09:10 UTC") = pitscaler-iocs.csv
#
# SAFETY     : NOTHING that is inspected is executed, sourced, loaded or interpreted.
#              Files are only READ (od, grep, sha256/sha256sum, stat). No network traffic.
#              PATH is reset so attacker-planted binaries elsewhere are not picked up.
#              On a rooted appliance the system tools themselves can be trojaned:
#              a live scan is triage, not forensics.
#
# Usage      : ./netscaler_pitscaler_ioc_scan.sh [/absolute/path/report.txt]
#              NO_COLOR=1            -> disable colours
#              STRICT_CUSTOMSNMPD=0  -> script at customsnmpd path without reverse-shell
#                                       markers becomes SUSPECTED instead of CONFIRMED
# Exit codes : 0 = nothing above WARNING, 1 = SUSPECTED, 2 = CONFIRMED, 3 = error
#
# Levels     : GREEN OK | YELLOW WARNING | ORANGE SUSPECTED | RED CONFIRMED
#              Report file gets identical text, without colour codes.

set -u
set -o pipefail
umask 077
export LC_ALL=C
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
unset CDPATH ENV BASH_ENV
shopt -s nullglob

if [ -z "${BASH_VERSINFO+x}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    printf 'ERROR: bash >= 4 required\n' >&2; exit 3
fi
if [ "$EUID" -ne 0 ]; then
    printf 'ERROR: must run as root\n' >&2; exit 3
fi

STRICT_CUSTOMSNMPD="${STRICT_CUSTOMSNMPD:-1}"
MAX_SCAN_KB=32768      # files above this size are not hashed / content-scanned
MAX_HITS=50            # max printed hits per log file per level
MAX_TTY_LEN=300        # terminal line truncation (report keeps full line)

# ---------------------------------------------------------------- report file
REPORT="${1:-/var/tmp/pitscaler_ioc_report_$(date -u +%Y%m%d_%H%M%S).txt}"
case "$REPORT" in
    *$'\n'*|*$'\r'*) printf 'ERROR: invalid report path\n' >&2; exit 3 ;;
    /*) ;;
    *) printf 'ERROR: report path must be absolute\n' >&2; exit 3 ;;
esac
if [ -e "$REPORT" ] || [ -L "$REPORT" ]; then
    printf 'ERROR: %s already exists, refusing to overwrite\n' "$REPORT" >&2; exit 3
fi
if ! ( set -C; : > "$REPORT" ) 2>/dev/null; then
    printf 'ERROR: cannot create %s\n' "$REPORT" >&2; exit 3
fi
SELF_SRC="${BASH_SOURCE[0]:-$0}"
SELF_PATH="$(cd -- "$(dirname -- "$SELF_SRC")" 2>/dev/null && pwd -P)/${SELF_SRC##*/}"

# ---------------------------------------------------------------- colours
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'; C_RED=$'\033[1;31m'
    C_BLUE=$'\033[0;36m';  C_BOLD=$'\033[1m';      C_RESET=$'\033[0m'
    case "${TERM:-}" in
        *256color*|*truecolor*|xterm-kitty|alacritty) C_ORANGE=$'\033[38;5;208m' ;;
        *) C_ORANGE=$'\033[1;33m' ;;   # 8/16-colour terminal: no real orange, bold yellow
    esac
else
    C_GREEN=''; C_YELLOW=''; C_ORANGE=''; C_RED=''; C_BLUE=''; C_BOLD=''; C_RESET=''
fi

# ---------------------------------------------------------------- output
N_CONF=0; N_SUSP=0; N_WARN=0

_emit() {   # colour tag message ; control chars stripped (log lines are attacker-controlled)
    local color="$1" tag="$2" msg="$3" tmsg
    msg="${msg//[[:cntrl:]]/?}"
    tmsg="$msg"
    if [ "${#tmsg}" -gt "$MAX_TTY_LEN" ]; then
        tmsg="${tmsg:0:$MAX_TTY_LEN} ...[truncated, full line in report]"
    fi
    printf '%s[%s]%s %s\n' "$color" "$tag" "$C_RESET" "$tmsg"
    printf '[%s] %s\n' "$tag" "$msg" >> "$REPORT"
}
ok()      { _emit "$C_GREEN"  "OK"        "$*"; }
info()    { _emit "$C_BLUE"   "INFO"      "$*"; }
warn()    { N_WARN=$((N_WARN+1)); _emit "$C_YELLOW" "WARNING"   "$*"; }
suspect() { N_SUSP=$((N_SUSP+1)); _emit "$C_ORANGE" "SUSPECTED" "$*"; }
confirm() { N_CONF=$((N_CONF+1)); _emit "$C_RED"    "CONFIRMED" "$*"; }
emit_level() {
    local l="$1"; shift
    case "$l" in
        C) confirm "$@" ;; S) suspect "$@" ;; W) warn "$@" ;; OK) ok "$@" ;; *) info "$@" ;;
    esac
}
detail() {
    local m="$*"
    m="${m//[[:cntrl:]]/?}"
    printf '          %s\n' "$m"
    printf '          %s\n' "$m" >> "$REPORT"
}
section() {
    printf '\n%s===== %s =====%s\n' "$C_BOLD" "$*" "$C_RESET"
    printf '\n===== %s =====\n' "$*" >> "$REPORT"
}

# ---------------------------------------------------------------- portability helpers
if stat -f '%z' / >/dev/null 2>&1; then STAT_FLAVOR=bsd; else STAT_FLAVOR=gnu; fi

file_meta() {
    local out=""
    if [ "$STAT_FLAVOR" = bsd ]; then
        out=$(stat -f '%Sp owner=%Su:%Sg size=%z mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' -- "$1" 2>/dev/null)
    else
        out=$(stat -c '%A owner=%U:%G size=%s mtime=%y' -- "$1" 2>/dev/null)
    fi
    printf '%s' "${out:-stat failed}"
}
file_perms_L() {   # follows symlinks
    if [ "$STAT_FLAVOR" = bsd ]; then stat -L -f '%Sp' -- "$1" 2>/dev/null
    else stat -L -c '%A' -- "$1" 2>/dev/null; fi
}
file_size() {
    if [ "$STAT_FLAVOR" = bsd ]; then stat -f '%z' -- "$1" 2>/dev/null
    else stat -c '%s' -- "$1" 2>/dev/null; fi
}
too_big() {
    local s; s=$(file_size "$1")
    [ -n "$s" ] && [ "$s" -gt $((MAX_SCAN_KB * 1024)) ]
}

if command -v sha256sum >/dev/null 2>&1; then HASH_TOOL=sha256sum
elif command -v sha256 >/dev/null 2>&1;  then HASH_TOOL=sha256
elif command -v openssl >/dev/null 2>&1; then HASH_TOOL=openssl
else HASH_TOOL=none; fi

hash_file() {
    local h=""
    case "$HASH_TOOL" in
        sha256sum) h=$(sha256sum -- "$1" 2>/dev/null); h="${h#\\}"; h="${h%% *}" ;;
        sha256)    h=$(sha256 -q -- "$1" 2>/dev/null) ;;
        openssl)   h=$(openssl dgst -sha256 -r "$1" 2>/dev/null); h="${h%% *}" ;;
    esac
    h="${h,,}"
    if [[ "$h" =~ ^[0-9a-f]{64}$ ]]; then printf '%s' "$h"; fi
}

# File type from magic bytes. Reads bytes only, never runs anything.
ftype() {
    local f="$1" hex tarm
    [ -f "$f" ] || { printf 'notfile'; return; }
    [ -s "$f" ] || { printf 'empty'; return; }
    hex=$(od -An -tx1 -N 32 -v -- "$f" 2>/dev/null); hex="${hex//[[:space:]]/}"
    case "$hex" in
        7f454c46*)                                   printf 'elf' ;;
        213c617263683e0a64656269616e2d62696e617279*) printf 'deb' ;;
        213c617263683e0a*)                           printf 'ar' ;;
        edabeedb*)                                   printf 'rpm' ;;
        1f8b*)                                       printf 'gzip' ;;
        425a68*)                                     printf 'bzip2' ;;
        fd377a585a00*)                               printf 'xz' ;;
        504b0304*)                                   printf 'zip' ;;
        4d5a*)                                       printf 'pe' ;;
        cafebabe*|cffaedfe*|cefaedfe*|feedface*|feedfacf*) printf 'macho' ;;
        2321*)                                       printf 'script' ;;
        *)
            tarm=$(od -An -tx1 -j 257 -N 5 -v -- "$f" 2>/dev/null); tarm="${tarm//[[:space:]]/}"
            if [ "$tarm" = "7573746172" ]; then printf 'tar'
            elif od -An -tx1 -N 8192 -v -- "$f" 2>/dev/null | grep -qw '00'; then printf 'data'
            else printf 'text'; fi ;;
    esac
}

has_php()         { grep -aqE '<\?php' -- "$1" 2>/dev/null; }
has_php_any()     { grep -aqE '<\?(php|=)' -- "$1" 2>/dev/null; }
has_webshell_fn() { grep -aqiE '(eval|assert|system|passthru|shell_exec|proc_open|popen|pcntl_exec|base64_decode|gzinflate|str_rot13|create_function)[[:space:]]*\(' -- "$1" 2>/dev/null; }
has_revshell()    { grep -aqiE 'socket\.socket|subprocess|pty\.spawn|os\.dup2|/bin/sh|/bin/bash|/dev/tcp/|connect\(\(|nc -e|45\.141\.21\.130' -- "$1" 2>/dev/null; }
has_shell_cmds()  { grep -aqiE '(^|[;|&[:space:]])(curl|wget|fetch|nc|perl|python[0-9.]*|sh|bash|chmod|base64)[[:space:]]' -- "$1" 2>/dev/null; }

re_escape() {
    local s="$1" out="" c i
    for (( i=0; i<${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            '.'|'['|']'|'^'|'$'|'*'|'+'|'?'|'('|')'|'{'|'}'|'|'|"\\") out+="\\$c" ;;
            *) out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}
ip_in_line() {   # $1 ip  $2 line ; true if ip appears with non-digit boundaries
    local re="(^|[^0-9])${1//./\\.}([^0-9]|\$)"
    [[ "$2" =~ $re ]]
}

# One process snapshot, taken once. Read-only.
PS_SNAPSHOT=$(ps axww -o pid= -o command= 2>/dev/null || true)
PROCSTAT_SNAPSHOT=""
if command -v procstat >/dev/null 2>&1; then
    PROCSTAT_SNAPSHOT=$(procstat -b -a 2>/dev/null || true)
fi
running_matches() {   # full-path token match only (avoids '/v' matching '/var/...')
    local re
    re="(^|[[:space:]=:])$(re_escape "$1")([[:space:]]|\$)"
    printf '%s\n%s\n' "$PS_SNAPSHOT" "$PROCSTAT_SNAPSHOT" | grep -E -- "$re" 2>/dev/null
}
print_procs() {
    local l
    while IFS= read -r l; do [ -n "$l" ] && detail "process: $l"; done <<< "$1"
}

declare -A REPORTED=()
declare -A HASHED=()
mark()   { REPORTED["$1"]=1; }
is_seen(){ [ -n "${REPORTED[$1]:-}" ]; }
is_excluded() {
    case "$1" in
        "$REPORT"|"$SELF_PATH"|*/pitscaler_ioc_report_*) return 0 ;;
    esac
    return 1
}
realdir() { (cd -P -- "$1" 2>/dev/null && pwd -P); }

# ---------------------------------------------------------------- IoC data
# Known-bad SHA-256 (PitScaler list). Many are per-victim / per-build: absence proves nothing.
# Excluded on purpose: Unit 42 "Figure 1/2" hashes (hashes of text reproductions, not files).
declare -A KNOWN_HASHES=(
  ["6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"]="webshell (GreyNoise)"
  ["ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1"]=".ctxs.receiver sample (IFIN, single victim)"
  ["5ea5ea61e9062822bee3f66ef5ff47c217178d9e31936ad6daf10c5dfae44d12"]="PHP webshell .ico variant (eSentire/Sygnia)"
  ["7add390ceee4a1373211b3e340451b34f08965fc4d805f94c9b8cebdc0775774"]="PHP webshell .deb variant (eSentire)"
  ["73b74309f4728d169cc9edfb2767c5aadd75d39b62de93c935a86c777d2646bc"]="payload /xd7h/x (Arctic Wolf)"
  ["9c7bf01d2c2cb31a3609d27c1bc9abc60d86e37b7f9908547e0c75fb18b99aab"]="nsmon.pl implant (Arctic Wolf)"
  ["57f9f30c50240fd48d761de7961a430cdebf2c084a36bc76d376a1ce8e6dfa9d"]="initial payload via 62.133.62.80 (Arctic Wolf)"
  ["974b69782fdf5d67b97cfd508465939e44ee10798dbcc1e82b92d78776bad938"]="update_c08937.pl (Arctic Wolf/LevelBlue)"
  ["927c7fbef2e620c1ce482c3ed67ebf53da97693c1d6c7552c77aec84ba982cf8"]="Platypus agent shell script (Arctic Wolf)"
  ["ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec"]="nsg64.deb RC4 PHP webshell (Unit 42)"
  ["e9fe43968c6c0955300e3bc4d7fb0b05a18570b4733aaf4f5c6f7f09be5a242c"]="main.py customsnmpd reverse-shell overwrite (LevelBlue)"
  ["c98aee7
