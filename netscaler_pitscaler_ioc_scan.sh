#!/usr/bin/env bash
#
# Name: netscaler_pitscaler_ioc_scan.sh
# Version: 1.5
# Author: Gunther De Poortere
# License: MIT + COMMONS CLAUSE (see LICENSE). Provided AS IS, no warranty.
#
# IoC triage scanner for Citrix NetScaler ADC / Gateway:
#   - CVE-2026-88771 / CVE-2026-88772 (bulletin CTX697096)
#   - artefacts tied to the separate SAML issue (Citrix guidance 2 Oct 2026, no CVE yet)
#   - SAML 2026 Go implant campaign: pylrk.cc / pyrlnk.cc dropper (.nsl payload)
#
# IoC source : PitScaler public IoC list https://pitscaler.com/netscaler-iocs/
#              (snapshot "last updated 3 October 2026, 09:10 UTC") = pitscaler-iocs.csv
#            + SAML 2026 dropper analysis (pylrk.cc/pyrlnk.cc campaign, f.pylrk.cc delivery):
#              /nsconfig/.nsl Go implant, /var/nslog/.nsl fallback, ns_ctx.html uname marker,
#              rc.netscaler persistence (nohup /nsconfig/.nsl /dev/null 2>&1 &)
#
# Compat     : GNU bash >= 3.2 (NetScaler ships 3.2.57 on FreeBSD).
#              No associative arrays, no ${var,,}, no process substitution, no stat(1).
#              Scratch lists go to a private mktemp dir (mode 700) under /var/tmp.
#
# SAFETY     : NOTHING that is inspected is executed, sourced, loaded or interpreted.
#              Files are only READ (od, grep, head, tail, ls, find, sha256 for one baseline).
#              No eval. No network traffic. PATH is reset.
#              On a rooted appliance system tools can be trojaned: triage, not forensics.
#
# Usage      : bash ./netscaler_pitscaler_ioc_scan.sh [/absolute/path/report.txt]
#              NO_COLOR=1                 disable colours
#              CHANGE_DAYS=30             window for customsnmpd change check (days)
#              NS_BACKUP_PL_SHA256=<hex>  baseline hash for /var/tmp/ns_system_backup.pl
#              CUSTOMSNMPD_SHA256=<hex>   baseline hash for /var/python/bin/customsnmpd (per firmware build)
#              OWN_CMD_MODULES="CLI GUI UI"  CMD_EXECUTED modules skipped in logs when the header
#                                         source IP is this appliance's NSIP (set "CLI" to narrow)
#              OWN_TRAP_FILTER=1          also skip "SNMP TRAP_SENT ... netScalerConfigChange" lines with
#                                         NSIP as header source (0 = disable)
# Exit codes : 0 = nothing above WARNING, 1 = SUSPECTED, 2 = CONFIRMED, 3 = error
#
# Levels     : GREEN OK | YELLOW WARNING | ORANGE SUSPECTED | RED CONFIRMED

set -u
set -o pipefail
umask 077
export LC_ALL=C
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
unset CDPATH ENV BASH_ENV
shopt -s nullglob

if [ -z "${BASH_VERSINFO+x}" ]; then
    printf 'ERROR: run this script with bash\n' >&2; exit 3
fi
if [ "${BASH_VERSINFO[0]}" -lt 3 ] || { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    printf 'ERROR: bash >= 3.2 required (found %s)\n' "$BASH_VERSION" >&2; exit 3
fi
if [ "$EUID" -ne 0 ]; then
    printf 'ERROR: must run as root\n' >&2; exit 3
fi

CHANGE_DAYS="${CHANGE_DAYS:-30}"
case "$CHANGE_DAYS" in ''|*[!0-9]*) CHANGE_DAYS=30 ;; esac
NS_BACKUP_PL=/var/tmp/ns_system_backup.pl
NS_BACKUP_PL_SHA256="${NS_BACKUP_PL_SHA256:-474e8f95bef654c6c6c423bf1bb5ec7d18c568da6f7c057fa5fb169fc933e45a}"
CUSTOMSNMPD=/var/python/bin/customsnmpd
CUSTOMSNMPD_SHA256="${CUSTOMSNMPD_SHA256:-1dd0887ff21b18b0eb78a336e76d4dc3bb6f4fc645e9d864414a2958cb1637fe}"
OWN_CMD_MODULES="${OWN_CMD_MODULES:-CLI GUI UI}"
OWN_TRAP_FILTER="${OWN_TRAP_FILTER:-1}"
case "$OWN_TRAP_FILTER" in 0|1) ;; *) OWN_TRAP_FILTER=1 ;; esac
MAX_SCAN_KB=32768      # files above this size are not content-scanned
MAX_HITS=50            # max printed hits per log file per level
MAX_TTY_LEN=300        # terminal line truncation (report keeps full line)

realdir() { (cd -P -- "$1" 2>/dev/null && pwd -P); }

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
REPORT_REAL="$(realdir "$(dirname -- "$REPORT")")/${REPORT##*/}"
SELF_SRC="${BASH_SOURCE[0]:-$0}"
SELF_PATH="$(cd -- "$(dirname -- "$SELF_SRC")" 2>/dev/null && pwd -P)/${SELF_SRC##*/}"

# ---------------------------------------------------------------- scratch dir
TMPD=$(mktemp -d /var/tmp/pitscaler_scan.XXXXXX 2>/dev/null) || TMPD=""
case "$TMPD" in
    /var/tmp/pitscaler_scan.??????) ;;
    *) printf 'ERROR: cannot create scratch dir under /var/tmp\n' >&2; exit 3 ;;
esac
TMPD_REAL=$(realdir "$TMPD")
cleanup() {
    case "${TMPD:-}" in
        /var/tmp/pitscaler_scan.??????) [ -d "$TMPD" ] && rm -rf -- "$TMPD" ;;
    esac
}
trap cleanup EXIT
trap 'exit 3' INT TERM HUP
TMPN=0
TMPF=""
newtmp() { TMPN=$((TMPN+1)); TMPF="$TMPD/l$TMPN"; : > "$TMPF"; }   # sets global TMPF

# ---------------------------------------------------------------- colours
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'; C_RED=$'\033[1;31m'
    C_BLUE=$'\033[0;36m';  C_BOLD=$'\033[1m';      C_RESET=$'\033[0m'
    case "${TERM:-}" in
        *256color*|*truecolor*|xterm-kitty|alacritty) C_ORANGE=$'\033[38;5;208m' ;;
        *) C_ORANGE=$'\033[1;33m' ;;
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

# ---------------------------------------------------------------- string sets (no assoc arrays)
S_REPORTED=$'\n'; S_BASE=$'\n'
S_D2=$'\n'; S_D4=$'\n'; S_D5=$'\n'; S_D6=$'\n'; S_CONF=$'\n'; S_P=$'\n'
set_has() { local cur="${!1}"; case "$cur" in *$'\n'"$2"$'\n'*) return 0 ;; esac; return 1; }
set_add() { local cur="${!1}"; case "$cur" in *$'\n'"$2"$'\n'*) return 0 ;; esac; printf -v "$1" '%s%s\n' "$cur" "$2"; }
first_visit() { set_has "$1" "$2" && return 1; set_add "$1" "$2"; return 0; }
mark()    { set_add S_REPORTED "$1"; }
is_seen() { set_has S_REPORTED "$1"; }
lc()      { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ---------------------------------------------------------------- portability helpers
# No stat(1): metadata via ls, time checks via find.
if ls -lTd / >/dev/null 2>&1; then LS_M='-lTd'; LS_C='-lcTd'; else LS_M='-ld'; LS_C='-lcd'; fi
file_meta() {
    local out
    out=$(ls $LS_M "$1" 2>/dev/null)
    printf '%s' "${out:-metadata unavailable}"
}
file_ctime() {
    local out
    out=$(ls $LS_C "$1" 2>/dev/null)
    printf '%s' "${out:-ctime unavailable}"
}

if command -v sha256sum >/dev/null 2>&1; then HASH_TOOL=sha256sum
elif command -v sha256 >/dev/null 2>&1;  then HASH_TOOL=sha256
elif command -v openssl >/dev/null 2>&1; then HASH_TOOL=openssl
else HASH_TOOL=none; fi

RE_SHA256='^[0-9a-f]{64}$'
hash_file() {   # used only for the ns_system_backup.pl baseline
    local h=""
    case "$HASH_TOOL" in
        sha256sum) h=$(sha256sum "$1" 2>/dev/null); h="${h#\\}"; h="${h%% *}" ;;
        sha256)    h=$(sha256 -q "$1" 2>/dev/null) ;;
        openssl)   h=$(openssl dgst -sha256 -r "$1" 2>/dev/null); h="${h%% *}" ;;
    esac
    h=$(lc "$h")
    if [[ $h =~ $RE_SHA256 ]]; then printf '%s' "$h"; fi
}

# File type from magic bytes. Reads bytes only, never runs anything.
ftype() {
    local f="$1" hex tarm
    [ -f "$f" ] || { printf 'notfile'; return; }
    [ -s "$f" ] || { printf 'empty'; return; }
    hex=$(od -An -tx1 -N 32 -v "$f" 2>/dev/null); hex="${hex//[[:space:]]/}"
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
            tarm=$(od -An -tx1 -j 257 -N 5 -v "$f" 2>/dev/null); tarm="${tarm//[[:space:]]/}"
            if [ "$tarm" = "7573746172" ]; then printf 'tar'
            elif od -An -tx1 -N 8192 -v "$f" 2>/dev/null | grep -qw '00'; then printf 'data'
            else printf 'text'; fi ;;
    esac
}

has_php()         { grep -aqE '<\?php' -- "$1" 2>/dev/null; }
has_php_any()     { grep -aqE '<\?(php|=)' -- "$1" 2>/dev/null; }
has_webshell_fn() { grep -aqiE '(eval|assert|system|passthru|shell_exec|proc_open|popen|pcntl_exec|base64_decode|gzinflate|str_rot13|create_function)[[:space:]]*\(' -- "$1" 2>/dev/null; }
has_shell_cmds()  { grep -aqiE '(^|[;|&[:space:]])(curl|wget|fetch|nc|perl|python[0-9.]*|sh|bash|chmod|base64)[[:space:]]' -- "$1" 2>/dev/null; }

# XML sanity check for files that must be pure XML (e.g. clientversions.xml).
# Sets XV_LVL / XV_WHY. Reads only.
RE_XML_CODE='<script|javascript:|#!/|/bin/(ba)?sh|/dev/tcp|(eval|system|exec|passthru|shell_exec|popen|proc_open|base64_decode|gzinflate)[[:space:]]*\(|<!ENTITY[^>]*SYSTEM'
XV_LVL=""; XV_WHY=""
xml_verdict() {
    local f="$1" first last bad
    XV_LVL=OK; XV_WHY="plain XML (starts with '<', ends with '>', no code markers)"
    if has_php_any "$f"; then XV_LVL=C; XV_WHY="PHP code inside .xml"; return 0; fi
    if grep -aqiE "$RE_XML_CODE" -- "$f" 2>/dev/null; then
        XV_LVL=S; XV_WHY="script/exec markers inside .xml"; return 0
    fi
    bad=$(grep -aoE '<\?[A-Za-z][A-Za-z0-9_.-]*' -- "$f" 2>/dev/null | grep -avE '^<\?xml(-stylesheet)?$' | head -n 1)
    if [ -n "$bad" ]; then XV_LVL=S; XV_WHY="non-XML processing instruction '$bad'"; return 0; fi
    first=$(grep -av '^[[:space:]]*$' -- "$f" 2>/dev/null | head -n 1)
    last=$(grep -av '^[[:space:]]*$' -- "$f" 2>/dev/null | tail -n 1)
    first="${first#$'\xef\xbb\xbf'}"
    first="${first#"${first%%[![:space:]]*}"}"
    last="${last%"${last##*[![:space:]]}"}"
    case "$first" in
        '<'*) ;;
        *) XV_LVL=S; XV_WHY="does not start with '<' (not XML)"; return 0 ;;
    esac
    case "$last" in
        *'>') ;;
        *) XV_LVL=S; XV_WHY="does not end with '>' (data appended after XML?)"; return 0 ;;
    esac
    return 0
}

re_escape() {
    local s="$1" out="" c i
    for (( i=0; i<${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            '.'|'['|']'|'^'|'$'|'*'|'+'|'?'|'('|')'|'{'|'}'|'|'|"\\") out="$out\\$c" ;;
            *) out="$out$c" ;;
        esac
    done
    printf '%s' "$out"
}
ip_in_line() {   # $1 ip  $2 line ; true if ip appears with non-digit boundaries
    local re="(^|[^0-9])${1//./[.]}([^0-9]|\$)"
    [[ $2 =~ $re ]]
}

is_excluded() {
    local first=""
    case "$1" in
        "$REPORT"|"$REPORT_REAL"|"$SELF_PATH"|"$TMPD"/*|"$TMPD_REAL"/*) return 0 ;;
        */pitscaler_ioc_report_*.txt)
            IFS= read -r first < "$1" 2>/dev/null || first=""
            case "$first" in
                "NetScaler PitScaler IoC scan (read-only)"*) has_php_any "$1" || return 0 ;;
            esac ;;
    esac
    return 1
}

# One process snapshot, taken once. Read-only.
PS_SNAPSHOT=$(ps axww -o pid= -o command= 2>/dev/null || true)
PROCSTAT_SNAPSHOT=""
if command -v procstat >/dev/null 2>&1; then
    PROCSTAT_SNAPSHOT=$(procstat -b -a 2>/dev/null || true)
fi
running_matches() {   # full-path token match only
    local re
    re="(^|[[:space:]=:])$(re_escape "$1")([[:space:]]|\$)"
    printf '%s\n%s\n' "$PS_SNAPSHOT" "$PROCSTAT_SNAPSHOT" | grep -E -- "$re" 2>/dev/null
}
print_procs() {
    local l
    while IFS= read -r l; do [ -n "$l" ] && detail "process: $l"; done <<< "$1"
}

# ---------------------------------------------------------------- IoC data
# IPv4: STRONG = PitScaler rows without a do-not-block caveat.
IP_STRONG=(
  149.104.78.141 104.248.244.66 139.180.152.138 77.83.199.39 78.135.96.136 149.28.29.221 80.240.22.229
  89.36.231.206 143.198.7.94 157.254.167.12 138.199.200.90 138.28.234.38 82.167.14.7 154.217.251.226
  194.26.29.88 34.90.151.231 31.56.197.72 64.94.85.67 23.27.143.20 62.133.62.80 144.172.108.78
  153.75.82.220 216.203.21.233 185.243.41.247 78.128.113.10 158.94.209.12 5.188.206.226 172.247.44.85
  165.227.201.112 173.231.39.244 64.225.103.14 159.65.104.231 142.93.205.229 137.220.53.135
  149.28.58.71 198.13.159.233 45.249.89.172 45.143.167.96 206.232.71.215 130.94.106.141 82.24.212.15
  185.209.15.246 47.243.125.255 47.76.92.109 8.217.173.25 8.210.67.91 47.239.205.29 47.76.132.65
  8.218.219.56 47.76.102.1 47.76.63.52 8.210.119.74 64.177.93.71 44.252.255.141 194.242.130.193
  23.132.164.35 54.70.59.128 44.226.128.41 4.246.63.96 176.65.148.54 45.141.21.130 68.178.160.183
  89.44.80.7 130.94.42.226 134.175.71.50 177.4.12.11 78.47.24.217 66.135.19.18 167.99.111.203
  142.93.85.227 104.248.74.206 137.184.91.207 162.33.178.9 193.149.176.207 45.61.136.143 66.227.183.84
  216.245.184.164 45.76.34.141 170.64.176.26 209.250.236.77 138.68.21.29 70.172.58.168 162.243.36.88
  173.40.135.209 47.230.224.154 195.123.233.245 38.180.81.157 95.133.231.109 104.200.67.56
  199.233.217.13 130.94.20.222 213.209.159.55
)
# IPv4: NOISY = shared VPN exits, residential/ISP, parking (PitScaler: do not block on these alone).
IP_NOISY=(
  91.195.240.123 85.203.46.191 185.156.46.162 182.101.54.57 87.224.84.82 120.28.233.211 23.234.111.22
  85.221.203.85 46.150.68.55 159.26.103.184 197.52.9.138 180.242.113.168 85.117.117.248 73.43.85.7
  88.180.103.22 194.28.195.90 95.63.246.50 31.13.192.160 185.170.55.89 104.203.50.26 37.19.221.171
  58.187.56.89 171.106.10.118 178.66.43.241 94.190.77.195 93.177.60.233 68.46.140.222 178.218.40.232
  49.36.107.103 191.37.30.194 23.234.74.48 72.73.231.73 95.229.84.239 113.137.102.68 125.122.56.47
  92.118.204.229
)
# Cloudflare WARP egress (104.28.x) deliberately NOT scanned: shared by unrelated users.

DOMAINS_SUSP=( echvista.com entretiensol.com white-guard.pro garyvard.com hickoryusedauto.com
               gurerasfalt.com rockinroyaltykids.com currydownsrvpark.com pyrlnk.cc pylrk.cc )
DOMAINS_WARN=( instances.httpworkbench.com gsocket.io )

IP_GREP_ARGS=();  for x in "${IP_STRONG[@]}" "${IP_NOISY[@]}"; do IP_GREP_ARGS+=( -e "$x" ); done
DOM_GREP_ARGS=(); for x in "${DOMAINS_SUSP[@]}" "${DOMAINS_WARN[@]}"; do DOM_GREP_ARGS+=( -e "$x" ); done

# ---------------------------------------------------------------- banner
printf '%sNetScaler PitScaler IoC scan (read-only)%s  %s\n' "$C_BOLD" "$C_RESET" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'NetScaler PitScaler IoC scan (read-only)  %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
printf 'Legend: %s[OK]%s %s[WARNING]%s %s[SUSPECTED]%s %s[CONFIRMED]%s\n' \
    "$C_GREEN" "$C_RESET" "$C_YELLOW" "$C_RESET" "$C_ORANGE" "$C_RESET" "$C_RED" "$C_RESET"
info "Host: $(hostname 2>/dev/null)  Kernel: $(uname -sr 2>/dev/null)  Bash: $BASH_VERSION"
info "Report: $REPORT"
info "Tools: ls=$LS_M hash=$HASH_TOOL procstat=$([ -n "$PROCSTAT_SNAPSHOT" ] && echo yes || echo no)"
[ -z "$PS_SNAPSHOT" ] && warn "Process snapshot empty: 'is it running' checks disabled."

# =====================================================================
section "1. Published artefact paths"
# level|escalate|path|note   (escalate=esc: upgrade to CONFIRMED if executable content)
KNOWN_ARTEFACTS=(
  "C||/var/netscaler/logon/LogonPoint/custom/.ctxs.receiver|PHP webshell (GreyNoise, Unit 42, Sygnia)"
  "C||/var/netscaler/logon/LogonPoint/custom/.slap.receiver|SAML-kit PHP webshell (Poppelgaard checker, single-source)"
  "C||/var/netscaler/logon/LogonPoint/custom/receiver.deb|SAML-kit PHP webshell (Poppelgaard checker, single-source)"
  "C||/var/netscaler/gui/vpn/scripts/linux/1bd8a664.sig|.sig webshell (Sygnia, context-specific)"
  "S||/netscaler/ns_gui/vpn/c88771.json|JSON artefact in VPN web dir (Sygnia, context-specific)"
  "C||/var/netscaler/logon/LogonPoint/.local_journal|PHP webshell from update_c08937.pl (LevelBlue, not independently confirmed)"
  "C||/tmp/.uxdport|SLAPSHOT port artefact (GTIG)"
  "C||/tmp/.uxdlock|SLAPSHOT lock artefact (GTIG)"
  "C||/var/tmp/.nsmon|nsmon.pl implant directory (Arctic Wolf)"
  "S|esc|/var/tmp/.s|path listed by Arctic Wolf without context"
  "C||/var/1.py|main.py drop location (Arctic Wolf)"
  "C||/tmp/update_result_3567cs.tgz|staged /flash/nsconfig archive (LevelBlue)"
  "C||/netscaler.local|operator-created binary dir, not stock layout (TENEX)"
  "S||/var/core/.ns-cache|Platypus agent working dir (TENEX)"
  "C||/var/core/.ns-cache/client.crt|Platypus enrolment completed (TENEX)"
  "C||/var/core/.ns-cache/client.key|Platypus enrolment completed (TENEX)"
  "C||/.x|stager written by shell loader (TENEX)"
  "S|esc|/v|payload saved at / and run (unverified write-up via Beaumont, Poppelgaard)"
  "C||/nsconfig/.slap|SAML-kit Perl agent dir (Poppelgaard checker, single-source)"
  "C||/flash/nsconfig/.slap|SAML-kit Perl agent dir (Poppelgaard checker, single-source)"
  "C||/var/tmp/.ux|SAML-kit staging dir slapshot.py/whipd.py (Poppelgaard checker, single-source)"
  "C||/var/tmp/.slap-agent.log|SAML-kit log (Poppelgaard checker, single-source)"
  "C||/var/tmp/.slap-httpd-test.log|SAML-kit log (Poppelgaard checker, single-source)"
  "C||/var/tmp/.slap-diag.txt|SAML-kit artefact (Poppelgaard checker, single-source)"
  "C||/var/tmp/.s2loot|SAML-kit loot file (Poppelgaard checker, single-source)"
  "C||/tmp/.slap.cron|SAML-kit cron staging (Poppelgaard checker, single-source)"
  "C||/etc/httpd.conf.slap.bak|SAML-kit httpd.conf backup (Poppelgaard checker, single-source)"
  "S||/var/tmp/watchTowr|watchTowr detection-tool output: proves code execution, tester OR attacker"
  "S||/tmp/watchTowr|watchTowr detection-tool output: proves code execution, tester OR attacker"
  # SAML 2026 dropper (pylrk.cc / pyrlnk.cc campaign, 2 Oct 2026)
  # Stage 1 shell dropper: fetch -qo "$f" <URL>; chmod 755; nohup "$f" /dev/null 2>&1 &
  # Stage 2: Go ELF x86-64 binary fetched from f.pylrk.cc
  # Persistence: appends /usr/bin/nohup /nsconfig/.nsl /dev/null 2>&1 & to /nsconfig/rc.netscaler
  "C||/nsconfig/.nsl|Go implant binary (SAML 2026 dropper, pylrk.cc campaign); persists via /nsconfig/rc.netscaler"
  "C||/var/nslog/.nsl|Go implant fallback drop path (SAML 2026 dropper, pylrk.cc campaign; /var/nslog is volatile - no persistence)"
)

inspect_known() {
    local lvl="$1" esc="$2" p="$3" note="$4" t run sub n=0 L
    if [ -L "$p" ]; then
        emit_level "$lvl" "Symlink present: $p -> $(readlink -- "$p" 2>/dev/null) ($note)"
        mark "$p"; return 0
    fi
    [ -e "$p" ] || return 1
    mark "$p"
    if [ -d "$p" ]; then
        emit_level "$lvl" "Directory present: $p ($note)"
        detail "$(file_meta "$p")"
        newtmp; L="$TMPF"
        find "$p" -xdev -mindepth 1 -maxdepth 3 -print0 > "$L" 2>/dev/null
        while IFS= read -r -d '' sub; do
            n=$((n+1))
            if [ "$n" -gt 25 ]; then detail "... further entries not listed"; break; fi
            mark "$sub"
            detail "entry [$(ftype "$sub")]: $(file_meta "$sub")"
            run=$(running_matches "$sub")
            if [ -n "$run" ]; then confirm "Running process references $sub"; print_procs "$run"; fi
        done < "$L"
        return 0
    fi
    t=$(ftype "$p")
    if [ "$esc" = esc ]; then
        case "$t" in
            elf|macho|script) lvl=C ;;
            text) has_shell_cmds "$p" && lvl=C ;;
        esac
    fi
    run=$(running_matches "$p")
    if [ -n "$run" ]; then
        confirm "File present AND referenced by a running process: $p [$t] ($note)"
        print_procs "$run"
    else
        emit_level "$lvl" "File present: $p [$t] ($note)"
    fi
    detail "$(file_meta "$p")"
    return 0
}

s1=0
for entry in "${KNOWN_ARTEFACTS[@]}"; do
    IFS='|' read -r lvl esc p note <<< "$entry"
    if inspect_known "$lvl" "$esc" "$p" "$note"; then s1=$((s1+1)); fi
done

p=/var/netscaler/logon/insight-new.js
if [ -e "$p" ]; then
    s1=$((s1+1)); mark "$p"
    if grep -aqE '^(add|set|bind|enable) (ns|system|vpn|lb|authentication|ssl|aaa) ' -- "$p" 2>/dev/null; then
        confirm "$p contains NetScaler config lines (ns.conf copy in web dir; Sygnia/LevelBlue)"
    else
        suspect "$p present, content not ns.conf-like [$(ftype "$p")] (Sygnia/LevelBlue artefact name)"
    fi
    detail "$(file_meta "$p")"
fi
p=/var/netscaler/logon/LogonPoint/xua.html
if [ -e "$p" ]; then
    s1=$((s1+1)); mark "$p"; t=$(ftype "$p")
    case "$t" in
        tar|gzip|bzip2|xz) confirm "$p is a $t archive disguised as .html (config staging, LevelBlue)" ;;
        *)                 suspect "$p present [$t] (LevelBlue config-staging name)" ;;
    esac
    detail "$(file_meta "$p")"
fi
# ns_ctx.html: SAML 2026 dropper (pylrk.cc campaign) overwrites this file with raw 'uname -srm' output
# to let the attacker confirm RCE and detect the build. A legitimate HTML file never starts a line with
# a bare kernel version string. Flag only on content match to avoid false positives on stock builds.
p=/var/netscaler/logon/LogonPoint/ns_ctx.html
if [ -f "$p" ] && ! is_seen "$p"; then
    mark "$p"
    if grep -aqE '^FreeBSD[[:space:]]+[0-9]' -- "$p" 2>/dev/null; then
        s1=$((s1+1))
        confirm "$p contains bare 'uname -srm' output (FreeBSD kernel string) - written by SAML 2026 dropper (pylrk.cc campaign)"
        detail "$(file_meta "$p")"
        detail "first line: $(head -n 1 -- "$p" 2>/dev/null | tr -dc '[:print:][:space:]')"
    fi
fi
[ "$s1" -eq 0 ] && ok "None of the published artefact paths exist."

# =====================================================================
section "2. VPN client download dirs (/vpn/scripts/linux) - content classification"
VPN_DIRS=( /netscaler/ns_gui/vpn/scripts/linux /var/netscaler/gui/vpn/scripts/linux )
UNIT42_DEB_NAMES='nsg64.deb nsgser18.deb nsgsupport.deb nsgpackage64.deb nsgbuild.deb'

classify_vpn_file() {
    local f="$1" name ext t run lvl why namenote=""
    name="${f##*/}"; ext="${name##*.}"; [ "$ext" = "$name" ] && ext=""; ext=$(lc "$ext")
    is_excluded "$f" && return 0
    mark "$f"
    if [ -L "$f" ]; then
        suspect "Symlink in VPN client dir: $f -> $(readlink -- "$f" 2>/dev/null)"; return 0
    fi
    t=$(ftype "$f")
    run=$(running_matches "$f")

    case " $UNIT42_DEB_NAMES " in *" $name "*) namenote="name on Unit 42 .deb-webshell list" ;; esac
    case "$name" in
        nginstaller*) namenote="name matches GTIG nginstaller* webshell pattern" ;;
        nsgclient.sig|e6ee7c85.sig|80974ca9.sig|LoginIcon.sig) namenote="published webshell file name" ;;
    esac

    if [ -n "$run" ]; then lvl=C; why="referenced by a running process"
    else
        case "$t" in
            deb|rpm)
                if has_php "$f"; then lvl=C; why="valid $t container but contains '<?php' (PHP polyglot)"
                else lvl=OK; why="valid $t package"; fi ;;
            elf|macho|pe)
                if [ "$ext" = deb ] || [ "$ext" = rpm ]; then lvl=C; why="$t executable masquerading as .$ext"
                else lvl=S; why="$t executable in VPN client dir (not running)"; fi ;;
            script)
                lvl=C; why="executable script (#!) in VPN client dir" ;;
            text)
                if has_php_any "$f"; then lvl=C; why="PHP code in text file (WHIPSHOT/.sig/.deb webshell pattern)"
                elif [ "$ext" = xml ]; then xml_verdict "$f"; lvl="$XV_LVL"; why="$XV_WHY"
                elif [ "$ext" = deb ] || [ "$ext" = rpm ]; then lvl=C; why="plain text masquerading as .$ext"
                else lvl=S; why="text file without PHP markers"; fi ;;
            gzip|bzip2|xz|zip|tar|ar)
                if has_php "$f"; then lvl=C; why="$t archive containing '<?php' (polyglot)"
                else lvl=W; why="$t archive (not deb/rpm) - compare with clean appliance, same build"; fi ;;
            data)
                if has_php "$f"; then lvl=C; why="binary data containing '<?php'"
                elif [ "$ext" = sig ]; then lvl=W; why="binary .sig (may be a real signature; known .sig webshells are PHP text)"
                elif [ "$ext" = xml ]; then lvl=S; why="binary content in .xml file"
                else lvl=S; why="unrecognised binary content"; fi ;;
            empty) lvl=W; why="empty file" ;;
            *)     lvl=S; why="unclassified ($t)" ;;
        esac
    fi
    if [ "$ext" = php ] && [ "$lvl" != C ]; then lvl=C; why="$why; .php in /vpn/scripts/linux (GTIG staging pattern)"; fi
    if [ -n "$namenote" ] && [ "$lvl" = OK ]; then lvl=W; why="$why, but $namenote"; fi
    if [ -n "$namenote" ] && [ "$lvl" != W ]; then why="$why; $namenote"; fi

    emit_level "$lvl" "$f [$t]: $why"
    detail "$(file_meta "$f")"
    [ -n "$run" ] && print_procs "$run"
    return 0
}

for d in "${VPN_DIRS[@]}"; do
    if [ ! -d "$d" ]; then info "$d not present"; continue; fi
    rd=$(realdir "$d"); [ -n "$rd" ] || continue
    if ! first_visit S_D2 "$rd"; then info "$d resolves to $rd (already scanned)"; continue; fi
    warn "Directory present: $d (stock VPN client location; also WHIPSHOT location per GTIG) - contents classified below"
    cnt=0
    newtmp; L="$TMPF"
    find "$rd" -xdev -mindepth 1 -maxdepth 2 \( -type f -o -type l \) -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        cnt=$((cnt+1)); classify_vpn_file "$f"
    done < "$L"
    [ "$cnt" -eq 0 ] && info "$d is empty"
done

# =====================================================================
section "3. Stock files: SHA-256 baseline (customsnmpd, ns_system_backup.pl) + change time"
# Sets BL_RES = ok | bad | none
BL_RES=""
check_baseline() {   # $1 path  $2 expected sha256  $3 report change time (1/0)
    local p="$1" exp="$2" chk="$3" pr h chg
    BL_RES=none
    pr="$(realdir "$(dirname -- "$p")")/${p##*/}"
    set_add S_BASE "$p"; set_add S_BASE "$pr"
    if [ -L "$p" ]; then suspect "$p is a symlink -> $(readlink -- "$p" 2>/dev/null)"; mark "$p"; return 0; fi
    if [ ! -e "$p" ]; then info "$p not present"; return 0; fi
    if [ ! -f "$p" ]; then suspect "$p exists but is not a regular file"; mark "$p"; return 0; fi
    if [ "$HASH_TOOL" = none ]; then
        warn "$p: no SHA-256 tool available, baseline not verified"
    else
        h=$(hash_file "$p")
        if [ -z "$h" ]; then
            warn "$p: SHA-256 could not be computed"
        elif [ "$h" = "$exp" ]; then
            BL_RES=ok; ok "$p matches baseline SHA-256"
            mark "$p"; mark "$pr"
        else
            BL_RES=bad
            suspect "$p SHA-256 deviates from baseline (expected $exp) - normal after a firmware upgrade (update baseline), otherwise investigate"
            detail "found sha256=$h"
        fi
    fi
    if [ "$chk" = 1 ]; then
        chg=$(find "$p" -prune \( -mtime -"$CHANGE_DAYS" -o -ctime -"$CHANGE_DAYS" \) -print 2>/dev/null)
        if [ -n "$chg" ]; then
            if [ "$BL_RES" = none ]; then
                suspect "$p changed in the last $CHANGE_DAYS days (mtime or ctime) and hash not verified - compare with last firmware upgrade"
            else
                info "$p changed in the last $CHANGE_DAYS days (mtime or ctime) - see hash verdict above"
            fi
        else
            info "$p not changed in the last $CHANGE_DAYS days (mtime and ctime)"
        fi
        detail "ctime: $(file_ctime "$p")"
    fi
    detail "mtime: $(file_meta "$p")"
    return 0
}
check_baseline "$CUSTOMSNMPD" "$CUSTOMSNMPD_SHA256" 1
check_baseline "$NS_BACKUP_PL" "$NS_BACKUP_PL_SHA256" 0

# =====================================================================
section "4. File-name patterns (content-verified)"
PATTERN_DIRS=( /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/tmp /tmp )
NAME_IOCS=(
  "nginstaller*|S|GTIG installer-webshell name pattern"
  "nsgclient.sig|S|GTIG .sig webshell name"
  "e6ee7c85.sig|S|GTIG example .sig webshell"
  "80974ca9.sig|S|artefact name from published IR"
  "LoginIcon.sig|S|artefact name from published IR"
  "receiver.min.*.css|S|webshell alias name (GreyNoise/CERT-EU)"
  "receiver.v2.min*.css|S|SAML-kit alias name (Poppelgaard)"
  ".slap.receiver|C|SAML-kit webshell (Poppelgaard)"
  ".ctxs.receiver|C|webshell (GreyNoise/Unit 42)"
  ".local_journal|C|webshell (LevelBlue)"
  "receiver.deb|S|SAML-kit webshell name (Poppelgaard)"
  "nsmon.pl|C|nsmon.pl implant (Arctic Wolf)"
  "update_c08937.pl|C|payload (LevelBlue/Arctic Wolf)"
  "slapshot.py|C|SAML-kit tunneler (Poppelgaard)"
  "whipd.py|C|SAML-kit component (Poppelgaard)"
  "ns_*.pl|S|Platypus agent renamed ns_*.pl (TENEX)"
  "nx_verify.html|S|exploit marker (Defused): proves code execution, tester or attacker"
  "id009*|S|exploit marker (TENEX opportunistic wave)"
  "wt88771*.txt|S|marker file (single Reddit report)"
  "wtw*|S|PoC/exploit output marker (Poppelgaard checker)"
  "watchTowr*|S|watchTowr tool output marker"
  "boom*|S|PoC/exploit output marker (Poppelgaard checker)"
)
FIND_NAMES=( \( ); first=1
for e in "${NAME_IOCS[@]}"; do
    pat="${e%%|*}"
    [ "$first" -eq 1 ] || FIND_NAMES+=( -o )
    FIND_NAMES+=( -name "$pat" ); first=0
done
FIND_NAMES+=( \) )

s4=0
for d in "${PATTERN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    rd=$(realdir "$d"); [ -n "$rd" ] || continue
    first_visit S_D4 "$rd" || continue
    newtmp; L="$TMPF"
    find "$rd" -xdev -maxdepth 5 "${FIND_NAMES[@]}" -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        is_excluded "$f" && continue
        is_seen "$f" && continue
        set_has S_BASE "$f" && continue          # handled in section 3
        mark "$f"; name="${f##*/}"; lvl=I; note=""
        for e in "${NAME_IOCS[@]}"; do
            IFS='|' read -r pat l n <<< "$e"
            if [[ $name == $pat ]]; then lvl="$l"; note="$n"; break; fi
        done
        t=$(ftype "$f")
        if [ -f "$f" ] && has_php_any "$f"; then lvl=C; note="$note; contains PHP code"; fi
        run=$(running_matches "$f")
        if [ -n "$run" ]; then lvl=C; note="$note; referenced by running process"; fi
        emit_level "$lvl" "$f [$t]: $note"
        detail "$(file_meta "$f")"
        [ -n "$run" ] && print_procs "$run"
        s4=$((s4+1))
    done < "$L"
done
ncore=0
if [ -d /var/core ]; then
    newtmp; L="$TMPF"
    find /var/core -xdev -maxdepth 3 -type f -name 'nsaaad-*.gz' -mtime -30 -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        ncore=$((ncore+1))
        [ "$ncore" -le 10 ] && warn "nsaaad core dump (last 30 days): $f - preserve, correlate with SAML requests, involve Citrix Support"
    done < "$L"
    [ "$ncore" -gt 10 ] && info "$((ncore-10)) more nsaaad core dumps not listed"
fi
[ "$s4" -eq 0 ] && ok "No published file-name patterns found."

# =====================================================================
section "5. PHP code in non-.php files (web and temp dirs)"
HIGH_RISK_DIRS=( /var/netscaler/logon/LogonPoint/custom /var/netscaler/logon/themes /var/tmp /tmp )
WEB_DIRS=( /var/netscaler/logon /netscaler/ns_gui/vpn /var/netscaler/gui/vpn )
s5=0
scan_php_dir() {
    local d="$1" risk="$2" rd f lvl L
    [ -d "$d" ] || return 0
    rd=$(realdir "$d"); [ -n "$rd" ] || return 0
    first_visit S_D5 "$rd" || return 0
    newtmp; L="$TMPF"
    find "$rd" -xdev -type f ! -name '*.php' ! -name '*.phtml' ! -name '*.inc' -size -"${MAX_SCAN_KB}"k -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        is_excluded "$f" && continue
        is_seen "$f" && continue
        has_php "$f" || continue
        mark "$f"
        if has_webshell_fn "$f"; then
            if [ "$risk" = high ]; then lvl=C; else lvl=S; fi
            emit_level "$lvl" "PHP with exec/eval/decode functions in non-.php file: $f"
        else
            if [ "$risk" = high ]; then lvl=S; else lvl=W; fi
            emit_level "$lvl" "PHP code in non-.php file: $f (compare with clean appliance, same build)"
        fi
        detail "$(file_meta "$f")"; s5=$((s5+1))
    done < "$L"
    return 0
}
for d in "${HIGH_RISK_DIRS[@]}"; do scan_php_dir "$d" high; done
for d in "${WEB_DIRS[@]}";       do scan_php_dir "$d" web;  done
[ "$s5" -eq 0 ] && ok "No PHP code found in non-.php files."

# =====================================================================
section "6. IoC strings inside files"
STRING_IOCS=(
  "UXD_IDLE_EXIT|C|SLAPSHOT tunneler variable (GTIG)"
  "HTTP_X_UX|C|WHIPSHOT chunked base64 header (GTIG)"
  "e826d7ddf3c85920|C|.ctxs.receiver CsrfToken (IFIN/GreyNoise)"
  "Rhfajaf1H992|C|nsg64.deb RC4 passphrase (Unit 42)"
  "7489a0f93c67fa5cdaeb4b921d90594d|C|nsg64.deb RC4 key (Unit 42)"
  "application/x-protobuf-platypus-v2|C|Platypus agent (TENEX)"
  "platypus-agent/public-ip-probe|C|Platypus agent (TENEX)"
  "S8GEj/Ibzw/Zy9Z5u4saQyn0h59enf9Mk3J2m70tTMs=|C|Platypus signing key (TENEX)"
  "platypus://server/default|C|Platypus cert SAN (TENEX)"
  "_platypus-mesh._tcp|C|Platypus mDNS (TENEX)"
  "0.1.0-SNAPSHOT-4b91c7db|C|Platypus build (TENEX)"
  "0.1.0-SNAPSHOT-697ffe7c|C|Platypus build (TENEX)"
  "update_c08937.pl|S|payload name (LevelBlue/Sygnia)"
  "/xd7h/|S|payload path (Arctic Wolf)"
  "gsocket.io/y|S|gsocket one-liner (TENEX)"
  "NX-CVE-OK|S|exploit-check marker (Lupovis via Beazley)"
  "HTTP_NSC_LDAP|S|nsginstaller.deb command header (GTIG) - verify vs stock code"
  "HTTP_NSC_CLIENTTYPE|S|nsgclient.sig command header (GTIG) - verify vs stock code"
)
STRING_DIRS=( /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/tmp /tmp
              /var/core/.ns-cache /netscaler.local /var/python/bin /nsconfig /flash/nsconfig )
STR_GREP_ARGS=(); for e in "${STRING_IOCS[@]}"; do STR_GREP_ARGS+=( -e "${e%%|*}" ); done
s6=0
for d in "${STRING_DIRS[@]}"; do
    [ -d "$d" ] || continue
    rd=$(realdir "$d"); [ -n "$rd" ] || continue
    first_visit S_D6 "$rd" || continue
    newtmp; L="$TMPF"
    find "$rd" -xdev -type f -size -"${MAX_SCAN_KB}"k -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        is_excluded "$f" && continue
        is_seen "$f" && continue
        grep -aqF "${STR_GREP_ARGS[@]}" -- "$f" 2>/dev/null || continue
        best=""; notes=""
        for e in "${STRING_IOCS[@]}"; do
            IFS='|' read -r s l n <<< "$e"
            if grep -aqF -e "$s" -- "$f" 2>/dev/null; then
                notes="${notes:+$notes; }'$s' = $n"
                if [ "$l" = C ]; then best=C; elif [ -z "$best" ]; then best="$l"; fi
            fi
        done
        emit_level "${best:-S}" "IoC string(s) in $f: $notes"
        detail "$(file_meta "$f")"; mark "$f"; s6=$((s6+1))
    done < "$L"
done
[ "$s6" -eq 0 ] && ok "No IoC strings found in scanned files."

# =====================================================================
section "7. httpd.conf"
HTTPD_CONF=/etc/httpd.conf
RE_HANDLER='^(AddHandler|AddType)[[:space:]]+application/x-httpd-php[^[:space:]]*[[:space:]]+(.+)$'
RE_SETH='^SetHandler[[:space:]]+application/x-httpd-php'
RE_ALIAS='^(Alias|AliasMatch)[[:space:]]'
RE_ALIAS_BAD='receiver[\]?[.](v2[\]?[.])?min|LogonUISimple[\]?[.]html[\]?[.]style|/vpn/media/|[.]sig([[:space:]$]|$)|[.]receiver|[.]local_journal'
RE_PHPFLAG='^php_flag[[:space:]]+engine[[:space:]]+on'
if [ ! -f "$HTTPD_CONF" ]; then
    warn "$HTTPD_CONF not found - section skipped"
else
    s8=0; n=0
    while IFS= read -r raw || [ -n "$raw" ]; do
        n=$((n+1))
        l="${raw#"${raw%%[![:space:]]*}"}"
        case "$l" in ''|'#'*) continue ;; esac
        if [[ $l =~ $RE_HANDLER ]]; then
            exts=()
            read -r -a exts <<< "${BASH_REMATCH[2]}"
            for e in ${exts[@]+"${exts[@]}"}; do
                e=$(lc "$e"); e="${e#.}"
                case "$e" in
                    php|php3|php4|php5|php7|phtml|phps) ;;
                    html|htm) warn "line $n maps .$e to PHP - compare with clean appliance: $l"; s8=$((s8+1)) ;;
                    *) confirm "line $n maps .$e to PHP (GTIG: non-PHP extension mapped to PHP = compromise): $l"; s8=$((s8+1)) ;;
                esac
            done
        fi
        if [[ $l =~ $RE_SETH ]]; then
            suspect "line $n SetHandler to PHP (GreyNoise/CERT-EU webshell pattern) - check enclosing <Files> block: $l"; s8=$((s8+1))
        fi
        if [[ $l =~ $RE_ALIAS ]] && [[ $l =~ $RE_ALIAS_BAD ]]; then
            confirm "line $n webshell alias (GreyNoise/GTIG/LevelBlue/Poppelgaard): $l"; s8=$((s8+1))
        fi
        if [[ $l =~ $RE_PHPFLAG ]]; then
            warn "line $n php_flag engine on (webshells flip this from off) - compare with clean appliance: $l"; s8=$((s8+1))
        fi
    done < "$HTTPD_CONF"
    detail "$(file_meta "$HTTPD_CONF")"
    [ "$s8" -eq 0 ] && ok "No PHP handler/alias anomalies in $HTTPD_CONF."
fi

# =====================================================================
section "8. ns.conf: rogue accounts, SAML exposure, NSIP"
s9=0
NSIPS=""
RE_NSIP='(^|[[:space:]])-IPAddress[[:space:]]+([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})([[:space:]]|$)'
for c in /nsconfig/ns.conf /flash/nsconfig/ns.conf; do
    [ -f "$c" ] || continue
    rc="$(realdir "$(dirname -- "$c")")/ns.conf"
    first_visit S_CONF "$rc" || continue
    hits=$(grep -nE '(^|[[:space:]"])sec_monitor([[:space:]"]|$)' -- "$c" 2>/dev/null)
    if [ -n "$hits" ]; then
        while IFS= read -r l; do
            confirm "$c: rogue superuser sec_monitor (LevelBlue): $l"; s9=$((s9+1))
        done <<< "$hits"
    fi
    nsaml=$(grep -ciE '^add authentication (samlAction|samlIdPProfile)' -- "$c" 2>/dev/null)
    if [ "${nsaml:-0}" -gt 0 ]; then
        warn "$c: $nsaml SAML action/IdP profile line(s) - in scope of Citrix SAML guidance (2 Oct 2026); no fixed build at PitScaler snapshot"
        s9=$((s9+1))
    fi
    hits=$(grep -nE '^add system user ' -- "$c" 2>/dev/null | sed -E 's/(-password|-encrypted)[[:space:]]+[^[:space:]]+/\1 <redacted>/g')
    if [ -n "$hits" ]; then
        while IFS= read -r l; do info "$c system user (review manually): $l"; done <<< "$hits"
    fi
    # NSIP: "set ns config -IPAddress <ip_addr> -netmask <netmask>" (NetScaler CLI reference, ns-config)
    hits=$(grep -E '^set ns config[[:space:]]' -- "$c" 2>/dev/null)
    if [ -n "$hits" ]; then
        while IFS= read -r l; do
            if [[ $l =~ $RE_NSIP ]]; then
                ip="${BASH_REMATCH[2]}"
                case " $NSIPS " in *" $ip "*) ;; *) NSIPS="${NSIPS:+$NSIPS }$ip" ;; esac
            fi
        done <<< "$hits"
    fi
done
[ "$s9" -eq 0 ] && ok "No sec_monitor account and no SAML action/IdP profile in ns.conf."

# Own-config-change filter (used in section 10). A log line is skipped only if:
#   (a) the header source IP right after <facility.level> is this appliance's NSIP, AND
#   (b) it is one of the two config-audit events:
#       - "<MOD> CMD_EXECUTED ... User <u> - ..."  (MOD in OWN_CMD_MODULES)
#         body per NetScaler syslog reference (UI/CMD_EXECUTED):
#         User %s - ADM_User %s - Remote_ip %s - Command "%s" - Status "%s"
#       - "SNMP TRAP_SENT ... : netScalerConfigChange (nsUserName = "<u>", configurationCmd = "...", ...)"
#         trap objects per NS-ROOT-MIB (CTX122436): nsUserName, configurationCmd,
#         authorizationStatus, commandExecutionStatus, sysIpAddress
#   (c) the user field contains no shell metacharacters.
# Header layout taken from appliance ns.log (not documented):
#   "<n>:Mon dd hh:mm:ss <local0.info> <NSIP>  <date> GMT <host> 0-PPE-0 : <partition> <MOD> <EVENT> ..."
OWN_MODS=""
for m in $OWN_CMD_MODULES; do
    case "$m" in *[!A-Z]*|'') continue ;; esac
    OWN_MODS="${OWN_MODS:+$OWN_MODS|}$m"
done
OWN_MODS_DISP="${OWN_MODS//|/ }"
OWN_DESC="${OWN_MODS_DISP:+$OWN_MODS_DISP CMD_EXECUTED}"
[ "$OWN_TRAP_FILTER" = 1 ] && OWN_DESC="${OWN_DESC:+$OWN_DESC, }SNMP netScalerConfigChange trap"
RE_OWN_MOD="[[:space:]](${OWN_MODS:-NONE})[[:space:]]+CMD_EXECUTED[[:space:]]"
RE_OWN_TRAP='[[:space:]]SNMP[[:space:]]+TRAP_SENT[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+:[[:space:]]+netScalerConfigChange[[:space:]]*[(]nsUserName[[:space:]]*=[[:space:]]*"([^"]*)",[[:space:]]*configurationCmd[[:space:]]*='
RE_OWN_SRC='<[A-Za-z0-9]+[.][A-Za-z]+>[[:space:]]+([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})[[:space:]]'
RE_OWN_USER='[[:space:]]User[[:space:]]+([^[:space:]]+)[[:space:]]+-[[:space:]]'
RE_OWN_BADU='[;|`&<>(){}$"]'
OWN_WHY=""
is_audit_line() { [[ $1 == *CMD_EXECUTED* || $1 == *netScalerConfigChange* ]]; }
own_cmd() {   # true = own config change logged by this appliance (skip)
    local line="$1" src user
    OWN_WHY=""
    if [ -z "$NSIPS" ]; then OWN_WHY="NSIP unknown"; return 1; fi
    if [[ $line == *CMD_EXECUTED* ]]; then
        if ! [[ $line =~ $RE_OWN_MOD ]]; then OWN_WHY="CMD_EXECUTED module not in OWN_CMD_MODULES ($OWN_CMD_MODULES)"; return 1; fi
        if ! [[ $line =~ $RE_OWN_USER ]]; then OWN_WHY="no 'User <name> -' field"; return 1; fi
        user="${BASH_REMATCH[1]}"
    elif [[ $line == *netScalerConfigChange* ]]; then
        if [ "$OWN_TRAP_FILTER" != 1 ]; then OWN_WHY="OWN_TRAP_FILTER=0"; return 1; fi
        if ! [[ $line =~ $RE_OWN_TRAP ]]; then OWN_WHY="netScalerConfigChange line not in expected 'SNMP TRAP_SENT ... (nsUserName = \"..\", configurationCmd =' format"; return 1; fi
        user="${BASH_REMATCH[1]}"
    else
        OWN_WHY="not a config-audit event"; return 1
    fi
    if [ -z "$user" ]; then OWN_WHY="empty user field"; return 1; fi
    if [[ $user =~ $RE_OWN_BADU ]]; then OWN_WHY="shell metacharacters in user field"; return 1; fi
    if ! [[ $line =~ $RE_OWN_SRC ]]; then OWN_WHY="no '<facility.level> <IPv4>' header"; return 1; fi
    src="${BASH_REMATCH[1]}"
    case " $NSIPS " in *" $src "*) ;; *) OWN_WHY="header source $src is not NSIP ($NSIPS)"; return 1 ;; esac
    return 0
}
if [ -z "$NSIPS" ]; then
    warn "NSIP not found in ns.conf (set ns config -IPAddress): own-config-change log filter disabled"
elif [ -z "$OWN_DESC" ]; then
    warn "OWN_CMD_MODULES invalid and OWN_TRAP_FILTER=0: own-config-change log filter disabled"
else
    info "NSIP(s) from ns.conf: $NSIPS - log lines with this header source IP and event [$OWN_DESC] are skipped in section 10"
fi

# =====================================================================
section "9. Privilege & persistence"
perms=$(ls -lLd /bin/sh 2>/dev/null); perms="${perms%% *}"
if [ -z "$perms" ]; then
    warn "/bin/sh: cannot read permissions"
elif [[ ${perms:3:1} == [sS] || ${perms:6:1} == [sS] ]]; then
    confirm "/bin/sh has setuid/setgid ($perms), expected -r-xr-xr-x (GTIG/GreyNoise/Beazley)"
else
    ok "/bin/sh permissions $perms"
fi
s10=0
for d in /tmp /var/tmp /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/core; do
    [ -d "$d" ] || continue
    newtmp; L="$TMPF"
    find "$d" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 > "$L" 2>/dev/null
    while IFS= read -r -d '' f; do
        confirm "setuid/setgid file in writable/web dir: $f [$(ftype "$f")]"; detail "$(file_meta "$f")"; s10=$((s10+1))
    done < "$L"
done
[ "$s10" -eq 0 ] && ok "No setuid/setgid files in temp/web dirs."

PERSIST_FILES=( /etc/crontab /nsconfig/crontab /flash/nsconfig/crontab /var/cron/tabs/root
                /nsconfig/rc.netscaler /flash/nsconfig/rc.netscaler
                /nsconfig/nsbefore.sh /nsconfig/nsafter.sh /flash/nsconfig/nsbefore.sh /flash/nsconfig/nsafter.sh )
P_CONF='nsmon[.]pl|[.]slap/|boot[.]sh|slapshot|whipd|/var/tmp/[.][A-Za-z]|/netscaler[.]local|[.]ns-cache|[.]nsl'
P_EXEC='[|;&][[:space:]]*(sh|bash|perl|python[0-9.]*)([[:space:]]|$)|base64|/dev/tcp|nc[[:space:]]+-e|(^|[[:space:]])/v([[:space:]]|$)|(^|[[:space:]])/[.]x([[:space:]]|$)|chmod[[:space:]]+[ugoa]*[+][rwxt]*s|chmod[[:space:]]+[2467][0-7][0-7][0-7]'
P_DL='(^|[^A-Za-z0-9_./-])(curl|wget|fetch)([[:space:]]|$)'
RE_URL_HOST='[A-Za-z][A-Za-z0-9+.-]*://([^/@[:space:]]+@)?([[][0-9A-Fa-f:.]+[]]|[A-Za-z0-9._-]+)'
remote_hosts() {   # prints URL hosts in $1 that are not loopback
    local rest="$1" h i=0
    while [ "$i" -lt 20 ] && [[ $rest =~ $RE_URL_HOST ]]; do
        i=$((i+1))
        h=$(lc "${BASH_REMATCH[2]}")
        rest="${rest#*"${BASH_REMATCH[0]}"}"
        case "$h" in
            localhost|localhost.|127.*|'[::1]') ;;
            *) printf '%s ' "$h" ;;
        esac
    done
}
cron_verdict() {   # sets CV_LVL (C/S/W/empty) and CV_WHY
    local l="$1" rh
    CV_LVL=""; CV_WHY=""
    if [[ $l =~ $P_CONF ]]; then CV_LVL=C; CV_WHY="known implant persistence"
    elif [[ $l =~ $P_EXEC ]]; then CV_LVL=S; CV_WHY="pipe-to-interpreter / encoding / reverse-shell / suid pattern"
    elif [[ $l =~ $P_DL ]]; then
        rh=$(remote_hosts "$l")
        if [ -n "$rh" ]; then CV_LVL=S; CV_WHY="download tool contacting non-loopback host(s): ${rh% }"
        elif ! [[ $l =~ $RE_URL_HOST ]]; then CV_LVL=W; CV_WHY="download tool without parsable URL"
        fi
    fi
    return 0
}
s10b=0
for pf in "${PERSIST_FILES[@]}"; do
    [ -f "$pf" ] || continue
    rp="$(realdir "$(dirname -- "$pf")")/${pf##*/}"
    first_visit S_P "$rp" || continue
    n=0
    while IFS= read -r raw || [ -n "$raw" ]; do
        n=$((n+1)); l="${raw#"${raw%%[![:space:]]*}"}"
        case "$l" in ''|'#'*) continue ;; esac
        cron_verdict "$l"
        [ -n "$CV_LVL" ] || continue
        emit_level "$CV_LVL" "$pf:$n $CV_WHY: $l"; s10b=$((s10b+1))
    done < "$pf"
done
[ "$s10b" -eq 0 ] && ok "No suspicious entries in crontab / rc.netscaler / nsbefore / nsafter."

# =====================================================================
section "10. Logs"
log_stream() {
    case "$1" in
        *.gz)  gzip  -dc -- "$1" 2>/dev/null ;;
        *.bz2) bzip2 -dc -- "$1" 2>/dev/null ;;
        *)     cat   -- "$1" 2>/dev/null ;;
    esac
}
SYS_LOGS=(); NSYS=0
for f in /var/log/ns.log /var/log/ns.log.* /var/log/messages /var/log/messages.*; do
    [ -f "$f" ] && { SYS_LOGS+=( "$f" ); NSYS=$((NSYS+1)); }
done
ACC_LOGS=(); NACC=0
for f in /var/log/httpaccess.log /var/log/httpaccess.log.* /var/log/httpaccess-vpn.log /var/log/httpaccess-vpn.log.* \
         /var/log/httperror.log /var/log/httperror.log.* /var/log/httperror-vpn.log /var/log/httperror-vpn.log.*; do
    [ -f "$f" ] && { ACC_LOGS+=( "$f" ); NACC=$((NACC+1)); }
done
[ "$NSYS" -eq 0 ] && warn "No ns.log/messages found under /var/log"
[ "$NACC" -eq 0 ] && warn "No httpaccess/httperror logs found under /var/log"
info "Logs rotate: no hit here does not mean no attempt. Check your SIEM too."

SH_C=0; SH_S=0; SH_W=0; SH_I=0
reset_caps() { SH_C=0; SH_S=0; SH_W=0; SH_I=0; }
show() {
    local n
    case "$1" in
        C) SH_C=$((SH_C+1)); n=$SH_C ;;
        S) SH_S=$((SH_S+1)); n=$SH_S ;;
        W) SH_W=$((SH_W+1)); n=$SH_W ;;
        *) SH_I=$((SH_I+1)); n=$SH_I ;;
    esac
    [ "$n" -le "$MAX_HITS" ] && emit_level "$1" "$2"
    return 0
}
cap_note() {
    [ "$SH_C" -gt "$MAX_HITS" ] && info "$1: $((SH_C-MAX_HITS)) more [CONFIRMED] lines not shown (cap $MAX_HITS)"
    [ "$SH_S" -gt "$MAX_HITS" ] && info "$1: $((SH_S-MAX_HITS)) more [SUSPECTED] lines not shown (cap $MAX_HITS)"
    [ "$SH_W" -gt "$MAX_HITS" ] && info "$1: $((SH_W-MAX_HITS)) more [WARNING] lines not shown (cap $MAX_HITS)"
    return 0
}
own_note() { [ "$2" -gt 0 ] && info "$1: $2 own config-change line(s) skipped (NSIP + $OWN_DESC)"; return 0; }

META_RE='[;|`]|[$][(]|[$][{]IFS[}]|[$]IFS|b64decode|base64|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]]|/dev/tcp|nc[[:space:]]+-e|whoami|printf[[:space:]]'
SYS_RE='pitboss|NSPPE|missed too many heartbeats|unexpectedly died|nsaaad.*(SIGNALED|EXITED)|maximum number of restarts|declaring system failure|All monitored processes have exited|scanner-probe|SSL_HANDSHAKE_FAILURE|[$][{]IFS[}]|b64decode'
CRASH_RE='nsaaad.*(SIGNALED|EXITED)|maximum number of restarts|declaring system failure|All monitored processes have exited'
POISON_CTX_RE='pitboss|NSPPE|heartbeats|unexpectedly died|LOGIN|[Uu]ser'
IFS_RE='[$][{]IFS[}]|b64decode'
s11=0
if [ "$NSYS" -gt 0 ]; then
  for f in "${SYS_LOGS[@]}"; do
    reset_caps; nsppe=0; dtls=0; own_skip=0
    newtmp; L="$TMPF"
    log_stream "$f" | grep -nE -- "$SYS_RE" > "$L" 2>/dev/null
    while IFS= read -r line; do
        if own_cmd "$line"; then own_skip=$((own_skip+1)); continue; fi
        is_audit_line "$line" && line="$line  [own-config filter not applied: $OWN_WHY]"
        if [[ $line == *SSL_HANDSHAKE_FAILURE* ]]; then
            [[ $line == *DTLS* ]] && dtls=1
            continue
        fi
        if [[ $line =~ $POISON_CTX_RE ]] && [[ $line =~ $META_RE ]]; then
            show S "$f: log-poisoning exploitation ATTEMPT (execution not proven): $line"; s11=$((s11+1))
        elif [[ $line == *scanner-probe* ]]; then
            show S "$f: recon username scanner-probe (Arctic Wolf): $line"; s11=$((s11+1))
        elif [[ $line == *"pitboss NOT restarting NSPPE"* ]]; then
            nsppe=1; show W "$f: NSPPE crash watchdog line (GTIG CVE-2026-88772 indicator when paired with DTLS failure): $line"; s11=$((s11+1))
        elif [[ $line =~ $CRASH_RE ]]; then
            show W "$f: nsaaad crash/restart (Beaumont SAML-issue pattern; other causes possible): $line"; s11=$((s11+1))
        elif [[ $line =~ $IFS_RE ]]; then
            show S "$f: IFS/b64decode in log line: $line"; s11=$((s11+1))
        else
            show W "$f: heartbeat/died message without injection syntax: $line"; s11=$((s11+1))
        fi
    done < "$L"
    if [ "$nsppe" -eq 1 ] && [ "$dtls" -eq 1 ]; then
        suspect "$f: NSPPE crash AND DTLS handshake failure in same log (GTIG CVE-2026-88772 pattern) - correlate timestamps"
    fi
    cap_note "$f"; own_note "$f" "$own_skip"
  done
fi

ACC_RE='/vpn/media/[^ "?]*[.]ico|/vpn/scripts/linux/|receiver[.](v2[.])?min|LogonUISimple[.]html[.]style|ns-88771-poc|PoCbit|Python-urllib|platypus-agent|PD9[A-Za-z0-9+/]{16,}|[$][{]IFS[}]|%24%7BIFS%7D|e826d7ddf3c85920|NSC_TASS=[^;" ]*(%7C|%3B|%60|%24%28)|(doAuthentication[.]do|/cgi/login|doLogon[.]do|tmindex[.]html|GetUserName)[^ ]*(%3B|%7C|%60|%24%28|;|[|])'
U42_RE='/vpn/scripts/linux/(nsg64|nsgser18|nsgsupport|nsgpackage64|nsgbuild)[.]deb|/vpn/scripts/linux/nginstaller|/vpn/scripts/linux/[^ "?]*[.]php'
PD9_RE='PD9[A-Za-z0-9+/]{16,}'
ICO_RE='/vpn/media/[^ "?]*[.]ico'
ALIASREQ_RE='receiver[.](v2[.])?min|LogonUISimple[.]html[.]style'
TOKEN_RE='e826d7ddf3c85920|NSC_TASS='
POC_RE='ns-88771-poc|PoCbit'
if [ "$NACC" -gt 0 ]; then
  for f in "${ACC_LOGS[@]}"; do
    reset_caps; legit_dl=0
    newtmp; L="$TMPF"
    log_stream "$f" | grep -nE -- "$ACC_RE" > "$L" 2>/dev/null
    while IFS= read -r line; do
        if [[ $line =~ $U42_RE ]]; then
            show S "$f: request to published webshell name in /vpn/scripts/linux (GTIG/Unit 42): $line"; s11=$((s11+1))
        elif [[ $line == */vpn/scripts/linux/* ]]; then
            legit_dl=$((legit_dl+1))
        elif [[ $line =~ $PD9_RE ]]; then
            show S "$f: base64 PHP ('PD9') in request - access-log payload staging (eSentire/CERT-EU): $line"; s11=$((s11+1))
        elif [[ $line =~ $ICO_RE ]]; then
            show S "$f: /vpn/media/*.ico request (GTIG .sig-webshell route): $line"; s11=$((s11+1))
        elif [[ $line =~ $ALIASREQ_RE ]]; then
            show S "$f: request to webshell alias (GreyNoise/LevelBlue/Poppelgaard): $line"; s11=$((s11+1))
        elif [[ $line =~ $TOKEN_RE ]]; then
            show S "$f: .ctxs.receiver token / NSC_TASS command cookie: $line"; s11=$((s11+1))
        elif [[ $line =~ $POC_RE ]]; then
            show S "$f: PoC/scanner User-Agent (someone tested the box): $line"; s11=$((s11+1))
        elif [[ $line == *platypus-agent* ]]; then
            show S "$f: Platypus agent User-Agent (TENEX): $line"; s11=$((s11+1))
        elif [[ $line == *Python-urllib* ]]; then
            show W "$f: Python-urllib client (only meaningful with auth-endpoint payload): $line"; s11=$((s11+1))
        else
            show S "$f: shell metacharacters / IFS in request: $line"; s11=$((s11+1))
        fi
    done < "$L"
    [ "$legit_dl" -gt 0 ] && info "$f: $legit_dl requests for other files in /vpn/scripts/linux (normal VPN client downloads; content checked in section 2)"
    cap_note "$f"
  done
fi

ALL_LOGS=( ${SYS_LOGS[@]+"${SYS_LOGS[@]}"} ${ACC_LOGS[@]+"${ACC_LOGS[@]}"} )
if [ $((NSYS + NACC)) -gt 0 ]; then
  for f in "${ALL_LOGS[@]}"; do
    reset_caps; own_skip=0
    newtmp; L="$TMPF"
    log_stream "$f" | grep -niwF "${IP_GREP_ARGS[@]}" "${DOM_GREP_ARGS[@]}" > "$L" 2>/dev/null
    while IFS= read -r line; do
        if own_cmd "$line"; then own_skip=$((own_skip+1)); continue; fi
        nf=""; is_audit_line "$line" && nf="  [own-config filter not applied: $OWN_WHY]"
        lvl=""; what=""
        for ip in "${IP_STRONG[@]}"; do
            if [[ $line == *"$ip"* ]] && ip_in_line "$ip" "$line"; then lvl=S; what="IoC IP $ip"; break; fi
        done
        if [ -z "$lvl" ]; then
            for ip in "${IP_NOISY[@]}"; do
                if [[ $line == *"$ip"* ]] && ip_in_line "$ip" "$line"; then lvl=W; what="IoC IP $ip (shared/residential/VPN - weak)"; break; fi
            done
        fi
        lline=$(lc "$line")
        for dm in "${DOMAINS_SUSP[@]}"; do
            if [[ $lline == *"$dm"* ]]; then lvl=S; what="${what:+$what, }IoC domain $dm"; break; fi
        done
        if [ -z "$lvl" ]; then
            for dm in "${DOMAINS_WARN[@]}"; do
                if [[ $lline == *"$dm"* ]]; then lvl=W; what="domain $dm (legit service, abused)"; break; fi
            done
        fi
        [ -n "$lvl" ] || continue
        show "$lvl" "$f: $what: $line$nf"; s11=$((s11+1))
    done < "$L"
    cap_note "$f (IP/domain)"; own_note "$f (IP/domain)" "$own_skip"
  done
fi
info "Cloudflare WARP egress IPs (104.28.x) are not scanned: shared by unrelated users."
[ "$s11" -eq 0 ] && ok "No log indicators found in available logs."

# =====================================================================
section "11. Network (live, read-only)"
if command -v sockstat >/dev/null 2>&1; then
    LISTEN=$(sockstat -46l 2>/dev/null)
else
    LISTEN=$(netstat -an 2>/dev/null | grep -i listen)
fi
PORT_RE='[.:](41[0-9][0-9][0-9]|9909|9910)([[:space:]]|$)'
PROC_RE='perl|python'
s12=0
if [ -n "$LISTEN" ]; then
    while IFS= read -r l; do
        [[ $l =~ $PORT_RE ]] || continue
        if [[ $l =~ $PROC_RE ]]; then
            suspect "Listener in nsmon.pl/SAML-kit range by perl/python: $l"
        else
            warn "Listener in nsmon.pl range 41000-41999 or 9909/9910 (could be legitimate): $l"
        fi
        s12=$((s12+1))
    done <<< "$LISTEN"
fi
CONN_HITS=$(netstat -an 2>/dev/null | grep -wF "${IP_GREP_ARGS[@]}")
if [ -n "$CONN_HITS" ]; then
    while IFS= read -r l; do
        hit=""
        for ip in "${IP_STRONG[@]}"; do
            if ip_in_line "$ip" "$l"; then confirm "Live socket to IoC IP $ip: $l"; hit=1; s12=$((s12+1)); break; fi
        done
        [ -n "$hit" ] && continue
        for ip in "${IP_NOISY[@]}"; do
            if ip_in_line "$ip" "$l"; then suspect "Live socket to shared/noisy IoC IP $ip: $l"; s12=$((s12+1)); break; fi
        done
    done <<< "$CONN_HITS"
fi
[ "$s12" -eq 0 ] && ok "No suspicious listeners and no live sockets to IoC IPs."

# =====================================================================
section "Summary"
printf '%sCONFIRMED: %d%s   %sSUSPECTED: %d%s   %sWARNING: %d%s\n' \
    "$C_RED" "$N_CONF" "$C_RESET" "$C_ORANGE" "$N_SUSP" "$C_RESET" "$C_YELLOW" "$N_WARN" "$C_RESET"
printf 'CONFIRMED: %d   SUSPECTED: %d   WARNING: %d\n' "$N_CONF" "$N_SUSP" "$N_WARN" >> "$REPORT"
info "Report: $REPORT"
info "A clean result does NOT prove a clean appliance: webshell names, tokens and IPs are per victim. Preserve evidence before patching; patching does not remove backdoors."

if   [ "$N_CONF" -gt 0 ]; then exit 2
elif [ "$N_SUSP" -gt 0 ]; then exit 1
else exit 0; fi
