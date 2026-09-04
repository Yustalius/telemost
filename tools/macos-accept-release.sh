#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat <<'EOF'
Usage: macos-accept-release.sh [options] <Telemost.app>

Options:
  --allow-unsigned         Continue automated checks when the app or DMG is unsigned.
                           Signature checks are reported as SKIP, never PASS.
  --dmg PATH              Verify the release DMG and its adjacent .sha256 file.
  --diagnostic-log PATH   Check diagnostic-log metadata without reading its contents.
  --checklist PATH        Read interactive results as key=PASS|FAIL|SKIP|NOT_RUN.
  --system-root PATH      Read launchd plists below PATH (default: /).
  --user-library PATH     Read preference/log metadata below PATH (default: ~/Library).
  --temporary-root PATH   Read IPC marker names below PATH (default: system temp dir).
  -h, --help              Show this help.

Exit codes:
  0  Automated validation completed without failures. The printed overall status may
     still be SKIP or NOT RUN when signing or interactive scenarios are incomplete.
  1  A mandatory automated check or an interactive scenario failed.
  2  Invalid arguments or checklist data.
  3  The requested app, DMG, or diagnostic log is unavailable.

Interactive checklist keys:
  first_launch, screen_recording, accessibility, microphone,
  service_start_restart, tunnel_relay, screen_control, clipboard, audio,
  file_transfer, restart_after_reboot, url_scheme_launch, normal_logs,
  diagnostic_logs
EOF
}

status_line() {
    printf '[%s] %s\n' "$1" "$2"
}

fail_check() {
    status_line FAIL "$1"
    failure_count=$((failure_count + 1))
}

pass_check() {
    status_line PASS "$1"
}

skip_check() {
    status_line SKIP "$1"
}

not_run_check() {
    status_line 'NOT RUN' "$1"
}

artifact_unavailable() {
    status_line 'NOT FOUND' "$1"
    echo 'Automated validation: NOT RUN'
    echo 'Overall acceptance: NOT RUN'
    exit 3
}

plist_value() {
    /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null
}

trim_value() {
    local value=$1
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    printf '%s\n' "$value"
}

normalize_status() {
    case "$1" in
        PASS|FAIL|SKIP) printf '%s\n' "$1" ;;
        NOT_RUN|'NOT RUN') printf '%s\n' 'NOT RUN' ;;
        *) return 1 ;;
    esac
}

validate_launchd_plist() {
    local plist=$1
    local label=$2
    local kind=$3
    local expected_first
    local expected_second
    local expected_third=''

    if [[ "$kind" == daemon ]]; then
        expected_first=/bin/sh
        expected_second=-c
        expected_third=/Applications/Telemost.app/Contents/MacOS/TelemostService
    else
        expected_first=/Applications/Telemost.app/Contents/MacOS/Telemost
        expected_second=--server
    fi

    if [[ "$(plist_value "$plist" Label || true)" != "$label" ]]; then
        return 1
    fi
    if [[ "$(plist_value "$plist" ProgramArguments:0 || true)" != "$expected_first" ||
          "$(plist_value "$plist" ProgramArguments:1 || true)" != "$expected_second" ]]; then
        return 1
    fi
    if [[ -n "$expected_third" &&
          "$(plist_value "$plist" ProgramArguments:2 || true)" != "$expected_third" ]]; then
        return 1
    fi
    if LC_ALL=C /usr/bin/grep -E -i -q \
        'com\.carriez|rustdesk|liblibtelemost|Contents/MacOS/service' "$plist"; then
        return 1
    fi
    return 0
}

allow_unsigned=false
dmg_path=''
diagnostic_log=''
checklist=''
system_root=/
user_library="$HOME/Library"
temporary_root=${TMPDIR:-/tmp}
app_path=''

while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-unsigned)
            allow_unsigned=true
            shift
            ;;
        --dmg|--diagnostic-log|--checklist|--system-root|--user-library|--temporary-root)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            case "$1" in
                --dmg) dmg_path=$2 ;;
                --diagnostic-log) diagnostic_log=$2 ;;
                --checklist) checklist=$2 ;;
                --system-root) system_root=$2 ;;
                --user-library) user_library=$2 ;;
                --temporary-root) temporary_root=$2 ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi
app_path=${1%/}

[[ -d "$app_path" ]] || artifact_unavailable 'Target Telemost.app is unavailable'
[[ -z "$dmg_path" || -f "$dmg_path" ]] || artifact_unavailable 'Requested DMG is unavailable'
[[ -z "$diagnostic_log" || -f "$diagnostic_log" ]] || artifact_unavailable 'Requested diagnostic log is unavailable'
[[ -z "$checklist" || -f "$checklist" ]] || artifact_unavailable 'Requested checklist is unavailable'
[[ -d "$system_root" ]] || artifact_unavailable 'System-state root is unavailable'
[[ -d "$user_library" ]] || artifact_unavailable 'User Library root is unavailable'
[[ -d "$temporary_root" ]] || artifact_unavailable 'Temporary-state root is unavailable'

failure_count=0
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/telemost-accept.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

plist="$app_path/Contents/Info.plist"
if [[ ! -f "$plist" ]]; then
    fail_check 'Info.plist exists'
else
    if [[ "$(plist_value "$plist" CFBundleIdentifier || true)" == com.telemost.desktop ]]; then
        pass_check 'Bundle identifier is com.telemost.desktop'
    else
        fail_check 'Bundle identifier is com.telemost.desktop'
    fi
    if [[ "$(plist_value "$plist" CFBundleShortVersionString || true)" == 1.5.0 ]]; then
        pass_check 'Version is 1.5.0'
    else
        fail_check 'Version is 1.5.0'
    fi
    if [[ "$(plist_value "$plist" CFBundleVersion || true)" == 68 ]]; then
        pass_check 'Build is 68'
    else
        fail_check 'Build is 68'
    fi
    if [[ "$(plist_value "$plist" CFBundleURLTypes:0:CFBundleURLSchemes:0 || true)" == telemost ]]; then
        pass_check 'telemost URL scheme is declared'
    else
        fail_check 'telemost URL scheme is declared'
    fi
fi

mach_o_count=0
wrong_arch=false
while IFS= read -r -d '' candidate; do
    if /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O'; then
        mach_o_count=$((mach_o_count + 1))
        if [[ "$(/usr/bin/lipo -archs "$candidate" 2>/dev/null || true)" != arm64 ]]; then
            wrong_arch=true
        fi
    fi
done < <(/usr/bin/find "$app_path" -type f -print0)
if [[ $mach_o_count -gt 0 && "$wrong_arch" == false ]]; then
    pass_check 'All Mach-O components are arm64'
else
    fail_check 'All Mach-O components are arm64'
fi

if /usr/bin/find "$app_path" \( \
    -iname '*.dSYM' -o \
    -iname '*.symbols' -o \
    -iname '*.symbolmap' -o \
    -iname '*.bcsymbolmap' -o \
    -iname '*split*debug*info*' -o \
    -iname '*flutter*symbol*' \
\) -print -quit | /usr/bin/grep -q .; then
    fail_check 'No symbol artifacts are bundled'
else
    pass_check 'No symbol artifacts are bundled'
fi

if "$script_dir/macos-audit-release.sh" "$app_path" >"$work_dir/audit-output.txt" 2>&1; then
    pass_check 'Release artifact audit passes'
else
    fail_check 'Release artifact audit passes'
fi

signature_status=PASS
if /usr/bin/codesign -d --verbose=4 "$app_path" >"$work_dir/signature.txt" 2>&1 &&
    ! /usr/bin/grep -q 'Signature=adhoc' "$work_dir/signature.txt"; then
    if /usr/bin/grep -F -x -q 'Authority=Telemost Signing' "$work_dir/signature.txt"; then
        pass_check 'Signing authority is Telemost Signing'
    else
        fail_check 'Signing authority is Telemost Signing'
        signature_status=FAIL
    fi
    if /usr/bin/codesign --verify --deep --strict "$app_path" >/dev/null 2>&1; then
        pass_check 'App signature passes strict deep verification'
    else
        fail_check 'App signature passes strict deep verification'
        signature_status=FAIL
    fi
    if /usr/bin/codesign -d --verbose=4 "$app_path" 2>&1 |
        /usr/bin/grep -q 'flags=.*runtime'; then
        pass_check 'Hardened runtime is enabled'
    else
        fail_check 'Hardened runtime is enabled'
        signature_status=FAIL
    fi
    if /usr/bin/codesign -d -r- "$app_path" >"$work_dir/requirement.txt" 2>&1 &&
        /usr/bin/grep -q 'designated =>' "$work_dir/requirement.txt"; then
        pass_check 'Designated requirement is present'
    else
        fail_check 'Designated requirement is present'
        signature_status=FAIL
    fi
    if /usr/bin/codesign -d --entitlements - --xml "$app_path" \
        >"$work_dir/entitlements.plist" 2>/dev/null &&
        /usr/bin/plutil -lint "$work_dir/entitlements.plist" >/dev/null 2>&1; then
        pass_check 'Signed entitlements are readable'
    else
        fail_check 'Signed entitlements are readable'
        signature_status=FAIL
    fi
elif [[ "$allow_unsigned" == true ]]; then
    skip_check 'Signature, hardened runtime, designated requirement, and entitlements are not verified (--allow-unsigned)'
    signature_status=SKIP
else
    fail_check 'App has a verifiable signature'
    signature_status=FAIL
fi

if [[ -n "$dmg_path" ]]; then
    expected_dmg=telemost-1.5.0-aarch64.dmg
    if [[ "${dmg_path##*/}" == "$expected_dmg" ]]; then
        pass_check 'DMG filename is telemost-1.5.0-aarch64.dmg'
    else
        fail_check 'DMG filename is telemost-1.5.0-aarch64.dmg'
    fi
    if /usr/bin/hdiutil verify "$dmg_path" >/dev/null 2>&1; then
        pass_check 'DMG structure verifies'
    else
        fail_check 'DMG structure verifies'
    fi
    checksum_file="$dmg_path.sha256"
    if [[ -f "$checksum_file" ]]; then
        expected_digest=$(/usr/bin/awk 'NR == 1 { print $1 }' "$checksum_file")
        expected_name=$(/usr/bin/awk 'NR == 1 { print $2 }' "$checksum_file")
        actual_digest=$(/usr/bin/shasum -a 256 "$dmg_path" | /usr/bin/awk '{ print $1 }')
        expected_name=${expected_name#\*}
        if [[ "$expected_digest" == "$actual_digest" && "$expected_name" == "$expected_dmg" ]]; then
            pass_check 'DMG SHA-256 matches its checksum file'
        else
            fail_check 'DMG SHA-256 matches its checksum file'
        fi
    else
        fail_check 'DMG checksum file is present'
    fi
    if /usr/bin/codesign -d "$dmg_path" >/dev/null 2>&1; then
        if /usr/bin/codesign --verify --strict "$dmg_path" >/dev/null 2>&1; then
            pass_check 'DMG signature passes strict verification'
        else
            fail_check 'DMG signature passes strict verification'
            signature_status=FAIL
        fi
    elif [[ "$allow_unsigned" == true ]]; then
        skip_check 'DMG signature is not verified (--allow-unsigned)'
        signature_status=SKIP
    else
        fail_check 'DMG has a verifiable signature'
        signature_status=FAIL
    fi
fi

system_root=${system_root%/}
[[ -n "$system_root" ]] || system_root=/
if [[ "$system_root" == / ]]; then
    daemon_plist=/Library/LaunchDaemons/com.telemost.desktop.service.plist
    agent_plist=/Library/LaunchAgents/com.telemost.desktop.agent.plist
    daemon_dir=/Library/LaunchDaemons
    agent_dir=/Library/LaunchAgents
else
    daemon_plist="$system_root/Library/LaunchDaemons/com.telemost.desktop.service.plist"
    agent_plist="$system_root/Library/LaunchAgents/com.telemost.desktop.agent.plist"
    daemon_dir="$system_root/Library/LaunchDaemons"
    agent_dir="$system_root/Library/LaunchAgents"
fi

launchd_present=false
if [[ -f "$daemon_plist" ]]; then
    launchd_present=true
    if validate_launchd_plist "$daemon_plist" com.telemost.desktop.service daemon; then
        pass_check 'LaunchDaemon label and arguments use current names'
    else
        fail_check 'LaunchDaemon label and arguments use current names'
    fi
fi
if [[ -f "$agent_plist" ]]; then
    launchd_present=true
    if validate_launchd_plist "$agent_plist" com.telemost.desktop.agent agent; then
        pass_check 'LaunchAgent label and arguments use current names'
    else
        fail_check 'LaunchAgent label and arguments use current names'
    fi
fi
if [[ "$launchd_present" == false ]]; then
    not_run_check 'Launchd plist validation; current entries are not installed'
fi

legacy_launchd=false
for state_dir in "$daemon_dir" "$agent_dir"; do
    if [[ -d "$state_dir" ]] && /usr/bin/find "$state_dir" -maxdepth 1 -type f \
        \( -iname '*com.carriez*' -o -iname '*rustdesk*' \) -print -quit |
        /usr/bin/grep -q .; then
        legacy_launchd=true
    fi
done
if [[ "$legacy_launchd" == true ]]; then
    skip_check 'Pre-existing legacy launchd entries detected; cleanup is deferred to iteration 7'
else
    pass_check 'No legacy launchd entry names detected'
fi

if /usr/bin/find "$user_library/Preferences" -maxdepth 1 \
    \( -type f -o -type d \) -name 'com.telemost.Telemost*' -print -quit 2>/dev/null |
    /usr/bin/grep -q .; then
    pass_check 'Current preferences namespace exists'
else
    not_run_check 'Current preferences namespace; no settings have been written'
fi

if [[ -d "$user_library/Logs/Telemost" ]]; then
    log_file_count=$(/usr/bin/find "$user_library/Logs/Telemost" -maxdepth 1 -type f 2>/dev/null |
        /usr/bin/wc -l | /usr/bin/tr -d ' ')
    if [[ $log_file_count -le 7 ]]; then
        pass_check "Current log namespace retains at most 7 files ($log_file_count found; contents not read)"
    else
        fail_check "Current log namespace retains at most 7 files ($log_file_count found; contents not read)"
    fi
else
    not_run_check 'Current log namespace; no logs have been written'
fi

if /usr/bin/find "$user_library/Preferences" "$user_library/Logs" -maxdepth 1 \
    \( -iname '*com.carriez*' -o -iname '*rustdesk*' \) -print -quit 2>/dev/null |
    /usr/bin/grep -q .; then
    skip_check 'Pre-existing legacy preference/log names detected; cleanup is deferred to iteration 7'
else
    pass_check 'No legacy preference/log names detected'
fi

if [[ -e "$temporary_root/Telemost-$(/usr/bin/id -u)" ]]; then
    pass_check 'Current Telemost IPC prefix exists'
else
    not_run_check 'Current Telemost IPC prefix; application is not running'
fi
if /usr/bin/find "$temporary_root" -maxdepth 1 \
    \( -iname '*rustdesk*' -o -iname '*com.carriez*' \) -print -quit 2>/dev/null |
    /usr/bin/grep -q .; then
    skip_check 'Pre-existing legacy temporary names detected; cleanup is deferred to iteration 7'
else
    pass_check 'No legacy temporary names detected'
fi

if [[ -n "$diagnostic_log" ]]; then
    if [[ -s "$diagnostic_log" ]]; then
        pass_check 'Diagnostic log exists and is non-empty (contents not read)'
    else
        fail_check 'Diagnostic log exists and is non-empty (contents not read)'
    fi
fi

manual_keys=(
    first_launch screen_recording accessibility microphone
    service_start_restart tunnel_relay screen_control clipboard audio file_transfer
    restart_after_reboot url_scheme_launch normal_logs diagnostic_logs
)
manual_labels=(
    'First launch with clean settings'
    'Screen Recording permission'
    'Accessibility permission'
    'Microphone permission'
    'TelemostService start and restart'
    'Connection through tunnel/relay'
    'Remote screen control'
    'Clipboard'
    'Audio'
    'File transfer'
    'Restart after reboot'
    'telemost:// launch'
    'Normal WARN/ERROR logs'
    'Diagnostic INFO logs without sensitive values'
)
manual_statuses=()
for index in "${!manual_keys[@]}"; do
    manual_statuses[$index]='NOT RUN'
done

if [[ -n "$checklist" ]]; then
    while IFS='=' read -r raw_key raw_value || [[ -n "$raw_key$raw_value" ]]; do
        key=$(trim_value "$raw_key")
        value=$(trim_value "$raw_value")
        [[ -z "$key" || "$key" == \#* ]] && continue
        if ! value=$(normalize_status "$value"); then
            echo 'Invalid checklist status; use PASS, FAIL, SKIP, or NOT_RUN' >&2
            exit 2
        fi
        found=false
        for index in "${!manual_keys[@]}"; do
            if [[ "${manual_keys[$index]}" == "$key" ]]; then
                manual_statuses[$index]=$value
                found=true
                break
            fi
        done
        if [[ "$found" == false ]]; then
            echo 'Unknown checklist key' >&2
            exit 2
        fi
    done <"$checklist"
fi

echo 'Interactive functional checklist:'
manual_failure=false
manual_skip=false
manual_not_run=false
for index in "${!manual_keys[@]}"; do
    value=${manual_statuses[$index]}
    status_line "$value" "${manual_labels[$index]}"
    case "$value" in
        FAIL) manual_failure=true ;;
        SKIP) manual_skip=true ;;
        'NOT RUN') manual_not_run=true ;;
    esac
done

if [[ $failure_count -gt 0 ]]; then
    echo 'Automated validation: FAIL'
    echo 'Overall acceptance: FAIL'
    exit 1
fi

echo 'Automated validation: PASS'
if [[ "$manual_failure" == true ]]; then
    echo 'Interactive scenarios: FAIL'
    echo 'Overall acceptance: FAIL'
    exit 1
fi
if [[ "$manual_not_run" == true ]]; then
    functional_status='NOT RUN'
elif [[ "$manual_skip" == true ]]; then
    functional_status=SKIP
else
    functional_status=PASS
fi
echo "Interactive scenarios: $functional_status"

if [[ "$functional_status" == PASS && "$signature_status" == PASS ]]; then
    echo 'Overall acceptance: PASS'
elif [[ "$functional_status" == 'NOT RUN' ]]; then
    echo 'Overall acceptance: NOT RUN'
else
    echo 'Overall acceptance: SKIP'
fi
