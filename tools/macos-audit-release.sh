#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <Telemost.app>" >&2
    exit 2
fi

app_path=${1%/}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
plist="$app_path/Contents/Info.plist"

fail() {
    echo "macOS release audit failed: $*" >&2
    exit 1
}

[[ -d "$app_path" ]] || fail "bundle does not exist: $app_path"
[[ -f "$plist" ]] || fail "missing Contents/Info.plist"
[[ -x "$app_path/Contents/MacOS/Telemost" ]] || fail "missing executable Contents/MacOS/Telemost"
[[ -x "$app_path/Contents/MacOS/TelemostService" ]] || fail "missing executable Contents/MacOS/TelemostService"
[[ -f "$app_path/Contents/Frameworks/libtelemost.dylib" ]] || fail "missing Contents/Frameworks/libtelemost.dylib"
[[ ! -e "$app_path/Contents/MacOS/service" ]] || fail "legacy Contents/MacOS/service is present"

if find "$app_path" -name 'liblibtelemost.dylib' -print -quit | grep -q .; then
    fail "legacy liblibtelemost.dylib is present"
fi

symbol_artifact=$(find "$app_path" \( \
    -iname '*.dSYM' -o \
    -iname '*.symbols' -o \
    -iname '*.symbolmap' -o \
    -iname '*.bcsymbolmap' -o \
    -iname '*split*debug*info*' -o \
    -iname '*flutter*symbol*' \
\) -print -quit)
[[ -z "$symbol_artifact" ]] || fail "debug symbol artifact is bundled: ${symbol_artifact#"$app_path/"}"

version_value=$(awk '$1 == "version:" { print $2; exit }' "$repo_root/flutter/pubspec.yaml")
[[ "$version_value" == *+* ]] || fail "cannot read version and build number from flutter/pubspec.yaml"
expected_version=${version_value%%+*}
expected_build=${version_value#*+}

plist_value() {
    /usr/libexec/PlistBuddy -c "Print :$1" "$plist" 2>/dev/null
}

[[ "$(plist_value CFBundleIdentifier)" == "com.telemost.desktop" ]] || fail "unexpected CFBundleIdentifier"
[[ "$(plist_value CFBundleShortVersionString)" == "$expected_version" ]] || fail "unexpected CFBundleShortVersionString"
[[ "$(plist_value CFBundleVersion)" == "$expected_build" ]] || fail "unexpected CFBundleVersion"
[[ "$(plist_value CFBundleURLTypes:0:CFBundleURLSchemes:0)" == "telemost" ]] || fail "telemost URL scheme is missing"

for key in NSHumanReadableCopyright NSCopyright CFBundleGetInfoString; do
    if plist_value "$key" >/dev/null; then
        fail "About metadata must not contain $key"
    fi
done

blocked_markers=(
    "com.carriez"
    "Purslane Tech"
    "telemost.example"
    "rustdesk"
    "/Users/runner/work/telemost/telemost"
    "$repo_root"
    "201.24.52.171"
    "127.0.0.1:23455"
    "127.0.0.1:23456"
    "127.0.0.1:23457"
    "/api/audit"
    "/api/heartbeat"
    "liblibtelemost.dylib"
    "Contents/MacOS/service"
)

marker_allowed_in_license() {
    case "$1" in
        "Purslane Tech"|"rustdesk") return 0 ;;
        *) return 1 ;;
    esac
}

scan_rustdesk_marker() {
    local payload=$1
    local source_path=$2
    local line
    local cleaned

    case "$source_path" in
        "$app_path/Contents/Resources/licenses/"*) return ;;
    esac

    while IFS= read -r line; do
        cleaned=${line//RUSTDESK_HWCODEC_NVENC_GPU/}
        if printf '%s\n' "$cleaned" | LC_ALL=C grep -F -i -q -- "rustdesk"; then
            fail "forbidden marker 'rustdesk' in ${source_path#"$app_path/"}"
        fi
    done < <(LC_ALL=C grep -a -F -i -- "rustdesk" "$payload" || true)
}

scan_payload() {
    local payload=$1
    local source_path=$2
    local in_licenses=false
    local marker

    case "$source_path" in
        "$app_path/Contents/Resources/licenses/"*) in_licenses=true ;;
    esac

    for marker in "${blocked_markers[@]}"; do
        if [[ "$marker" == "rustdesk" ]]; then
            scan_rustdesk_marker "$payload" "$source_path"
            continue
        fi
        if [[ "$in_licenses" == true ]] && marker_allowed_in_license "$marker"; then
            continue
        fi
        if LC_ALL=C grep -a -F -i -q -- "$marker" "$payload"; then
            fail "forbidden marker '$marker' in ${source_path#"$app_path/"}"
        fi
    done
}

strings_output=$(mktemp "${TMPDIR:-/tmp}/telemost-audit-strings.XXXXXX")
trap 'rm -f "$strings_output"' EXIT

while IFS= read -r -d '' entry; do
    printf '%s\n' "${entry#"$app_path/"}" >"$strings_output"
    scan_payload "$strings_output" "$entry"
done < <(find "$app_path" -mindepth 1 -print0)

while IFS= read -r -d '' candidate; do
    if file -b "$candidate" | grep -q 'Mach-O'; then
        strings -a "$candidate" >"$strings_output"
        scan_payload "$strings_output" "$candidate"
    else
        scan_payload "$candidate" "$candidate"
    fi
done < <(find "$app_path" -type f -print0)

echo "macOS release audit passed: $app_path"
