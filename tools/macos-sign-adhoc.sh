#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "macOS ad-hoc signing failed: $*" >&2
    exit 1
}

[[ $# -eq 1 ]] || fail "usage: $0 /path/to/Telemost.app"

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
app_path=$1
entitlements="$repo_root/flutter/macos/Runner/AdHocRelease.entitlements"

[[ -d "$app_path" ]] || fail "app bundle does not exist: $app_path"
[[ -f "$app_path/Contents/Info.plist" ]] || fail "Contents/Info.plist is missing"
[[ -f "$entitlements" ]] || fail "entitlements are missing: $entitlements"

# A hardened ad-hoc executable has no Team ID to share with embedded frameworks.
# Disable library validation only for this certificate-free test build.
/usr/bin/codesign --force \
    --deep \
    --sign - \
    --options runtime \
    --entitlements "$entitlements" \
    "$app_path" || fail "could not sign $app_path"

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app_path" ||
    fail "signature verification rejected $app_path"

entitlements_dump=$(mktemp) || fail "could not create an entitlement check file"
trap 'rm -f -- "$entitlements_dump"' EXIT
/usr/bin/codesign -d --entitlements - --xml "$app_path" >"$entitlements_dump" 2>/dev/null ||
    fail "could not read signed entitlements"
[[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.cs.disable-library-validation' \
    "$entitlements_dump" 2>/dev/null) == true ]] ||
    fail "library validation is enabled for the ad-hoc build"

echo "Ad-hoc signature verified: $app_path"
