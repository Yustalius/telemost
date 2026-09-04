#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
auditor="$script_dir/macos-audit-release.sh"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/telemost-audit-test.XXXXXX")
trap 'rm -rf "$fixture_root"' EXIT

version_value=$(awk '$1 == "version:" { print $2; exit }' "$repo_root/flutter/pubspec.yaml")
version=${version_value%%+*}
build=${version_value#*+}
base_app="$fixture_root/base/Telemost.app"

mkdir -p "$base_app/Contents/MacOS" "$base_app/Contents/Frameworks" \
    "$base_app/Contents/Resources/licenses"
cp /usr/bin/true "$base_app/Contents/MacOS/Telemost"
cp /usr/bin/true "$base_app/Contents/MacOS/TelemostService"
cp /usr/bin/true "$base_app/Contents/Frameworks/libtelemost.dylib"
printf '%s\n' 'RUSTDESK_HWCODEC_NVENC_GPU' >"$base_app/Contents/Resources/compatibility.txt"
printf '%s\n' 'Purslane Tech rustdesk.com' >"$base_app/Contents/Resources/licenses/NOTICE.txt"

cat >"$base_app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Telemost</string>
    <key>CFBundleIdentifier</key>
    <string>com.telemost.desktop</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleVersion</key>
    <string>$build</string>
    <key>CFBundleURLTypes</key>
    <array><dict><key>CFBundleURLSchemes</key><array><string>telemost</string></array></dict></array>
</dict>
</plist>
EOF

pass_count=0

new_case() {
    local name=$1
    local case_app="$fixture_root/$name/Telemost.app"
    mkdir -p "$(dirname "$case_app")"
    cp -R "$base_app" "$case_app"
    printf '%s\n' "$case_app"
}

expect_fail() {
    local name=$1
    local case_app=$2
    if "$auditor" "$case_app" >"$fixture_root/$name.log" 2>&1; then
        echo "self-test failed: '$name' unexpectedly passed" >&2
        exit 1
    fi
    pass_count=$((pass_count + 1))
}

"$auditor" "$base_app" >/dev/null
pass_count=$((pass_count + 1))

expect_fail missing-bundle "$fixture_root/missing/Telemost.app"

case_app=$(new_case missing-main)
rm "$case_app/Contents/MacOS/Telemost"
expect_fail missing-main "$case_app"

case_app=$(new_case missing-helper)
rm "$case_app/Contents/MacOS/TelemostService"
expect_fail missing-helper "$case_app"

case_app=$(new_case missing-library)
rm "$case_app/Contents/Frameworks/libtelemost.dylib"
expect_fail missing-library "$case_app"

case_app=$(new_case old-service)
cp /usr/bin/true "$case_app/Contents/MacOS/service"
expect_fail old-service "$case_app"

case_app=$(new_case old-library)
cp /usr/bin/true "$case_app/Contents/Frameworks/liblibtelemost.dylib"
expect_fail old-library "$case_app"

case_app=$(new_case bundle-id)
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier com.carriez.telemost' "$case_app/Contents/Info.plist"
expect_fail bundle-id "$case_app"

case_app=$(new_case version)
/usr/libexec/PlistBuddy -c 'Set :CFBundleShortVersionString 0.0.0' "$case_app/Contents/Info.plist"
expect_fail version "$case_app"

case_app=$(new_case build)
/usr/libexec/PlistBuddy -c 'Set :CFBundleVersion 0' "$case_app/Contents/Info.plist"
expect_fail build "$case_app"

case_app=$(new_case scheme)
/usr/libexec/PlistBuddy -c 'Set :CFBundleURLTypes:0:CFBundleURLSchemes:0 invalid' "$case_app/Contents/Info.plist"
expect_fail scheme "$case_app"

case_app=$(new_case copyright)
/usr/libexec/PlistBuddy -c 'Add :NSHumanReadableCopyright string placeholder' "$case_app/Contents/Info.plist"
expect_fail copyright "$case_app"

blocked_markers=(
    "com.carriez"
    "Purslane Tech"
    "telemost.example"
    "RustDesk"
    "rs-ny.rustdesk.com"
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

index=0
for marker in "${blocked_markers[@]}"; do
    index=$((index + 1))
    case_app=$(new_case "marker-$index")
    printf '%s\n' "$marker" >"$case_app/Contents/Resources/blocked.txt"
    expect_fail "marker-$index" "$case_app"
done

case_app=$(new_case compatibility-plus-brand)
printf '%s\n' 'RUSTDESK_HWCODEC_NVENC_GPU RustDesk' \
    >"$case_app/Contents/Resources/compatibility.txt"
expect_fail compatibility-plus-brand "$case_app"

case_app=$(new_case compatibility-wrong-case)
printf '%s\n' 'rustdesk_hwcodec_nvenc_gpu' \
    >"$case_app/Contents/Resources/compatibility.txt"
expect_fail compatibility-wrong-case "$case_app"

license_blocked_markers=("com.carriez" "telemost.example" "201.24.52.171")
index=0
for marker in "${license_blocked_markers[@]}"; do
    index=$((index + 1))
    case_app=$(new_case "license-scope-$index")
    printf '%s\n' "$marker" >"$case_app/Contents/Resources/licenses/not-legal.txt"
    expect_fail "license-scope-$index" "$case_app"
done

case_app=$(new_case dsym)
mkdir "$case_app/Contents/Resources/Telemost.dSYM"
expect_fail dsym "$case_app"

case_app=$(new_case split-debug-info)
mkdir "$case_app/Contents/Resources/split-debug-info"
expect_fail split-debug-info "$case_app"

case_app=$(new_case flutter-symbols)
mkdir "$case_app/Contents/Resources/flutter-symbols"
expect_fail flutter-symbols "$case_app"

case_app=$(new_case symbol-map)
printf '%s\n' placeholder >"$case_app/Contents/Resources/app.macos-arm64.symbols"
expect_fail symbol-map "$case_app"

case_app=$(new_case macho-strings)
cat >"$fixture_root/marker.c" <<'EOF'
__attribute__((used)) static const char marker[] = "telemost.example";
int main(void) { return marker[0] == '\0'; }
EOF
/usr/bin/clang "$fixture_root/marker.c" -o "$case_app/Contents/MacOS/Telemost"
expect_fail macho-strings "$case_app"

echo "macOS release audit self-test passed ($pass_count checks)"
