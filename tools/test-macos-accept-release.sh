#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
acceptor="$script_dir/macos-accept-release.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/telemost-accept-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

fail() {
    echo "macOS release acceptance self-test failed: $*" >&2
    exit 1
}

expect_failure() {
    local expected_status=$1
    local expected_text=$2
    shift 2
    local output
    local actual_status

    set +e
    output=$("$@" 2>&1)
    actual_status=$?
    set -e
    [[ $actual_status -eq $expected_status ]] ||
        fail "expected exit $expected_status, got $actual_status"
    if ! printf '%s\n' "$output" | /usr/bin/grep -F -q -- "$expected_text"; then
        printf '%s\n' "$output" >&2
        fail "failure output did not contain: $expected_text"
    fi
}

write_app_plist() {
    local path=$1
    local identifier=$2
    local version=$3
    local build=$4
    local scheme=$5

    cat >"$path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Telemost</string>
<key>CFBundleIdentifier</key><string>$identifier</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$build</string>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>$scheme</string></array></dict></array>
</dict></plist>
EOF
}

write_launchd_plist() {
    local path=$1
    local label=$2
    shift 2

    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0"><dict>'
        printf '<key>Label</key><string>%s</string>\n' "$label"
        printf '%s\n' '<key>ProgramArguments</key><array>'
        while [[ $# -gt 0 ]]; do
            printf '<string>%s</string>\n' "$1"
            shift
        done
        printf '%s\n' '</array></dict></plist>'
    } >"$path"
}

base_app="$test_root/base/Telemost.app"
mkdir -p \
    "$base_app/Contents/MacOS" \
    "$base_app/Contents/Frameworks" \
    "$base_app/Contents/Resources/licenses"
cat >"$test_root/program.c" <<'EOF'
int main(void) { return 0; }
EOF
/usr/bin/clang -arch arm64 "$test_root/program.c" -o "$base_app/Contents/MacOS/Telemost"
/usr/bin/clang -arch arm64 "$test_root/program.c" -o "$base_app/Contents/MacOS/TelemostService"
/usr/bin/clang -arch arm64 -dynamiclib "$test_root/program.c" \
    -o "$base_app/Contents/Frameworks/libtelemost.dylib"
write_app_plist "$base_app/Contents/Info.plist" com.telemost.desktop 1.5.0 68 telemost

state_root="$test_root/state"
user_library="$test_root/user-library"
temporary_root="$test_root/temporary"
mkdir -p \
    "$state_root/Library/LaunchDaemons" \
    "$state_root/Library/LaunchAgents" \
    "$user_library/Preferences" \
    "$user_library/Logs/Telemost" \
    "$temporary_root/Telemost-$(/usr/bin/id -u)"
touch "$user_library/Preferences/com.telemost.Telemost.plist"
write_launchd_plist \
    "$state_root/Library/LaunchDaemons/com.telemost.desktop.service.plist" \
    com.telemost.desktop.service \
    /bin/sh -c /Applications/Telemost.app/Contents/MacOS/TelemostService
write_launchd_plist \
    "$state_root/Library/LaunchAgents/com.telemost.desktop.agent.plist" \
    com.telemost.desktop.agent \
    /Applications/Telemost.app/Contents/MacOS/Telemost --server

common_args=(
    --allow-unsigned
    --system-root "$state_root"
    --user-library "$user_library"
    --temporary-root "$temporary_root"
)

output=$("$acceptor" "${common_args[@]}" "$base_app")
printf '%s\n' "$output" | /usr/bin/grep -F -q 'Automated validation: PASS' ||
    fail 'allow-unsigned fixture did not pass automated validation'
printf '%s\n' "$output" | /usr/bin/grep -F -q 'Signature, hardened runtime, designated requirement, and entitlements are not verified' ||
    fail 'unsigned fixture was not reported as SKIP'
printf '%s\n' "$output" | /usr/bin/grep -F -q 'Overall acceptance: NOT RUN' ||
    fail 'interactive scenarios were not reported as NOT RUN'

manual_fail_checklist="$test_root/manual-fail.checklist"
printf '%s\n' 'first_launch=FAIL' >"$manual_fail_checklist"
set +e
manual_output=$("$acceptor" "${common_args[@]}" --checklist "$manual_fail_checklist" "$base_app" 2>&1)
manual_status=$?
set -e
[[ $manual_status -eq 1 ]] || fail 'manual failure did not return exit 1'
printf '%s\n' "$manual_output" | /usr/bin/grep -F -q 'Automated validation: PASS' ||
    fail 'manual failure incorrectly changed the automated result'
printf '%s\n' "$manual_output" | /usr/bin/grep -F -q 'Interactive scenarios: FAIL' ||
    fail 'manual failure was not reported'

for index in 1 2 3 4 5 6 7 8; do
    touch "$user_library/Logs/Telemost/log-$index"
done
expect_failure 1 '[FAIL] Current log namespace retains at most 7 files' \
    "$acceptor" "${common_args[@]}" "$base_app"
rm "$user_library/Logs/Telemost"/log-*

expect_failure 3 'Target Telemost.app is unavailable' \
    "$acceptor" "${common_args[@]}" "$test_root/missing/Telemost.app"

new_case() {
    local name=$1
    local case_app="$test_root/$name/Telemost.app"
    mkdir -p "$(dirname "$case_app")"
    /usr/bin/ditto "$base_app" "$case_app"
    printf '%s\n' "$case_app"
}

case_app=$(new_case wrong-version)
/usr/libexec/PlistBuddy -c 'Set :CFBundleShortVersionString 0.0.0' "$case_app/Contents/Info.plist"
expect_failure 1 '[FAIL] Version is 1.5.0' "$acceptor" "${common_args[@]}" "$case_app"

case_app=$(new_case wrong-bundle)
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier com.invalid.desktop' "$case_app/Contents/Info.plist"
expect_failure 1 '[FAIL] Bundle identifier is com.telemost.desktop' \
    "$acceptor" "${common_args[@]}" "$case_app"

case_app=$(new_case wrong-scheme)
/usr/libexec/PlistBuddy -c 'Set :CFBundleURLTypes:0:CFBundleURLSchemes:0 invalid' \
    "$case_app/Contents/Info.plist"
expect_failure 1 '[FAIL] telemost URL scheme is declared' \
    "$acceptor" "${common_args[@]}" "$case_app"

case_app=$(new_case wrong-arch)
/usr/bin/clang -arch x86_64 "$test_root/program.c" -o "$case_app/Contents/MacOS/Telemost"
expect_failure 1 '[FAIL] All Mach-O components are arm64' \
    "$acceptor" "${common_args[@]}" "$case_app"

echo 'macOS release acceptance self-test passed'
