#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
signer="$script_dir/macos-sign-release.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/telemost-sign-test.XXXXXX")
mounted_image=""

cleanup() {
    local cleanup_status=$?
    if [[ -n "$mounted_image" ]]; then
        if ! /usr/bin/hdiutil detach "$mounted_image" -force -quiet >/dev/null 2>&1; then
            echo "macOS release signing self-test cleanup failed: could not detach $mounted_image" >&2
            return 1
        fi
    fi
    rm -rf -- "$test_root"
    return "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

fail() {
    echo "macOS release signing self-test failed: $*" >&2
    exit 1
}

expect_failure() {
    local expected=$1
    shift
    local output
    if output=$("$@" 2>&1); then
        fail "command unexpectedly succeeded: $*"
    fi
    if ! printf '%s\n' "$output" | /usr/bin/grep -F -q -- "$expected"; then
        printf '%s\n' "$output" >&2
        fail "failure output did not contain: $expected"
    fi
}

write_plist() {
    local path=$1
    local executable=$2
    local identifier=$3
    local version=$4
    local build=$5

    cat >"$path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$executable</string>
    <key>CFBundleIdentifier</key>
    <string>$identifier</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleVersion</key>
    <string>$build</string>
    <key>CFBundleURLTypes</key>
    <array><dict><key>CFBundleURLSchemes</key><array><string>telemost</string></array></dict></array>
</dict>
</plist>
EOF
}

version_value=$(/usr/bin/awk '$1 == "version:" { print $2; exit }' "$repo_root/flutter/pubspec.yaml")
version=${version_value%%+*}
build=${version_value#*+}
fixture_app="$test_root/fixture/Telemost.app"
nested_app="$fixture_app/Contents/Helpers/Nested.app"
mkdir -p \
    "$fixture_app/Contents/MacOS" \
    "$fixture_app/Contents/Frameworks" \
    "$fixture_app/Contents/Resources/licenses" \
    "$nested_app/Contents/MacOS"

cat >"$test_root/program.c" <<'EOF'
int main(void) { return 0; }
EOF
/usr/bin/clang -arch arm64 "$test_root/program.c" -o "$fixture_app/Contents/MacOS/Telemost"
/usr/bin/clang -arch arm64 "$test_root/program.c" -o "$fixture_app/Contents/MacOS/TelemostService"
/usr/bin/clang -arch arm64 -dynamiclib "$test_root/program.c" -o "$fixture_app/Contents/Frameworks/libtelemost.dylib"
/usr/bin/clang -arch arm64 "$test_root/program.c" -o "$nested_app/Contents/MacOS/Nested"
write_plist "$fixture_app/Contents/Info.plist" Telemost com.telemost.desktop "$version" "$build"
write_plist "$nested_app/Contents/Info.plist" Nested com.telemost.desktop.synthetic "$version" "$build"

mkdir -p "$test_root/output"

"$signer" --help >/dev/null
expect_failure "Usage:" "$signer"
expect_failure "Unknown option" "$signer" --not-an-option

touch "$test_root/output/telemost-$version-aarch64.dmg"
expect_failure "refusing to overwrite telemost-$version-aarch64.dmg" \
    "$signer" "$fixture_app" "$test_root/output"
rm "$test_root/output/telemost-$version-aarch64.dmg"
touch "$test_root/output/telemost-$version-aarch64.dmg.sha256"
expect_failure "refusing to overwrite telemost-$version-aarch64.dmg" \
    "$signer" "$fixture_app" "$test_root/output"
rm "$test_root/output/telemost-$version-aarch64.dmg.sha256"

audit_fixture="$test_root/audit/Telemost.app"
mkdir -p "$(dirname "$audit_fixture")"
/usr/bin/ditto "$fixture_app" "$audit_fixture"
printf '%s\n' 'telemost.example' >"$audit_fixture/Contents/Resources/blocked.txt"
expect_failure "macOS release audit failed" \
    "$signer" "$audit_fixture" "$test_root/output"

identity=${TELEMOST_SIGNING_IDENTITY_FOR_TESTS:-Telemost Signing}
keychain=$(/usr/bin/security default-keychain -d user 2>/dev/null)
keychain=${keychain#"${keychain%%[![:space:]]*}"}
keychain=${keychain%"${keychain##*[![:space:]]}"}
keychain=${keychain#\"}
keychain=${keychain%\"}

if ! /usr/bin/security find-identity -v -p codesigning "$keychain" 2>/dev/null |
    /usr/bin/awk -v expected="$identity" '
        index($0, "\"" expected "\"") { found = 1 }
        END { exit(found ? 0 : 1) }
    '; then
    echo "CLI, naming, overwrite guard, and audit integration checks passed"
    echo "SKIP: cryptographic signing test; identity unavailable: $identity"
    exit 0
fi

crypto_output="$test_root/crypto-output"
"$signer" "$fixture_app" "$crypto_output" >/dev/null
final_dmg="$crypto_output/telemost-$version-aarch64.dmg"
final_sha="$final_dmg.sha256"
[[ -f "$final_dmg" ]] || fail "expected DMG was not created"
[[ -f "$final_sha" ]] || fail "expected checksum was not created"
(cd "$crypto_output" && /usr/bin/shasum -a 256 -c "${final_sha##*/}") >/dev/null ||
    fail "checksum verification failed"
/usr/bin/codesign --verify --strict "$final_dmg" || fail "DMG signature verification failed"

mount_dir="$test_root/verify-mount"
mkdir -p "$mount_dir"
/usr/bin/hdiutil attach "$final_dmg" -readonly -nobrowse -mountpoint "$mount_dir" -quiet ||
    fail "could not attach result DMG"
mounted_image="$mount_dir"
[[ -L "$mount_dir/Applications" ]] || fail "Applications link is missing"
/usr/bin/codesign --verify --deep --strict "$mount_dir/Telemost.app" ||
    fail "app signature verification failed"
/usr/bin/codesign --verify --strict "$mount_dir/Telemost.app/Contents/Helpers/Nested.app" ||
    fail "nested app signature verification failed"

echo "CLI, naming, overwrite guard, and audit integration checks passed"
echo "Cryptographic signing, nested code, DMG, and SHA-256 checks passed"
