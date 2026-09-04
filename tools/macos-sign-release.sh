#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

usage() {
    cat <<'EOF'
Usage:
  macos-sign-release.sh [--force] [--keychain <path>] <Telemost.app|input.dmg> <output-directory>
  macos-sign-release.sh --create-identity [--keychain <path>] [<Telemost.app|input.dmg> <output-directory>]

Options:
  --create-identity  Create "Telemost Signing" in the selected user Keychain.
  --force            Replace an existing DMG and checksum in the output directory.
  --keychain PATH    Use this user Keychain instead of the default user Keychain.
  -h, --help         Show this help.
EOF
}

fail() {
    echo "macOS release signing failed: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

trim_keychain_path() {
    local value=$1
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    value=${value#\"}
    value=${value%\"}
    printf '%s\n' "$value"
}

identity_available() {
    /usr/bin/security find-identity -v -p codesigning "$keychain" 2>/dev/null |
        /usr/bin/awk -v expected="$identity" '
            index($0, "\"" expected "\"") { found = 1 }
            END { exit(found ? 0 : 1) }
        '
}

create_identity() {
    require_command openssl

    if identity_available; then
        echo "Identity already exists in $keychain: $identity"
        return
    fi

    local identity_dir="$work_dir/identity"
    local package_password
    mkdir -p "$identity_dir"
    package_password=$(/usr/bin/uuidgen)

    cat >"$identity_dir/certificate.cnf" <<EOF
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no

[subject]
CN = $identity
O = Telemost

[extensions]
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

    echo "Creating identity in $keychain: $identity"
    /usr/bin/openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -config "$identity_dir/certificate.cnf" \
        -keyout "$identity_dir/private-key.pem" \
        -out "$identity_dir/certificate.pem" >/dev/null 2>&1 ||
        fail "certificate generation failed"

    /usr/bin/openssl pkcs12 -export \
        -inkey "$identity_dir/private-key.pem" \
        -in "$identity_dir/certificate.pem" \
        -out "$identity_dir/identity.p12" \
        -name "$identity" \
        -passout "pass:$package_password" \
        -certpbe PBE-SHA1-3DES \
        -keypbe PBE-SHA1-3DES \
        -macalg sha1 >/dev/null 2>&1 ||
        fail "identity packaging failed"

    echo "Importing the non-exportable private key"
    /usr/bin/security import "$identity_dir/identity.p12" \
        -k "$keychain" \
        -P "$package_password" \
        -x \
        -T /usr/bin/codesign >/dev/null ||
        fail "identity import failed; make sure the selected Keychain is unlocked"

    echo "Adding user code-signing trust for: $identity"
    /usr/bin/security add-trusted-cert \
        -r trustRoot \
        -p codeSign \
        -k "$keychain" \
        "$identity_dir/certificate.pem" >/dev/null ||
        fail "the identity was imported, but code-signing trust could not be added"

    identity_available ||
        fail "the imported identity is not available for code signing"
    echo "Identity ready: $identity"
}

detach_image() {
    if [[ -n "$mounted_image" ]]; then
        if ! /usr/bin/hdiutil detach "$mounted_image" -quiet >/dev/null 2>&1; then
            if ! /usr/bin/hdiutil detach "$mounted_image" -force -quiet >/dev/null 2>&1; then
                return 1
            fi
        fi
        mounted_image=""
    fi
}

cleanup() {
    local cleanup_status=$?
    local can_remove_work=true
    if ! detach_image; then
        echo "macOS release signing cleanup failed: could not detach $mounted_image" >&2
        can_remove_work=false
        cleanup_status=1
    fi
    if [[ -n "$output_temp_dmg" && -f "$output_temp_dmg" ]]; then
        rm -f -- "$output_temp_dmg"
    fi
    if [[ -n "$output_temp_sha" && -f "$output_temp_sha" ]]; then
        rm -f -- "$output_temp_sha"
    fi
    if [[ "$can_remove_work" == true && -n "$work_dir" && -d "$work_dir" ]]; then
        rm -rf -- "$work_dir"
    fi
    return "$cleanup_status"
}

copy_input_app() {
    local input=$1
    local copied_app="$work_dir/Telemost.app"

    if [[ -d "$input" && "$input" == *.app ]]; then
        /usr/bin/ditto "$input" "$copied_app" || fail "could not copy app bundle"
    elif [[ -f "$input" && "$input" == *.dmg ]]; then
        local mount_dir="$work_dir/mount"
        mkdir -p "$mount_dir"
        /usr/bin/hdiutil attach "$input" \
            -readonly \
            -nobrowse \
            -noautoopen \
            -mountpoint "$mount_dir" \
            -quiet || fail "could not attach input DMG"
        mounted_image="$mount_dir"
        [[ -d "$mount_dir/Telemost.app" ]] ||
            fail "input DMG does not contain Telemost.app at its root"
        /usr/bin/ditto "$mount_dir/Telemost.app" "$copied_app" ||
            fail "could not copy Telemost.app from input DMG"
        detach_image || fail "could not detach input DMG"
    else
        fail "input must be a Telemost.app bundle or DMG"
    fi

    app_path=$copied_app
}

plist_value() {
    /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null
}

artifact_arch() {
    local app=$1
    local executable_name
    local executable_path
    local archs

    executable_name=$(plist_value "$app" CFBundleExecutable) ||
        fail "CFBundleExecutable is missing"
    executable_path="$app/Contents/MacOS/$executable_name"
    [[ -f "$executable_path" ]] || fail "main executable is missing: $executable_name"
    archs=$(/usr/bin/lipo -archs "$executable_path" 2>/dev/null) ||
        fail "main executable is not a Mach-O file"

    case "$archs" in
        arm64) printf '%s\n' aarch64 ;;
        x86_64) printf '%s\n' x86_64 ;;
        "arm64 x86_64"|"x86_64 arm64") printf '%s\n' universal ;;
        *) fail "unsupported executable architectures: $archs" ;;
    esac
}

extract_entitlements() {
    local target=$1
    local destination=$2

    if /usr/bin/codesign -d --entitlements - --xml "$target" >"$destination" 2>/dev/null &&
        [[ -s "$destination" ]] &&
        /usr/bin/plutil -lint "$destination" >/dev/null 2>&1; then
        return 0
    fi

    rm -f -- "$destination"
    return 1
}

sign_code() {
    local target=$1
    local entitlement_file="$work_dir/entitlements/$entitlement_index.plist"
    local -a sign_args
    entitlement_index=$((entitlement_index + 1))
    sign_args=(
        --force
        --sign "$identity"
        --keychain "$keychain"
        --options runtime
        --timestamp=none
    )

    if extract_entitlements "$target" "$entitlement_file"; then
        sign_args+=(--entitlements "$entitlement_file")
    fi

    /usr/bin/codesign "${sign_args[@]}" "$target" ||
        fail "could not sign ${target#"$app_path/"}"
}

sign_nested_code() {
    local app=$1
    local candidate
    local bundle
    local depth
    local order_file="$work_dir/code-bundles.txt"

    mkdir -p "$work_dir/entitlements"

    while IFS= read -r -d '' candidate; do
        if /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O'; then
            sign_code "$candidate"
        fi
    done < <(/usr/bin/find "$app" -type f -print0)

    : >"$order_file"
    while IFS= read -r -d '' bundle; do
        depth=${bundle//[^\/]/}
        printf '%08d\t%s\n' "${#depth}" "$bundle" >>"$order_file"
    done < <(/usr/bin/find "$app" -mindepth 1 -type d \( \
        -name '*.app' -o \
        -name '*.appex' -o \
        -name '*.bundle' -o \
        -name '*.framework' -o \
        -name '*.plugin' -o \
        -name '*.xpc' \
    \) -print0)

    while IFS=$'\t' read -r depth bundle; do
        [[ -n "$bundle" ]] || continue
        sign_code "$bundle"
    done < <(/usr/bin/sort -r "$order_file")
}

verify_code() {
    local app=$1
    local candidate
    local bundle

    while IFS= read -r -d '' candidate; do
        if /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O'; then
            /usr/bin/codesign --verify --strict "$candidate" ||
                fail "signature verification failed for ${candidate#"$app/"}"
        fi
    done < <(/usr/bin/find "$app" -type f -print0)

    while IFS= read -r -d '' bundle; do
        /usr/bin/codesign --verify --strict "$bundle" ||
            fail "signature verification failed for ${bundle#"$app/"}"
    done < <(/usr/bin/find "$app" -mindepth 1 -type d \( \
        -name '*.app' -o \
        -name '*.appex' -o \
        -name '*.bundle' -o \
        -name '*.framework' -o \
        -name '*.plugin' -o \
        -name '*.xpc' \
    \) -print0)

    /usr/bin/codesign --verify --deep --strict "$app" ||
        fail "app bundle signature verification failed"
}

create_dmg() {
    local app=$1
    local destination=$2
    local staging_dir="$work_dir/dmg-root"

    mkdir -p "$staging_dir"
    /usr/bin/ditto "$app" "$staging_dir/Telemost.app" ||
        fail "could not stage Telemost.app for the DMG"
    /bin/ln -s /Applications "$staging_dir/Applications"

    /usr/bin/hdiutil create \
        -volname Telemost \
        -srcfolder "$staging_dir" \
        -format UDZO \
        -noanyowners \
        -nospotlight \
        -quiet \
        "$destination" || fail "DMG creation failed"
}

sign_dmg() {
    local dmg=$1
    local error_file="$work_dir/dmg-signing-error.txt"

    if /usr/bin/codesign --force \
        --sign "$identity" \
        --keychain "$keychain" \
        --timestamp=none \
        "$dmg" 2>"$error_file"; then
        /usr/bin/codesign --verify --strict "$dmg" ||
            fail "DMG signature verification failed"
        return
    fi

    if /usr/bin/grep -E -q 'bundle format unrecognized|not a code object|unsupported format' "$error_file"; then
        echo "DMG code signing is unavailable on this macOS version"
        return
    fi

    /bin/cat "$error_file" >&2
    fail "DMG signing failed"
}

create_identity_mode=false
force=false
keychain=""
input_path=""
output_dir=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --create-identity)
            create_identity_mode=true
            shift
            ;;
        --force)
            force=true
            shift
            ;;
        --keychain)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            keychain=$2
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

if [[ $# -eq 2 ]]; then
    input_path=$1
    output_dir=$2
elif [[ $# -ne 0 || "$create_identity_mode" != true ]]; then
    usage >&2
    exit 2
fi

require_command security
require_command codesign

identity=${TELEMOST_SIGNING_IDENTITY_FOR_TESTS:-Telemost Signing}
[[ -n "$identity" ]] || fail "signing identity must not be empty"

if [[ -z "$keychain" ]]; then
    keychain=$(/usr/bin/security default-keychain -d user 2>/dev/null) ||
        fail "could not determine the default user Keychain"
    keychain=$(trim_keychain_path "$keychain")
fi
[[ -n "$keychain" ]] || fail "the selected user Keychain path is empty"
[[ -f "$keychain" ]] ||
    fail "the selected user Keychain is unavailable: $keychain"

umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/telemost-sign.XXXXXX") ||
    fail "could not create private temporary directory"
mounted_image=""
output_temp_dmg=""
output_temp_sha=""
entitlement_index=0
app_path=""
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [[ "$create_identity_mode" == true ]]; then
    create_identity
    if [[ -z "$input_path" ]]; then
        exit 0
    fi
fi

require_command hdiutil

[[ -e "$input_path" ]] || fail "input does not exist: $input_path"
mkdir -p "$output_dir" || fail "could not create output directory: $output_dir"
[[ -d "$output_dir" ]] || fail "output path is not a directory: $output_dir"

copy_input_app "$input_path"
info_plist="$app_path/Contents/Info.plist"
[[ -f "$info_plist" ]] || fail "copied app is missing Contents/Info.plist"

version=$(plist_value "$app_path" CFBundleShortVersionString) ||
    fail "CFBundleShortVersionString is missing"
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] ||
    fail "unsafe CFBundleShortVersionString: $version"
arch=$(artifact_arch "$app_path")
output_name="telemost-$version-$arch.dmg"
final_dmg="$output_dir/$output_name"
final_sha="$final_dmg.sha256"

if [[ "$force" != true && ( -e "$final_dmg" || -e "$final_sha" ) ]]; then
    fail "refusing to overwrite $output_name or its checksum; pass --force to replace them"
fi

"$script_dir/macos-audit-release.sh" "$app_path" ||
    fail "release audit rejected the input"

identity_available ||
    fail "identity '$identity' is unavailable in $keychain; run with --create-identity first"

echo "Signing nested code"
sign_nested_code "$app_path"
echo "Signing Telemost.app"
/usr/bin/codesign --force \
    --sign "$identity" \
    --keychain "$keychain" \
    --options runtime \
    --timestamp=none \
    --entitlements "$repo_root/flutter/macos/Runner/Release.entitlements" \
    "$app_path" || fail "could not sign Telemost.app"

verify_code "$app_path"
if ! /usr/bin/codesign -d --verbose=4 "$app_path" 2>&1 |
    /usr/bin/grep -q 'flags=.*runtime'; then
    fail "hardened runtime is missing from Telemost.app"
fi

echo "Designated requirement:"
/usr/bin/codesign -d -r- "$app_path" 2>&1 ||
    fail "could not read the designated requirement"

work_dmg="$work_dir/$output_name"
create_dmg "$app_path" "$work_dmg"
sign_dmg "$work_dmg"

output_temp_dmg=$(mktemp "$output_dir/.telemost-dmg.XXXXXX") ||
    fail "could not prepare output DMG"
/usr/bin/ditto "$work_dmg" "$output_temp_dmg" || fail "could not stage output DMG"
output_temp_sha=$(mktemp "$output_dir/.telemost-sha256.XXXXXX") ||
    fail "could not prepare checksum"
digest=$(/usr/bin/shasum -a 256 "$output_temp_dmg" | /usr/bin/awk '{ print $1 }') ||
    fail "could not calculate SHA-256"
printf '%s  %s\n' "$digest" "$output_name" >"$output_temp_sha"

if [[ "$force" == true ]]; then
    /bin/mv -f "$output_temp_dmg" "$final_dmg" || fail "could not publish output DMG"
    output_temp_dmg=""
    /bin/mv -f "$output_temp_sha" "$final_sha" || fail "could not publish checksum"
    output_temp_sha=""
else
    /bin/mv -n "$output_temp_dmg" "$final_dmg" || fail "could not publish output DMG"
    [[ ! -e "$output_temp_dmg" ]] ||
        fail "refusing to overwrite an output DMG created during signing"
    output_temp_dmg=""
    /bin/mv -n "$output_temp_sha" "$final_sha" || fail "could not publish checksum"
    [[ ! -e "$output_temp_sha" ]] ||
        fail "refusing to overwrite a checksum created during signing"
    output_temp_sha=""
fi

echo "DMG: $final_dmg"
echo "SHA-256: $digest"
echo "Signed"
