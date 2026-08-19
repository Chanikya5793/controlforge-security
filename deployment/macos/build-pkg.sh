#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
python_bin=${CONTROLFORGE_PYTHON:-$project_root/.venv/bin/python}
if [ ! -x "$python_bin" ]; then
  echo "CONTROLFORGE_PYTHON must name an executable project Python." >&2
  exit 1
fi
if ! "$python_bin" -c 'import pydantic, PyInstaller' >/dev/null 2>&1; then
  echo "The release Python requires the project and macos-dist dependencies." >&2
  exit 1
fi
release_channel=${CONTROLFORGE_RELEASE_CHANNEL:-development}
case "$release_channel" in
  development|staging|production) ;;
  *) echo "Invalid CONTROLFORGE_RELEASE_CHANNEL." >&2; exit 1 ;;
esac
output_dir="$project_root/dist/macos"
if [ -n "${CONTROLFORGE_BUILD_LABEL:-}" ]; then
  case "$CONTROLFORGE_BUILD_LABEL" in
    .|..|*[!a-zA-Z0-9._-]*) echo "Invalid CONTROLFORGE_BUILD_LABEL." >&2; exit 1 ;;
  esac
  output_dir="$output_dir/$CONTROLFORGE_BUILD_LABEL"
fi
task_temp_dir=$(/usr/bin/mktemp -d -t controlforge-pkg)
trap '/bin/rm -rf "$task_temp_dir"' EXIT HUP INT TERM

version=$(
  PYTHONPATH="$project_root/src" "$python_bin" -c \
    'from controlforge import __version__; print(__version__)'
)
source_commit=$(/usr/bin/git -C "$project_root" rev-parse --verify HEAD)
source_dirty=true
if [ -z "$(/usr/bin/git -C "$project_root" status --porcelain --untracked-files=normal)" ]; then
  source_dirty=false
fi
source_tag=$(/usr/bin/git -C "$project_root" describe --tags --exact-match HEAD 2>/dev/null || true)
if [ "$release_channel" = staging ] && [ -z "${CONTROLFORGE_ACCOUNT_SERVER_HOST:-}" ]; then
  echo "Staging releases require CONTROLFORGE_ACCOUNT_SERVER_HOST." >&2
  exit 1
fi
if [ "$release_channel" = production ]; then
  if [ -z "${CONTROLFORGE_ACCOUNT_SERVER_HOST:-}" ]; then
    echo "Production releases require CONTROLFORGE_ACCOUNT_SERVER_HOST." >&2
    exit 1
  fi
  if [ -z "${CONTROLFORGE_PRODUCTION_ACCOUNT_SERVER_HOST:-}" ] || \
     [ "$CONTROLFORGE_PRODUCTION_ACCOUNT_SERVER_HOST" != \
       "$CONTROLFORGE_ACCOUNT_SERVER_HOST" ]; then
    echo "Production releases require an explicitly matched production account host." >&2
    exit 1
  fi
  if [ "$source_dirty" != false ]; then
    echo "Production releases require a clean source tree." >&2
    exit 1
  fi
  if [ "$source_tag" != "v$version" ]; then
    echo "Production releases require the exact v$version source tag." >&2
    exit 1
  fi
  if [ -z "${DEVELOPER_ID_APPLICATION:-}" ] || \
     [ -z "${DEVELOPER_ID_INSTALLER:-}" ] || \
     [ -z "${NOTARY_PROFILE:-}" ]; then
    echo "Production releases require Developer ID signing and notarization." >&2
    exit 1
  fi
fi
runtime="$output_dir/pyinstaller/controlforge-runtime"
binary="$output_dir/controlforge"
user_app_binary="$output_dir/ControlForgeUser"
package_root="$task_temp_dir/root"
user_app_output="$output_dir/ControlForge.app"
user_app="$package_root/Applications/ControlForge.app"
component_package="$task_temp_dir/controlforge-component.pkg"
unsigned_package="$output_dir/ControlForge-${version}-unsigned.pkg"
final_package="$output_dir/ControlForge-${version}.pkg"
release_manifest="$output_dir/ControlForge-${version}.release.json"

if [ -e "$final_package" ] || [ -e "$release_manifest" ]; then
  echo "Release output already exists; use a new build label or remove it deliberately." >&2
  exit 1
fi

/bin/mkdir -p "$output_dir" "$package_root/Library/ControlForge/bin" \
  "$package_root/Library/ControlForge/rules" \
  "$package_root/Library/ControlForge/status" \
  "$package_root/Library/ControlForge/installer" \
  "$package_root/Library/Application Support/ControlForge" \
  "$package_root/Library/LaunchDaemons" \
  "$package_root/Applications" \
  "$user_app_output/Contents/MacOS"

cd "$project_root"
set -- --output "$package_root/Library/ControlForge/installer/account-server.default.json"
if [ -n "${CONTROLFORGE_ACCOUNT_SERVER_HOST:-}" ]; then
  set -- "$@" --api-host "$CONTROLFORGE_ACCOUNT_SERVER_HOST" \
    --api-port "${CONTROLFORGE_ACCOUNT_SERVER_PORT:-443}"
elif [ -n "${CONTROLFORGE_ACCOUNT_SERVER_PORT:-}" ]; then
  echo "An account server port requires CONTROLFORGE_ACCOUNT_SERVER_HOST." >&2
  exit 1
fi
PYTHONPATH="$project_root/src" "$python_bin" -m controlforge.macos_installer "$@"

set -- build-identity \
  --output "$package_root/Library/ControlForge/installer/release-build.json" \
  --version "$version" \
  --channel "$release_channel" \
  --source-commit "$source_commit" \
  --source-dirty "$source_dirty"
if [ -n "$source_tag" ]; then
  set -- "$@" --source-tag "$source_tag"
fi
if [ -n "${CONTROLFORGE_ACCOUNT_SERVER_HOST:-}" ]; then
  set -- "$@" --api-host "$CONTROLFORGE_ACCOUNT_SERVER_HOST" \
    --api-port "${CONTROLFORGE_ACCOUNT_SERVER_PORT:-443}"
fi
PYTHONPATH="$project_root/src" "$python_bin" -m controlforge.release_manifest "$@"

"$python_bin" -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name controlforge-runtime \
  --distpath "$output_dir/pyinstaller" \
  --workpath "$task_temp_dir/pyinstaller-work" \
  --specpath "$task_temp_dir" \
  --collect-data controlforge \
  deployment/macos/entrypoint.py

/usr/bin/xcrun swiftc -O -target arm64-apple-macos13.0 -framework Security \
  -o "$binary" "$script_dir/collector-wrapper.swift"
/usr/bin/xcrun swiftc -O -parse-as-library -target arm64-apple-macos13.0 \
  -framework SwiftUI -framework AppKit \
  -o "$user_app_binary" "$script_dir/user-dashboard.swift" "$script_dir/account-onboarding.swift"

/bin/rm -rf "$user_app_output"
/bin/mkdir -p "$user_app_output/Contents/MacOS"
/usr/bin/install -m 755 "$user_app_binary" "$user_app_output/Contents/MacOS/ControlForge"
/usr/bin/install -m 644 "$script_dir/ControlForge-Info.plist" \
  "$user_app_output/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" \
  "$user_app_output/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" \
  "$user_app_output/Contents/Info.plist"

if [ -n "${DEVELOPER_ID_APPLICATION:-}" ]; then
  /usr/bin/codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APPLICATION" "$runtime"
  /usr/bin/codesign --verify --strict --verbose=2 "$runtime"
  /usr/bin/codesign --force --options runtime --timestamp \
    --identifier controlforge --sign "$DEVELOPER_ID_APPLICATION" "$binary"
  /usr/bin/codesign --verify --strict --verbose=2 "$binary"
  /usr/bin/codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APPLICATION" "$user_app_output"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$user_app_output"
else
  /usr/bin/codesign --force --identifier controlforge --sign - "$binary"
  /usr/bin/codesign --force --sign - "$user_app_output"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$user_app_output"
fi

DITTONORSRC=1 /usr/bin/ditto --norsrc --noextattr --noqtn --noacl \
  --nopersistRootless --noclone "$user_app_output" "$user_app"

/usr/bin/install -m 755 "$binary" "$package_root/Library/ControlForge/bin/controlforge"
/usr/bin/install -m 755 "$runtime" \
  "$package_root/Library/ControlForge/bin/controlforge-runtime"
/usr/bin/install -m 644 "$project_root/config/collector.yml" \
  "$package_root/Library/Application Support/ControlForge/collector.default.yml"
/usr/bin/install -m 644 "$project_root/config/agents-production.yml" \
  "$package_root/Library/Application Support/ControlForge/agents.yml"
for rule_path in "$project_root"/rules/*.yml; do
  /usr/bin/install -m 644 "$rule_path" \
    "$package_root/Library/ControlForge/rules/$(/usr/bin/basename "$rule_path")"
done
/usr/bin/install -m 644 "$script_dir/com.controlforge.agent.plist" \
  "$package_root/Library/LaunchDaemons/com.controlforge.agent.plist"

/usr/bin/pkgbuild \
  --root "$package_root" \
  --scripts "$script_dir/scripts" \
  --identifier com.controlforge.agent \
  --version "$version" \
  --install-location / \
  "$component_package"

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
  /usr/bin/productbuild --package "$component_package" \
    --sign "$DEVELOPER_ID_INSTALLER" "$final_package"
else
  /usr/bin/productbuild --package "$component_package" "$unsigned_package"
  final_package="$unsigned_package"
fi

developer_id_signed=false
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
  developer_id_signed=true
  /usr/sbin/pkgutil --check-signature "$final_package"
else
  /usr/sbin/pkgutil --check-signature "$final_package" || true
fi

apple_notarized=false
if [ -n "${NOTARY_PROFILE:-}" ]; then
  if [ -z "${DEVELOPER_ID_APPLICATION:-}" ] || [ -z "${DEVELOPER_ID_INSTALLER:-}" ]; then
    echo "NOTARY_PROFILE requires both Developer ID signing identities." >&2
    exit 1
  fi
  /usr/bin/xcrun notarytool submit "$final_package" \
    --keychain-profile "$NOTARY_PROFILE" --wait
  /usr/bin/xcrun stapler staple "$final_package"
  /usr/bin/xcrun stapler validate "$final_package"
  /usr/sbin/spctl --assess --type install --verbose=2 "$final_package"
  apple_notarized=true
fi

set -- release-manifest \
  --output "$release_manifest" \
  --package "$final_package" \
  --developer-id-signed "$developer_id_signed" \
  --apple-notarized "$apple_notarized" \
  --version "$version" \
  --channel "$release_channel" \
  --source-commit "$source_commit" \
  --source-dirty "$source_dirty"
if [ -n "$source_tag" ]; then
  set -- "$@" --source-tag "$source_tag"
fi
if [ -n "${CONTROLFORGE_ACCOUNT_SERVER_HOST:-}" ]; then
  set -- "$@" --api-host "$CONTROLFORGE_ACCOUNT_SERVER_HOST" \
    --api-port "${CONTROLFORGE_ACCOUNT_SERVER_PORT:-443}"
fi
PYTHONPATH="$project_root/src" "$python_bin" -m controlforge.release_manifest "$@"
PYTHONPATH="$project_root/src" "$python_bin" -m controlforge.release_manifest verify \
  --manifest "$release_manifest" --package "$final_package"

echo "$final_package"
echo "$release_manifest"
