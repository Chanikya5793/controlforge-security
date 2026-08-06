#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output_dir="$project_root/dist/macos"
task_temp_dir=$(/usr/bin/mktemp -d -t controlforge-pkg)
trap '/bin/rm -rf "$task_temp_dir"' EXIT HUP INT TERM

version=$(
  PYTHONPATH="$project_root/src" /usr/bin/python3 -c \
    'from controlforge import __version__; print(__version__)'
)
runtime="$output_dir/pyinstaller/controlforge-runtime"
binary="$output_dir/controlforge"
package_root="$task_temp_dir/root"
component_package="$task_temp_dir/controlforge-component.pkg"
unsigned_package="$output_dir/ControlForge-${version}-unsigned.pkg"
final_package="$output_dir/ControlForge-${version}.pkg"

/bin/mkdir -p "$output_dir" "$package_root/Library/ControlForge/bin" \
  "$package_root/Library/Application Support/ControlForge" \
  "$package_root/Library/LaunchDaemons"

cd "$project_root"
python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name controlforge-runtime \
  --distpath "$output_dir/pyinstaller" \
  --workpath "$task_temp_dir/pyinstaller-work" \
  --specpath "$task_temp_dir" \
  --collect-data controlforge \
  deployment/macos/entrypoint.py

/usr/bin/xcrun swiftc -O -framework Security \
  -o "$binary" "$script_dir/collector-wrapper.swift"

if [ -n "${DEVELOPER_ID_APPLICATION:-}" ]; then
  /usr/bin/codesign --force --options runtime --timestamp \
    --sign "$DEVELOPER_ID_APPLICATION" "$runtime"
  /usr/bin/codesign --verify --strict --verbose=2 "$runtime"
  /usr/bin/codesign --force --options runtime --timestamp \
    --identifier controlforge --sign "$DEVELOPER_ID_APPLICATION" "$binary"
  /usr/bin/codesign --verify --strict --verbose=2 "$binary"
else
  /usr/bin/codesign --force --identifier controlforge --sign - "$binary"
fi

/usr/bin/install -m 755 "$binary" "$package_root/Library/ControlForge/bin/controlforge"
/usr/bin/install -m 755 "$runtime" \
  "$package_root/Library/ControlForge/bin/controlforge-runtime"
/usr/bin/install -m 600 "$project_root/config/collector.yml" \
  "$package_root/Library/Application Support/ControlForge/collector.yml"
/usr/bin/install -m 644 "$project_root/config/agents-production.yml" \
  "$package_root/Library/Application Support/ControlForge/agents.yml"
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

/usr/sbin/pkgutil --check-signature "$final_package" || true

if [ -n "${NOTARY_PROFILE:-}" ]; then
  if [ -z "${DEVELOPER_ID_APPLICATION:-}" ] || [ -z "${DEVELOPER_ID_INSTALLER:-}" ]; then
    echo "NOTARY_PROFILE requires both Developer ID signing identities." >&2
    exit 1
  fi
  /usr/bin/xcrun notarytool submit "$final_package" \
    --keychain-profile "$NOTARY_PROFILE" --wait
  /usr/bin/xcrun stapler staple "$final_package"
  /usr/sbin/spctl --assess --type install --verbose=2 "$final_package"
fi

echo "$final_package"
