#!/bin/sh
set -eu

service="com.controlforge.collector.v2"
collector="/Library/ControlForge/bin/controlforge"
keychain="/Library/Keychains/System.keychain"
mode="${1:-cloud}"

case "$mode" in
  cloud)
    accounts="credential-id credential-secret access-client-id access-client-secret"
    ;;
  standalone)
    accounts="credential-id credential-secret"
    ;;
  *)
    echo "Usage: $0 [cloud|standalone]" >&2
    exit 64
    ;;
esac

if [ ! -x "$collector" ]; then
  echo "Install the ControlForge package before provisioning credentials." >&2
  exit 1
fi

for account in $accounts; do
  echo "Enter the secret value for $account when prompted. Input will be hidden."
  /usr/bin/sudo /usr/bin/security add-generic-password \
    -U -s "$service" -a "$account" -T "$collector" "$keychain" -w
done

echo "Credentials stored in the System keychain for the signed collector binary."
echo "Enable only after Santa is healthy:"
echo "  sudo launchctl enable system/com.controlforge.agent"
echo "  sudo launchctl bootstrap system /Library/LaunchDaemons/com.controlforge.agent.plist"
