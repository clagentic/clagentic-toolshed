#!/bin/sh
# Install the daily update timer as a system unit that runs as the invoking user.
# Usage: sudo install-timer.sh [DATA_DIR] [CONFIG_FILE]
# The unit runs as $SUDO_USER (or the current user when not run through sudo). Defaults follow
# that user's home, or CLAGENTIC_TOOLSHED_HOME / CLAGENTIC_TOOLSHED_CONFIG when set.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
user=${SUDO_USER:-$(id -un)}
user_home=$(getent passwd "$user" | cut -d: -f6)
if [ -z "$user_home" ]; then
  echo "install-timer.sh: cannot find the home directory of user '$user'" >&2
  exit 1
fi
home=${1:-${CLAGENTIC_TOOLSHED_HOME:-$user_home/.local/share/clagentic/toolshed}}
config=${2:-${CLAGENTIC_TOOLSHED_CONFIG:-$user_home/.config/clagentic/toolshed/config.toml}}
for u in clagentic-toolshed-update.service clagentic-toolshed-update.timer; do
  sed -e "s|@REPO@|$repo|g" -e "s|@HOME@|$home|g" -e "s|@CONFIG@|$config|g" -e "s|@USER@|$user|g" \
    "$repo/deploy/$u" > "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now clagentic-toolshed-update.timer
systemctl list-timers clagentic-toolshed-update.timer --no-pager
