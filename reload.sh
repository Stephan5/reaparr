#!/bin/sh
# Generate the launchd plist from reaparr.plist.template + reaparr.conf,
# install it to ~/Library/LaunchAgents and (re)load the job.
set -eu

label="io.github.stephan5.reaparr"
dir="$(cd "$(dirname "$0")" && pwd)"
conf="$dir/reaparr.conf"
dest="$HOME/Library/LaunchAgents/$label.plist"
domain="gui/$(id -u)"

[ -f "$conf" ] || { echo "Missing $conf (copy reaparr.conf.example)" >&2; exit 1; }

# One <string> per non-blank, non-comment line of the conf, XML-escaped.
args="$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$conf" |
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's|^|        <string>|' -e 's|$|</string>|')"

mkdir -p "$HOME/Library/LaunchAgents"
# (ENVIRON rather than -v: macOS awk rejects newlines in -v values.)
LABEL="$label" DIR="$dir" ARGS="$args" awk '
    /__ARGS__/ { print ENVIRON["ARGS"]; next }
    { gsub(/__LABEL__/, ENVIRON["LABEL"]); gsub(/__HOME__/, ENVIRON["HOME"]); gsub(/__DIR__/, ENVIRON["DIR"]); print }
' "$dir/reaparr.plist.template" > "$dest"
plutil -lint "$dest" >/dev/null

# Not loaded yet is fine.
launchctl bootout "$domain/$label" 2>/dev/null || true
launchctl bootstrap "$domain" "$dest"

echo "Reloaded $label"
launchctl print "$domain/$label" | grep -E "state|pid" || true
echo "Log: tail -f ~/Library/Logs/$label.log"
