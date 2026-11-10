#!/bin/sh
# Copies the reference protocol into the browser extension fork. The fork's webpack/tsc setup
# doesn't accept ".ts" import specifiers, so they are stripped. Re-run after changing protocol/src.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dest="$here/../upstream/clients/apps/browser/src/autofill/l2/protocol"
mkdir -p "$dest"
for f in "$here"/src/*.ts; do
  {
    echo "// Copied from protocol/src by protocol/scripts/sync-to-clients.sh. Do not edit here."
    echo "/* eslint-disable */"
    sed -E 's/(from "\.\/[a-z0-9-]+)\.ts"/\1"/' "$f"
  } > "$dest/$(basename "$f")"
done
(cd "$here/../upstream/clients" && npx prettier --log-level warn --write "$dest")
echo "synced to $dest"
