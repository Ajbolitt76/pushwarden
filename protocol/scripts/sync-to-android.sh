#!/bin/sh
# Copies the wordlist and test vectors into the Android fork. Re-run after changing them.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
app="$here/../upstream/android/app/src"
mkdir -p "$app/main/assets/l2" "$app/test/resources/l2"
cp "$here/wordlist/eff_large_wordlist.txt" "$app/main/assets/l2/"
cp "$here/vectors/v1.json" "$app/test/resources/l2/"
echo "synced to $app"
