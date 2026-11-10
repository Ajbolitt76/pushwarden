#!/bin/sh
# Copies the test vectors into the iOS fork's PushWardenL2 package. Re-run after changing them.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tests="$here/../upstream/ios/PushWardenL2/Tests/PushWardenL2Tests"
cp "$here/vectors/v1.json" "$tests/"
echo "synced to $tests"
