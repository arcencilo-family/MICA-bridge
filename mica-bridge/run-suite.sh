#!/usr/bin/env bash
# The shipped suite: every bridge test except the reference-deployment-only ones (see reference-only.ts), then tsc.
#   bash mica-bridge/run-suite.sh               shipped suite + tsc
#   bash mica-bridge/run-suite.sh --reference   ONLY the reference-deployment-only checks (expected red at the example)
# Needs a ts-node and a typescript: set TSNODE and TSC (defaults look in ./node_modules).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSNODE="${TSNODE:-$HERE/../node_modules/ts-node/dist/bin.js}"
TSC="${TSC:-$HERE/../node_modules/typescript/bin/tsc}"
cd "$HERE"
rc=0
if [[ "${1:-}" == "--reference" ]]; then
  export MICA_BRIDGE_REFERENCE_SET=1
  for f in declarations.test.ts mica-service.test.ts tools/relay-sunset.test.ts; do
    echo "== $f (reference only)"; node "$TSNODE" -P tsconfig.json "$f" || rc=1
  done
  echo "== relay-lib.test.sh (all checks run; the reference one is the point)"; bash relay-lib.test.sh || rc=1
  exit $rc
fi
for f in *.test.ts tools/*.test.ts ../tools/doctor-attest/*.test.ts; do
  echo "== $f"; node "$TSNODE" -P tsconfig.json "$f" || rc=1
done
echo "== relay-lib.test.sh"; bash relay-lib.test.sh || rc=1
echo "== mica-alerter.test.py"; python3 -B mica-alerter.test.py || rc=1
echo "== tsc"; node "$TSC" -p tsconfig.json --noEmit || rc=1
exit $rc
