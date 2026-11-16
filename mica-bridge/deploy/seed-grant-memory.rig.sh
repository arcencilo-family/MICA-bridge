#!/usr/bin/env bash
# S216-2 · cond. 10 · THE SEED SCRIPT'S DRY RIG, at uid 1000, no sudo: every refusal the dry half can reach, and the
# one dry pass. The --go half's privileged steps are not run here (the arbiter's hand); its tty refusal and its refusal of
# any SEED_RIG_* override are. A fake /status answers on a fixture unix socket.
#   bash mica-bridge/deploy/seed-grant-memory.rig.sh <release tree>        (prints one PASS/FAIL line per case)
set -uo pipefail
REL=$(cd "${1:?usage: seed-grant-memory.rig.sh <release tree>}" && pwd)
SCRIPT="$REL/mica-bridge/deploy/seed-grant-memory.sh"
TOOL="$REL/mica-bridge/tools/grant-memory-seed.ts"
NODE=${RIG_NODE:-/usr/bin/node}
TSN=${RIG_TS_NODE:-/opt/mica-machine/node_modules/ts-node/dist/bin.js}
W=$(mktemp -d "${TMPDIR:-/tmp}/seed-rig-XXXXXX")
STATE="$W/state"; mkdir -p "$STATE"; RUNS="$W/runs"
# a unix socket path must fit sun_path (108 bytes): the fake /status lives in a short dir of its own
SOCKDIR=$(mktemp -d /tmp/seedrig-XXXXXX); SOCK="$SOCKDIR/s.sock"
pass=0; fail=0

DECL_HASH=$("$NODE" "$TSN" -P "$REL/mica-bridge/tsconfig.json" "$TOOL" hash --declaration "$REL/mica-bridge/declarations.config.json" | sed -n 's/^DECLARATION_HASH=//p')
CAND="$W/candidate.jsonl"
"$NODE" "$TSN" -P "$REL/mica-bridge/tsconfig.json" "$TOOL" build --declaration "$REL/mica-bridge/declarations.config.json" --out "$CAND" > "$W/build.txt"
CSHA=$(sha256sum "$CAND" | cut -d' ' -f1)

serve() { # serve <declarationHash> <lastRejected json>
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null && wait "$SRV" 2>/dev/null
  rm -f "$SOCK"
  "$NODE" -e '
    const http=require("http"); const [sock,h,rej]=process.argv.slice(1);
    http.createServer((q,r)=>{r.setHeader("content-type","application/json");r.end(JSON.stringify({preflight:"SERVING",declarationHash:h,lastRejectedDeclaration:JSON.parse(rej)}));}).listen(sock);
  ' "$SOCK" "$1" "$2" &
  SRV=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCK" ] && break; sleep 0.2; done
}
run() { # run <name> <expect-regex> <env...> -- <args...>
  local name=$1 want=$2; shift 2
  local envs=(); while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  local out
  out=$(env SEED_RIG_STATE_DIR="$STATE" SEED_RIG_SOCK="$SOCK" "${envs[@]}" bash "$SCRIPT" --run-dir "$RUNS" "$@" </dev/null 2>&1)
  local rc=$?
  if grep -qE "$want" <<<"$out"; then echo "PASS  $name (rc=$rc)"; pass=$((pass+1)); else echo "FAIL  $name (rc=$rc)"; echo "$out" | tail -5 | sed 's/^/      /'; fail=$((fail+1)); fi
}
OK=(--candidate "$CAND" --expect-seed "$CSHA" --expect-declaration "$DECL_HASH" --release "$REL")

serve "$DECL_HASH" null
run "the dry pass: every check, nothing laid" "^DRY: every check passed; nothing laid" -- "${OK[@]}"
[ ! -e "$STATE/grant-memory" ] && echo "PASS  the dry pass laid nothing" && pass=$((pass+1)) || { echo "FAIL  the dry pass laid a file"; fail=$((fail+1)); }
run "--go with a rig override is refused" "REFUSE: a SEED_RIG_\* override is set" -- "${OK[@]}" --go
run "--go with no tty is refused before anything privileged" "REFUSE: no tty" SEED_RIG_STATE_DIR= SEED_RIG_SOCK= -- "${OK[@]}" --go
run "a missing required flag" "REFUSED: --candidate, --expect-seed, --expect-declaration and --release are all required" -- --candidate "$CAND"
run "a flag whose value is another flag" "needs a value, and the next argument is another flag" -- --candidate --expect-seed "$CSHA"
run "--expect-seed not 64 hex" "REFUSED: --expect-seed is not 64 lower-case hex" -- --candidate "$CAND" --expect-seed ABC --expect-declaration "$DECL_HASH" --release "$REL"
run "the candidate is not the one posted" "REFUSED: the candidate is not the one posted" -- --candidate "$CAND" --expect-seed "$(printf 'f%.0s' {1..64})" --expect-declaration "$DECL_HASH" --release "$REL"
touch "$STATE/grant-memory"; run "a memory exists" "REFUSED: .*grant-memory exists: a memory is never overwritten" -- "${OK[@]}"; rm -f "$STATE/grant-memory"
touch "$STATE/grant-memory.lock"; run "a lock exists" "REFUSED: .*grant-memory.lock exists" -- "${OK[@]}"; rm -f "$STATE/grant-memory.lock"
touch "$STATE/.grant-memory.seed-20990101T000000Z"; run "a leftover dot-temp" "REFUSED: a leftover dot-temp exists" -- "${OK[@]}"; rm -f "$STATE"/.grant-memory.seed-*
BAD="$W/bad.jsonl"; sed 's/"SEEDED"/"BEGUN"/' "$CAND" > "$BAD"
run "the release's verifier rejects a tampered candidate" "REFUSED: the release's chain verifier rejects the candidate" -- --candidate "$BAD" --expect-seed "$(sha256sum "$BAD" | cut -d' ' -f1)" --expect-declaration "$DECL_HASH" --release "$REL"
OTHER=$(printf 'a%.0s' {1..64})
run "the declaration file is not --expect-declaration" "REFUSED: the declaration file's canonical hash is not --expect-declaration" -- --candidate "$CAND" --expect-seed "$CSHA" --expect-declaration "$OTHER" --release "$REL"
serve "$OTHER" null
run "the SERVED declaration is not --expect-declaration" "REFUSED: the SERVED declaration is not --expect-declaration" -- "${OK[@]}"
serve "$DECL_HASH" '{"hash":"unavailable","field":"harm","reason":"H11","ts":"2026-10-18T00:00:00.000Z"}'
run "a refused SIGHUP is on /status (lastRejectedDeclaration set)" "REFUSED: /status.lastRejectedDeclaration is set" -- "${OK[@]}"
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -f "$SOCK"; SRV=""
run "live /status cannot be read" "REFUSED: live /status could not be read" -- "${OK[@]}"
n=$(ls "$RUNS" | wc -l)
[ "$n" -ge 10 ] && echo "PASS  every run left its run-stamped record ($n in $RUNS)" && pass=$((pass+1)) || { echo "FAIL  run records: $n"; fail=$((fail+1)); }
rm -rf -- "$SOCKDIR"
echo "RIG: $pass passed, $fail failed (work dir $W)"
[ "$fail" = "0" ]
