# mica-bridge

The bridge service and everything it needs that is not the machine itself: its declaration loader, the service, its peer authentication, its deploy templates and its tests. The repository's top README says what the bridge is for, what state it is in and how to build and test it. The socket API is in [API.md](API.md), the declaration in [DECLARATION.md](DECLARATION.md).

The machine (readers, gates, glue) is imported from `/opt/mica-machine/src/...`, never copied. Where a rule of the machine matters here (`isUsableLine`, the `--sensor-config` key sets), it is reimplemented as the one narrow predicate needed and cited to its source.

## What is here

**The declaration**
- `declarations.schema.json`: the JSON Schema (draft 2020-12) of a declaration. `additionalProperties: false` at every level, and no default for any field: a missing value is a rejection, never a fallback.
- `declarations.ts`: the one loader and validator. It also holds the cross-field rules the schema cannot state.
- `declarations.example.json`: the shape of a declaration, with every path and uid invented. A deployer writes their own. The live declaration of the reference box is not shipped.
- `declarations.fixture.json`: a declaration used as test input.
- `example-draft.ts`: test support. It maps the example's invented route uids to the uids the behaviour tests were written against.
- `canonical-json.ts`: the one canonicalisation rule (sorted keys, NFC, UTF-8, no whitespace; `null` kept, `undefined` left out), used for the declaration hash and request hashes.
- `to-sensor-config.ts`, `to-guard-flags.ts`, `to-wire-options.ts`: turn a loaded declaration into what the machine's guard and readers take. The act's stakes class comes from the declaration; a caller cannot set it.

**The service**
- `mica-service.ts`: HTTP/1.1 over Unix sockets only, never TCP. It loads the declaration and serves the routes in API.md. `--check` loads the declaration and exits without binding a socket. On SIGHUP it reloads, and it keeps the last good declaration when a new one is rejected.
- `peer-auth.ts`: one socket per declared caller (see "Who is asking").
- `guard-adapter.ts`: the interface `POST /guard` evaluates through.
- `stage1-guard-adapter.ts`: the binding of that interface to the machine's `evaluateAndRecord`. It is the file that imports the machine's glue by absolute path.
- `core-door-status.ts`: the `door` section of `/status`, a census of the machine's core door, never a verdict about it.
- `interest-label.ts`, `interest-book.ts`: Gate 1's label for each act (which declared region its target lies in) and where that label is written.
- `target-fingerprint.ts`: the bridge's own normalisation and salted hash of a claimed target.
- `witness-pointer.ts`: the bridge's half of the witness's pointer contract. For each act it writes one pointer file into the witness's intake.
- `grant-memory.ts`: the bridge's lasting record of grants. It is written under a lock and fsynced.
- `vendored-mica-client.ts`: a read-only copy of a caller's client, for the bridge's own tests.
- `mica-alerter.py`: polls `GET /events` and `GET /status` over its own socket and posts alerts. Delivery is at least once: after a crash an alert can be sent twice, and each message carries the event's sequence number so a repeat can be told from a new event.

**Deploy templates** (`deploy/`; nothing here installs anything)
- `mica-bridge.service`, `mica-alerter.service`: systemd unit templates. Neither has an `[Install]` section.
- `mica-bridge.tmpfiles.conf`: the per-caller socket folders under `/run/mica-bridge`. It is rendered by `render-tmpfiles.ts` from a declaration's `routes[]`, and names each folder's owner by asking the host which account has that uid. **The committed file was rendered on the reference box and carries that box's account names; a deployer re-renders it on their own box.**
- `deployment-facts.fragment.json`: the expected owner, mode and ACL of the same folders, in the shape the machine's deployment-facts loader reads. The operator's account stands as `USER`; a deployer sets it. It is not merged into any deployment-facts file in this tree. The loader has no `file-group` family, so the group half of each folder's ownership is stated only in the ACL facts.
- `seed-grant-memory.sh` (and its dry rig `seed-grant-memory.rig.sh`): lays the first grant memory. It is an act for root.

**Tools** (`tools/`)
- `relay-sunset.ts`: sends Gate 4's ending order through the bridge as an ordinary caller.
- `grant-memory-seed.ts`: builds and checks the grant memory's seed.
- `witness-rehearsal.ts`: an end-to-end rehearsal of the witness's seeing half on scratch paths.

**Relay scripts** (need root; not run by the tests)
- `relay-bridge.sh`: lays a bridge release: custody check, `--check` as the service account, an atomic link swap, then SIGHUP and verify for a declaration-only change, or a restart for a code change.
- `relay-lib.sh`: its inactivity check and marker lock, pulled out so they can be tested without root (`relay-lib.test.sh`).

**Tests**: every `*.test.ts` here and under `tools/`, plus `relay-lib.test.sh` and `mica-alerter.test.py`. `run-suite.sh` runs them (see "Running the tests"). `reference-only.ts` lists the checks that hold only on the reference box.

## Who is asking: per-caller sockets

The service never asks the kernel for a caller's uid. It opens one socket for each declared caller, at `<socketDir>/peers/<uid>/guard.sock`. A connection's uid is the uid of the socket that accepted it.
- **Leaves:** each `peers/<uid>/` folder is owned by exactly that uid and group `mica-bridge`, mode exactly `0770`. The service checks this at start and refuses to start on any mismatch (`peer-auth.ts`).
- **Parents:** the two folders above (`/run/mica-bridge` and `peers/`) are `0711 root root`. Anyone can pass through, and no one but root can list who has a folder there. Identity is decided at the leaf, never at the parents.
- **Group membership:** callers are not put into group `mica-bridge`. That group also guards `/var/lib/mica-bridge`, where the decision journal, the event book and the subject log are kept.
- **Root:** root can connect to any of these sockets whatever the folder bits say. The loader refuses a `routes[]` row for uid 0.

## Zero subjects

A declaration may declare no subject (`subjects: []`). Then:
- every `/status` instrument row reads `NOTHING_DECLARED`, with no verdict and no footing;
- `/status.subjects` reads `{"state": "NOTHING_DECLARED", "declared": []}`, and `guardBound` is `false`;
- `POST /guard` is refused at four independent points: the route check, the handler's own check (503 `NOTHING_DECLARED`), the guard-flag resolution (`UNKNOWN_SUBJECT`) and the adapter;
- the loader also refuses a subject row with no route and an active pilot;
- a SIGHUP may not change membership, route uids or any route's grants: that takes a restart;
- the event book records `SUBJECTS_DECLARED` when membership differs from the last record of it.

What this means:
1. At zero there is no floor: not a CANNOT_ASSESS floor, but none at all.
2. The bridge refuses; the caller decides what to do with a refusal.
3. The subject chain, the decision journal and the floor trail keep a removed subject's history, and `/log` and `/explain` serve it as history.
4. The interval at zero is recorded on the event book only. The subject chain has no record of it, no reader sees it, and `/status` after a subject is declared again keeps no memory of it.
5. Root can lay any declaration by restart; the SIGHUP rule binds only the SIGHUP path.

## What this directory does not hold

- No secrets, and no read of an environment file.
- No instrument code of the machine, imported or copied whole.
- No default numbers: every number is declared.
- No health vocabulary in a string a person might read.

## Reference defaults a deployer replaces

This tree was cut from a reference deployment. The values below are functional (code, configuration or test input) and are left as they were. A deployer replaces each one.

| # | What | Where | Kind |
|---|------|-------|------|
| 1 | Bridge service uid `982` | `declarations.ts:43` (`MICA_BRIDGE_SERVICE_UID`) | uid constant |
| 2 | Operator uid `1000` as the fallback when `process.getuid` is absent | `tools/relay-sunset.ts:85, 411, 453, 463` | uid default |
| 3 | Operator peer socket `/run/mica-bridge/peers/1000/guard.sock` | `deploy/seed-grant-memory.sh:30`; `../tools/doctor-attest/doctor-attest.ts:127` | socket path (uid in path) |
| 4 | Alerter peer socket `/run/mica-bridge/peers/981/guard.sock` | `mica-alerter.py:37` (docstring); `deploy/mica-alerter.service:66` | socket path (uid in path) |
| 5 | Peer folders `peers/980`, `peers/981`, `peers/1000`, with the reference box's owner accounts and group | `deploy/mica-bridge.tmpfiles.conf:20-22` (rendered on the reference box; re-render on yours) | uid and account |
| 6 | The same peer folders as owner, mode and ACL facts; the operator's account as `USER` | `deploy/deployment-facts.fragment.json` | uid and account |
| 7 | Route uids `980`, `981`, `1000` and subject `peerUid` `980` | `declarations.fixture.json:93, 98, 112, 126` | uid (test input) |
| 8 | Invented route uids `5101`, `5102`, `5103`; tests map them to 980, 981, 1000 | `declarations.example.json`; `example-draft.ts:9` (`UID_MAP`) | uid (example) |
| 9 | Default declaration path `declarations.config.json` beside the service (not shipped; supply your own) | `mica-service.ts:7155`; environment `MICA_BRIDGE_DECLARATIONS` | path default |
| 10 | Installed paths `/opt/mica-bridge/...` | `deploy/mica-bridge.service:84, 86`; `tools/relay-sunset.ts:346` (`LIVE_DECLARATION`); `tools/relay-sunset.test.ts:50, 186` | path default |
| 11 | Host name in the schema's `$id` | `declarations.schema.json:3` | identifier |
| 12 | Service accounts `mica-bridge`, `mica-housekeeper`, `mica-alerter` | `deploy/*.service`, `deploy/mica-bridge.tmpfiles.conf` | account names |
| 13 | Uid literals in test inputs and assertions | `declarations.test.ts` (30 lines), `mica-service.test.ts` (91), `errand-grant.test.ts` (11), `tools/relay-sunset.test.ts` (11), `interest-book.test.ts` (5), `grant-memory.test.ts` (2), `witness-pointer.test.ts` (2), `mica-alerter.test.py` (3) | uid (tests) |
| 14 | Invented account paths used as test data | `interest-label.test.ts`, `interest-book.test.ts`, `declarations.test.ts`, `witness-drops.test.ts` | test data |
| 15 | Uid mentions in comments only (no effect) | `mica-service.ts`, `peer-auth.ts`, `grant-memory.ts`, `target-fingerprint.ts`, `stage1-guard-adapter.ts`, `deploy/seed-grant-memory.sh`, `deploy/seed-grant-memory.rig.sh` | comment |
| 16 | Imports of the installed machine `/opt/mica-machine/src/...` | `stage1-guard-adapter.ts` (18 lines), `mica-service.ts` (7), `core-door-status.ts` (6), `to-wire-options.ts` (5), `to-sensor-config.ts` (1); tests: `gate2-harm.test.ts` (6), `mica-service.test.ts` (5), `core-door-status.test.ts`, `declarations.test.ts`, `order-citation-bound.test.ts` (2 each) | path (code) |

## Running the tests

`bash mica-bridge/run-suite.sh`, from the repository root, runs the shipped suite and then `tsc`. It needs a ts-node and a tsc: by default from a `node_modules` beside `mica-bridge/`, or from the environment as `TSNODE` and `TSC`.

- **`TSNODE`:** the two test files that start a child process with ts-node (`mica-service.test.ts`, `tools/relay-sunset.test.ts`) also read it from the environment, and otherwise resolve ts-node from the tree's own `node_modules`.
- **`MICA_MACHINE_ROOT`:** one check in `declarations.test.ts` runs the machine's guard script from it. Set it to a machine checkout with its `node_modules`. Unset, the check fails and says so.

The reds expected in a default run are listed in the top README (section 3.3). Checks that hold only on the reference box are listed with reasons in `reference-only.ts` and skipped. `bash mica-bridge/run-suite.sh --reference` runs only those. Away from the reference box they are not expected to pass; on it, against the example declaration, 7 of the 12 read red and 5 pass.
