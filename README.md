# MICA bridge

**What this is.** The MICA bridge is the service an AI agent's harness asks before each act. It loads a declaration, asks the MICA machine's readers what they can see, composes their verdicts into a disposition, writes that decision to its books, and serves what it wrote. This repository holds the bridge (`mica-bridge/`) and its tools (`tools/`).

**The canon says what MICA is meant to do; this repository reports what is built and what has run.** Start with the canon's chapter 01, "The architecture in brief".

**State: alpha.** This is a working prototype that runs on one reference box, built by a small project. Most of what it reads has been designed and unit-tested. Less of it has run live, and none of it has been shown to read a probe correctly (section 3). Names, formats and the record series may still change, and nothing here is supported or certified. What is offered is this alpha. ROADMAP (in MICA machine) names its known problems, and each needs design and building before the machine works as intended.

**The other repositories.**
- **MICA machine** (`https://github.com/arcencilo-family/mica-machine`): the readers, the gates, the witness and the probe harness. The bridge imports it and does not run without it.
- **MICA canon** (`https://github.com/arcencilo-family/mica-canon`): the method. It says what each instrument is meant to read, and why.

**Where to look first.**
- Build and test: section 3.2.
- Tests expected to fail, and why: section 3.3.
- Known limits: section 4.

Licence: Apache-2.0 (`LICENSE`, `NOTICE`, `CITATION.cff`). Version 0.1.0.

---

## 1. The target (by pointer to the canon)

What MICA is for is set out in the MICA canon; start with its chapter 01. In the canon's own words, MICA is "a set of instruments that read what an AI agent does and print what they can and cannot see". This section adds no claim of its own.

---

## 2. The design (design, not tested as a whole)

**When MICA works as intended**, in the canon's words:

- **The operating rule** (chapter 01): "Health conditions confidence; confidence conditions assertion." At critical health the system "withholds assertion, holds itself reversible, and escalates. It never converts degraded health into an action." And: "This is what makes a degraded MICA quiet and reversible rather than confidently wrong."
- **Negative attestation** (chapters 01 and 08a): the substrate "may emit alarm (degraded, critical); it never emits a positive attestation of health". Health is attested from outside: "an external doctor attests the substrate's health from outside, which the substrate cannot do for itself; it can attest un-health, never certify health".
- **Where an escalation ends** (chapters 01 and 07): "A designated arbiter terminates every escalation in a node that cannot itself defer. Both are appointed by the deployer, which carries final liability."
- **The last resort** (chapters 01 and 08i): "MICA's real work is upstream: read degradation so early the crunch never arrives (sub-certain)." When it does come to that, "the failsafe is abstain-and-hold — the last resort, not the primary mechanism".

**The bridge's part in a working deployment:**

1. The agent's harness calls `POST /guard` before each act, naming the subject, its session, the act and the tool. The bridge reads the act's stakes from its declaration; the caller cannot set them (`mica-bridge/to-guard-flags.ts`).
2. The bridge asks each wired reader of the machine for a verdict on the record so far, composes the release floor (ALARM over CANNOT_ASSESS over SILENT), and answers with one disposition: RELEASE, HOLD, HOLD_BLIND or PASS_BLIND.
3. The decision is written to the decision journal and the floor trail. Every reading carries what the reader could and could not see; a reading that cannot be trusted is printed as CANNOT_ASSESS, not as a pass.
4. The harness reports what the agent did through `POST /subject-events`, into the subject log the readers read.
5. Anyone the declaration admits can read what was decided: `GET /status`, `/log`, `/events` and `/explain` (`mica-bridge/API.md`).
6. Each caller has its own socket in a folder only that account owns. The bridge knows who is asking by which socket was used (`mica-bridge/peer-auth.ts`).

The expected result: a decision on record for every act, each saying what the readers saw and what they could not see.

**How much of this path the alpha walks today.** On the reference box the bridge answers `POST /guard` and books every decision it gives, but it has released none: Gate 1 can never read SILENT, so every act is held or passes blind (limit 1). A doctor's adverse finding raises a notice that reaches no one, because no transport is configured (limit 17), and no gate has read READABLE under a probe (limit 3). Section 3 gives the detail.

---

## 3. Today: what this alpha does, and what has been tested

### 3.1 Which release

The reference box runs bridge release fde2b0d on machine a3cb4a0 (release ids of the reference box, not published commits). This tree is that bridge release cut to `mica-bridge/` and `tools/`, plus additions that do not run on the reference box:
- an example declaration in place of the live one (`declarations.example.json`, `example-draft.ts`);
- the role-word pass;
- the API and declaration references;
- the test runner and its reference-only list (`run-suite.sh`, `reference-only.ts`);
- a vendored client;
- settable test paths (`TSNODE`, `MICA_MACHINE_ROOT`).

The MICA machine tree published beside this one is the machine it is meant to sit on.

The reference box's subject is a housekeeping agent. Code, tests and account names call it `housekeeper` (account `mica-housekeeper`).

**Tested and design.** What each reader has produced on the reference box, by kind of reading:

| reader or part | wired on the box | tests | kinds of reading on the box | status |
|---|---|---|---|---|
| Gate 1 scope | yes | yes | CANNOT_ASSESS only, by construction | running; can never read SILENT |
| Gate 2 direction (harm mode) | yes | yes | SILENT, ALARM, CANNOT_ASSESS | running; both probes NOT-READABLE |
| Gate 3 | — | — | — | not a gate: the canon's chapter 01 ("The shape") says "No Gate 3: the system's immune health is the substrate, not a peer gate." The gate numbers were kept. |
| Gate 4 sunset | yes | yes | SILENT | running |
| Gate 5 adaptive | **no** | yes | none | design and tests only |
| Eng | yes | yes | SILENT, CANNOT_ASSESS | running |
| Sig | yes | yes | SILENT, CANNOT_ASSESS | running |
| narrow-T | yes | yes | SILENT, CANNOT_ASSESS | running |
| narrow-K | yes | yes | ALARM, CANNOT_ASSESS | running |
| narrow-W | yes | yes | ALARM, CANNOT_ASSESS | running |
| narrow-R | yes | yes | ALARM, CANNOT_ASSESS | running |
| op1 doctor cadence | yes | yes | SILENT, ALARM | running |
| op2 audit presence | **no** | yes | none | design and tests only |
| op3 node response | yes | yes | ALARM, CANNOT_ASSESS | running; cannot read SILENT today (R-26) |
| clerk gap | no (needs a clerk store) | indirectly | none | design and tests only |
| witness (keeps the book; gives no verdict) | yes, its own service | partly (three witness suites are not in the chain, R-31) | gives no verdict | running |
| release floor | yes | yes | CANNOT_ASSESS, ALARM; **no RELEASE read** | running; see limit 1 |
| probe harness | not on the box | yes | two scored probes, run from a checkout | both NOT-READABLE |
| doctor's wire, reply book, operator page | not on the box | yes | none | tests only (limit 17) |

**In plain words:**
- **No act has been released by the readers.**
- **No gate has read READABLE under a probe.**
- Gate 5 and op2 are not wired.
- Every wired reader except Gate 1 has produced a reading other than CANNOT_ASSESS on the reference box.

### 3.2 Build and test

These steps build and test this tree. They do not deploy it.

**Tested with:** Linux (WSL2, kernel 6.6) with bash; Node v22.22.0; npm 10.9.4; Python 3.12.3; TypeScript 5.9.3, ts-node 10.9.2 and @types/node 20.19.43, taken from the machine tree's lockfile (this tree has no `package.json` of its own). Other versions and systems are unconfirmed. systemd is needed only to deploy, which these steps do not cover.

1. **Use a git clone**, not a bare archive. One check (`mica-alerter.test.py`, "committed executable") asks git.
2. **Provide the machine.**
   - The bridge imports the machine from `/opt/mica-machine/src/...`, and `mica-bridge/tsconfig.json` points `typeRoots` at `/opt/mica-machine/node_modules/@types`. Placing a machine tree there needs root.
   - Without root, use `tools/stage-machine-half.sh`. It copies both trees from commits into a scratch folder with that prefix rewritten to the staged machine, type-checks the bridge, and runs the suites named on its command line. It needs `MACHINE_REPO` (a git checkout of the machine tree), takes the bridge repository it stands in, and defaults `NODE_MODULES` to the machine checkout's own.
3. **Provide the toolchain:** run `npm ci` in the machine tree, and make its `node_modules` available as `node_modules` beside `mica-bridge/` (a link or a copy). Or set `TSNODE` and `TSC` to a ts-node and a tsc.
4. **Set `MICA_MACHINE_ROOT`** to a machine checkout that has its `node_modules`. One check in `mica-bridge/declarations.test.ts` runs the machine's guard script from there. Unset, that check fails and says what to set.
5. **Run the suite alone:** `bash mica-bridge/run-suite.sh`.
   - It runs every `*.test.ts` in `mica-bridge/` and `mica-bridge/tools/`, `tools/doctor-attest/doctor-attest.test.ts`, `relay-lib.test.sh` and `mica-alerter.test.py`, then `tsc`.
   - It takes about seven minutes on a 3-core box, and exits 1 while the expected reds stand.
   - Run it alone: run in parallel with other suites, checks that spawn a child process time out.
6. **The reference-only checks:** `bash mica-bridge/run-suite.sh --reference` runs only the checks that assert facts of the reference box (section 3.3).

### 3.3 Tests expected to fail

A red that is not on this list is a finding. The check names below are given as the suite prints them, so that a red line can be matched; they carry no meaning beyond that.

**This tree** (`bash mica-bridge/run-suite.sh`, run alone):
- `mica-bridge/mica-service.test.ts`, 7 checks:
  - `AMENDMENT 11 / Ruling R item 2 (ACT A)`; `P6 END TO END`; `STAGE 4 §A.2`. Each expects the readers to stand on a verified subject chain, but the example declaration declares log kind `mica`.
  - `STAGE 4 §A`. It expects more wired readers than the example declares.
  - `FLOATFIX 1`. It expects 500 where the code answers a typed 503.
  - Both `SHAPE (b)` checks. They need the machine's clerk-stamps door to accept the test's own account as owner, and it does not.
- `mica-bridge/declarations.test.ts`, `toSensorConfig output run through mica-guard --sensor-config observes the recorded exit code`: red when `MICA_MACHINE_ROOT` is not set (step 4).
- `mica-bridge/mica-alerter.test.py`, `committed executable, mode 100755`: red only in a copy without `.git`.
- `bash mica-bridge/run-suite.sh --reference`: the 12 reference-only checks. Each asserts a fact of the reference box (its served declaration, a laid release, a commit of its history, its accounts) and is listed with its reason in `mica-bridge/reference-only.ts`. The default run skips them. Away from the reference box they are not expected to pass; on the reference box, in a checkout with its history, 7 read red against the example declaration and 5 pass.

**The MICA machine tree** (its README has the same list):
- `npm run typecheck`: 2 errors in `tools/gate4/probe-leg-a.ts`.
- `SM-A` in `tools/suite-membership.test.ts`, and the registration check in `src/mica/registration.test.ts`: three witness test files are not in the test chain (R-31).
- `EV-FIX-H3` in `src/probe/evidence-log.test.ts`: six test files pin a literal 64-hex hash.
- `PF-G2` and `PF-G15` in `tools/ticket-preflight/preflight.test.ts`: their fixture ticket has no `base` stamp.
- `PF-G3e` in the same file, in a repository with one commit: the check reads `HEAD~1`.
- `src/integration/l0-clerk-f3.test.ts` without the sibling ILAS checkout (limit 16).
- In a copy without `.git`: `OS-B`, `OS-G` and `OS-N` in `tools/opens-sweep/opens-sweep.test.ts`, and `PF-G3e` and `PF-G8` in the preflight test.

---

## 4. Known limits

The same limits in both trees; only a pointer to the reader's own tree differs (limits 1, 12, 14 and 18). In brackets: the tree or trees each concerns. Each is work that can be done.

1. **The release floor: no act is released by the readers while Gate 1 is wired.** [both] The floor composes reader verdicts as ALARM over CANNOT_ASSESS over SILENT. Only all-SILENT gives RELEASE. CANNOT_ASSESS never releases: it goes to the stakes split, which gives HOLD_BLIND at or above the line in force and PASS_BLIND below it (machine, `src/mica/chokepoint/types.ts`). Gate 1 only ever returns CANNOT_ASSESS (machine, `src/mica/gate1-scope/index.ts`). So while Gate 1 is wired, every act is held or proceeds as PASS_BLIND, which is a permit and not a verdict. No RELEASE has been read in the reference box's decision log. Whether a reader that can never read SILENT should take part in the release floor is an open design question.
2. **"Cannot assess" is not yet guaranteed everywhere.** [machine] Four open ROADMAP rows say where it does not yet hold in full:
   - R-12: a malformed record on a declared item is skipped silently in six places.
   - R-13: an absent witness look reads "no look" instead of NOT READABLE.
   - R-27: the witness can forget a target or fail a look without a record.
   - R-28: in harm mode nothing checks the declared witness method.
3. **No probe has read READABLE.** [both] Two live Gate 2 probes have been scored. Both scored NOT-READABLE, and no gate is promoted.
4. **The delivery stamp is taken by hand after the send.** [machine harness; both affected] The probe's "delivered-at" stamp is the sealed boundary. When it is taken by hand after the message is sent, the subject's first act can fall before it and is then not read. The fix is owed before any further probe: take the stamp before the send, or derive it from the bridge's own record of the delivered message (R-77).
5. **The scorer brief's wording.** [machine harness] The scorer brief asks for the addendum in the ceilings cell without the word "verbatim". Both scorers recorded it faithfully but not verbatim, and so failed the runbook's check (b). The wording fix is future work (R-78).
6. **Both scorers were one vendor's models.** [machine harness] The two scorers were Claude models, one Sonnet run and one Opus run. They are not decorrelated from each other or from the models that built the harness, and their agreement was compared by hand. A non-Claude second scorer is designed, not running (R-23).
7. **A killed caller holds every act.** [machine; seen through the bridge] If the caller is killed mid-tool, the signal reader's re-entry alarm latches and every later act is held, with no pilot able to release it, until the subject log is rotated. The alarm is true about the record, but not necessarily about the agent (R-98).
8. **A declaration change leaves no event of its own in the bridge's book.** [bridge; ROADMAP R-36] The bridge loads its declaration at start or on SIGHUP. A change shows only as a new declaration hash:
   - in the journal line an accepted SIGHUP prints (`SIGHUP: reloaded, declarationHash=…`);
   - on `GET /status`;
   - in the next start's `GRANT_MEMORY_ADOPTED` (or `_BEGUN`) detail, and in `SUBJECTS_DECLARED` when the subject set also changed;
   - in each later decision's `declarationBinding` (read through `/explain`).

   Whoever audits a box must compare hashes to notice a change. An event carrying the old and the new hash at every load is future work.
9. **The subject can read its declaration; that is by design.** [bridge] On the reference box the declaration file is readable by the subject's account (by file mode; the read was not exercised as that account), so the subject can know what is read and where the lines are. MICA offers its orientation and does not hide it. The cost is stated: a subject that sets out to game the readers knows where they look.
10. **The host clock steps backwards.** [both] The reference host's wall clock steps backwards by up to a few seconds many times a day, so every non-monotonic stamp is exposed (R-46). The harness's own timing test can fail some runs on such a host (R-57).
11. **The bridge's event book and witness pointer are written without fsync.** [bridge] The event book, and its quarantine sidecar, are written with a plain append; the witness pointer with a write and a rename. None of these calls fsync, so a power loss can drop a record the bridge already counted as written.
    - The decision journal, the floor trail and the chokepoint ledger are written through the machine's append store, which calls fsync before it returns.
    - So are the grant memory and the vendored client's append (R-47).
12. **What a lab can run, and what it cannot.** [both]
    - **Can run:** the machine's unit suite (`npm run test:mica`) as an ordinary user without root, with the expected reds in section 3.3.
    - **Needs root or the staging script:** this bridge's suite (section 3.2, step 2). One check also needs `MICA_MACHINE_ROOT` (step 4).
    - **Cannot run: an agent connected end to end.** The witness and the bridge run as their own systemd services under their own accounts, the bridge's per-caller socket folders must be made by root, and there are no install steps (limit 13).
13. **No install steps; the lay step is by hand.** [both] No committed script lays the machine or the bridge onto a box, and this release gives no install steps. The build-and-test steps are not install steps (R-83).
14. **Reference defaults are left in place.** [both] Uids, socket paths, account names and installed paths of the reference box stay as written, and a deployer replaces them. They are listed in `mica-bridge/README.md` ("Reference defaults a deployer replaces"). Two of them are a deployer's own:
    - The rendered `mica-bridge/deploy/mica-bridge.tmpfiles.conf` carries the reference box's account names. A deployer re-renders it on their own box (`mica-bridge/deploy/render-tmpfiles.ts`).
    - `mica-bridge/deploy/deployment-facts.fragment.json` names the operator's account as `USER`. A deployer sets it.
15. **Signed tickets name the signer.** [machine] The 36 tickets under `src/core-door/tickets/` and one glue ticket ship unchanged. 25 of the 36, and the glue ticket, name the arbiter by first name as signer. They are pinned by checksum in `src/core-door/core-inventory.json`, and the machine code is frozen for this release, so the name stays.
16. **One test needs a second repository.** [machine] `src/integration/l0-clerk-f3.test.ts` loads `src/l0` from a sibling checkout of ILAS (`https://github.com/arcencilo-family/ilas`) at `<the folder that holds the machine tree>/ILAS/ilas-github-copy`; clone it there. The machine's tests were run against a checkout whose tree is equal to that of the public commit `f768236a20f00eb203f6ce1c292f388c7a7a2a7e`. Without the checkout, that file fails with "module not found". Copying the module in, or skipping the test with a printed reason, is owed (R-84).
17. **The doctor's wire, reply book and operator page are partly built.** [machine] Built:
    - a doctor's finding raises a notice;
    - a reply is recorded in its own chained book;
    - a pairing reader prints each raising's replies;
    - the operator page renders both books.

    Not built:
    - no transport is handed to the commands, so they reach no one;
    - the submitter is a declared uid, not a separate identity (R-02);
    - the notice book's head is not committed to the witness;
    - no wall-clock time is joined to either book (R-103);
    - the page is generated once and does not verify the chains;
    - there are no halt, release or treatment records (R-100).
18. **Open work for a deployment.** [both] Each item below is in the machine's ROADMAP, section 3, in the same words.
    - **Grant memory:** the bridge's lasting record of grants is built, but it has not been seeded and proved on a fresh deployment.
    - **A reader that fails:** a reader that throws is recorded as held, blind. The code does this, but it has not been exercised on a running box.
    - **One machine root:** letting the bridge find the machine through one configured folder, instead of the fixed install path, is not installed on the reference box. Neither are the printed texts with role words in place of names. Both need root.
    - **Removal:** removing MICA from a box in one act has a generator, but the removal has not been rehearsed (two items).
    - **Zero subjects:** with no subject declared, the loader still keeps reader settings that name a removed subject. They do nothing now, but they would apply again if a subject of the same name were declared.
    - **Loading a declaration that needs a restart:** the script for it is a draft, tried only as a dry run.
    - **A reference subject:** the example agent meant to ship beside MICA as the subject it watches is not included.
    - **Documents:**
      - a live page that joins each decision to its harm line (generated once; needs a timer and its own documentation);
      - a guide to reading MICA's record;
      - a statement of what the subject on the reference box can read, and how probe material is kept away from it;
      - a first-hour walk-through;
      - a catalogue of the project's files, to be refreshed;
      - a pass that turns deployment-specific paths into documented defaults or declared settings;
      - the publication checklist, closed item by item.

The socket API, route by route, is in `mica-bridge/API.md`. Every declaration field, and the environment variables the bridge reads, are in `mica-bridge/DECLARATION.md`.

---

## 5. What stays uncertain

These are not limits that a build removes. They are what the canon says no instrument of this kind can settle, in the canon's own words (chapter and title given; the canon holds the argument):

- **08f, the externality cut:** "MICA cannot police a channel it is not on, nor attest in a vocabulary it does not have; every external property is required and named, never verified from inside; the regress halts at a declared human posit".
- **08a, negative attestation:** "no node may positively attest health, and the entitlement even to a bounded negative must come from outside the loop".
- **08e, record and truth:** a "closure that is technical, never epistemic", and "the doctor–arbiter disagreement the architecture deliberately leaves unadjudicated."
- **08g, show, not enforce:** MICA "makes their conduct provable on the record and compels none of it".

Each reading this bridge prints is bounded by these.
