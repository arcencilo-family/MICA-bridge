# PROOF-RUN: MICA bridge

**Who ran it, on what.**
- **Who:** the project's build agent (Claude Opus 5.5), **under the reference operator's own account**, on the project's reference box. It ran with no root and no `sudo`.
- **What:** this repository before this file was added and the release date was set in CITATION.cff. The tested tree is `e07cc46350cc0432aedf3681c469ab59080fa911`. The published tree is that tree plus this file and the release date in CITATION.cff. A file cannot carry the id of the tree that holds it; read the published tree's id with `git rev-parse HEAD^{tree}`.
- **The machine it ran against:** the MICA machine repository at tree `2248db8a3b6bb925d4d8b97dfd25694ee09971f2` (before its own `PROOF-RUN.md` and release date).
- **When:** 2026-11-15.
- **The install:** a fresh install was made by the operator from the machine tree's lockfile, with `npm ci --no-audit --no-fund`.
- **How:** the machine was not placed at `/opt`. The bridge ran through `tools/stage-machine-half.sh`, which copies both trees from their commits into a scratch folder and rewrites the `/opt/mica-machine` prefix to the staged machine. The suite ran inside that stage, alone.

**The repeat.** The suites were run twice more on the published tree, each time with this file in an earlier wording, the second time also with the release date set in CITATION.cff. Every check gave the same result, apart from titles that print the run's own stage path or a process id.

**A stage path that holds a name the name checks look for turns them red** (`no-personal-name.test.ts`, `witness-fence.test.ts` F-2 and F-4). This run put the stage under `/tmp`.

**What this cannot show.**
- **An outsider's account:** the run used the operator's own account on the reference box.
- **A bridge laid at `/opt`:** the bridge was not run against a machine placed there.
- **Deployment:** deploy and install are not covered, and neither is a connected agent.
- **Checks that read git state:** the stage is a copy without `.git`, so those checks read as in such a copy.

```
release      : bridge tree e07cc46350cc0432aedf3681c469ab59080fa911, on machine tree 2248db8a3b6bb925d4d8b97dfd25694ee09971f2
run          : 2026-11-15, the reference operator's own account, no root, each suite alone, staged under /tmp (no /opt)
environment  : Linux, WSL2, kernel 6.6.87.2, Ubuntu 24.04.4 LTS · 3 cores · Node v22.22.0 · npm 10.9.4 · Python 3.12.3
               · TypeScript 5.9.3, ts-node 10.9.2, @types/node 20.19.43, from a fresh install of the machine's lockfile
               · MICA_MACHINE_ROOT set to the staged machine
bridge       : stage: prefix rewritten in 17 files; tsc --noEmit CLEAN
               run-suite.sh   815 checks passed, 8 failed; tsc clean; rc 1
               --reference    12 reference-only checks: 9 red, 3 pass
reds         : every red is on the README's expected list; no red off the list.
               mica-service.test.ts   AMENDMENT 11 / Ruling R item 2 (ACT A); P6 END TO END; STAGE 4 §A, FOUND LIVE;
                                      STAGE 4 §A.2; FLOATFIX 1; both SHAPE (b) checks
               mica-alerter.test.py   committed executable, mode 100755 (the stage is a copy without .git)
not covered  : deploy, install on another box, a connected agent, a second account, a machine at /opt, other systems
```

**The 12 reference-only checks** (`run-suite.sh --reference`) assert facts of the reference box.
- **Red (9):** six in `declarations.test.ts`, `GATE 1 · THE SERVED SHAPE (S26)` in `mica-service.test.ts`, the laid-bridge check in `tools/relay-sunset.test.ts`, and one in `relay-lib.test.sh`. This tree carries no history and is not the laid release.
- **Pass (3):** the three account checks, because this box has those accounts. On another box they are not expected to pass.

**Outputs** (kept by the project, not shipped):

| file | bytes | sha256 |
|---|---|---|
| env.txt | 420 | 0f0ba400c01e3dc5980218cb9c5fb2ec5c3359e6f0b7bb19730875f7101f5fa1 |
| b-stage.txt | 315 | 8ad46a824de416efbe74381dd2e27bf94ba5aed0dc5c05c11c93e855f14a1ce1 |
| b-suite.txt | 191836 | 30844343d3be3b425f9e31b8bbfbd55aa98d898677beace38472cebdcdd64dd4 |
| b-reference.txt | 15099 | b6836d0d993969b1b549ec0c73b5bcf35a00f1d51e82b4cf198f357af69f9201 |

**Commands, as run** (`<machine>` is the machine repository; `NM` is its `node_modules`):

```
MACHINE_REPO=<machine> bash <this repository>/tools/stage-machine-half.sh      # prints "(stage kept at <stage>)"
cd <stage>/bridge
TSNODE=$NM/ts-node/dist/bin.js TSC=$NM/typescript/bin/tsc MICA_MACHINE_ROOT=<stage>/mica-machine bash mica-bridge/run-suite.sh
TSNODE=$NM/ts-node/dist/bin.js TSC=$NM/typescript/bin/tsc MICA_MACHINE_ROOT=<stage>/mica-machine bash mica-bridge/run-suite.sh --reference
```
