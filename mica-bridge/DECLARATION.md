# mica-bridge declaration reference

A reference of the declaration the bridge loads: every field, its type, whether it is required, what happens when it is absent, and its meaning in one line. Then the environment variables the bridge's code reads. Built from the code in this tree. Every fact cites a file and line in `mica-bridge/` at this tree's head. Line numbers move when the code changes; the code wins over this file. Where the code did not settle a point, this file says "unconfirmed".

## 1. The files

- **Schema:** `declarations.schema.json`, JSON Schema draft 2020-12 (`declarations.schema.json:2`). It sets `additionalProperties: false` on its objects (for example `declarations.schema.json:6`, `declarations.schema.json:24`).
- **Loader:** `declarations.ts`. The service loads the declaration with `loadDeclarations` (`declarations.ts:3864-3882`; called at `mica-service.ts:4773` and, for `--check`, `mica-service.ts:7104`). The loader does not run a JSON Schema engine. It walks the schema's fields by hand and stops at the first bad field (`declarations.ts:8-12`). It also enforces cross-field rules the schema cannot express (`declarations.ts:3-5`).
- **Example:** `declarations.example.json`. The same shape, with every path and uid invented, for a deployer to replace (`README.md:18`, in this directory). The live declaration of the reference deployment is not shipped.
- **Defaults: there are none.** The schema has no `default` keyword. A missing required field is a rejection, never a fallback (`declarations.ts:5-6`). "Absent" in the tables below means what the code does when an optional field is left out.
- **The hash.** `declarationHash` is the sha256 of the canonical JSON of the parsed declaration, not of the file bytes (`declarations.ts:3855-3858`, `declarations.ts:3878`; the canonical form is `canonical-json.ts`).
- **Pilot state** is computed at load: `INACTIVE`, `ACTIVE`, or `EXPIRED` once `expiresAt` has passed (`declarations.ts:3838-3850`).

## 2. The declared envelope

Most leaf values are wrapped in an envelope with three keys. All three are required (`declarations.schema.json:1126-1270`; loader `declarations.ts:1081-1160`).

| envelope | `value` | `basis` | `proxy` |
|---|---|---|---|
| declaredNumber (N) | finite number (`declarations.schema.json:1135`, `declarations.ts:1092-1094`) | non-empty string: why this value (`declarations.schema.json:1138`) | boolean: true when the value is a stand-in, not a calibrated one (`declarations.schema.json:1142`) |
| declaredString (S) | non-empty string (`declarations.schema.json:1156`) | as above | as above |
| declaredStringList (L) | non-empty list of unique non-empty strings (`declarations.schema.json:1178`) | as above | as above |
| declaredEventMap (M) | object: eventType to a non-empty list of eventTypes (`declarations.schema.json:1206`) | as above | as above |
| declaredEventClass (C) | `{moduleId, eventType}`, each matching `^[A-Za-z0-9_.:-]+$` (`declarations.schema.json:1242-1255`) | as above | as above |

Where the tables below say "N, integer ≥ 1" the schema narrows the envelope's `value`.

## 3. Top level

Required: `schemaVersion`, `readers`, `stakes`, `subjects`, `routes`, `pilot`, `notice`, `subjectLog`, `paths` (`declarations.schema.json:7-17`). Optional: `frame`, `baskets`, `harm`. Any other key is refused (`declarations.ts:1323-1327`).

| field | type | required | absent | meaning | schema line | loader |
|---|---|---|---|---|---|---|
| `schemaVersion` | const `1` | yes | rejected | the schema version | 19 | `declarations.ts:1335` |
| `readers` | object | yes | rejected | which readers are wired and how (section 4) | 22 | `declarations.ts:1341` |
| `stakes` | object | yes | rejected | the stakes line (section 5) | 685 | `declarations.ts:1871` |
| `subjects` | array, may be empty | yes | rejected | the agents the bridge reads (section 5) | 718 | `declarations.ts:1905` |
| `routes` | array, at least 1 | yes | rejected | which uid may call which route (section 5) | 760 | `declarations.ts:1981` |
| `pilot` | object | yes | rejected | a session-bound, expiring override of the line (section 5) | 818 | `declarations.ts:2155` |
| `notice` | object | yes | rejected | notice rate settings (section 5) | 861 | `declarations.ts:2200` |
| `subjectLog` | object | yes | rejected | the subject log's limits and chain boundary (section 5) | 901 | `declarations.ts:2217` |
| `paths` | object | yes | rejected | where the bridge's books live (section 5) | 976 | `declarations.ts:2318` |
| `frame` | object keyed by subject | no | no frame; Gate 1 labels nothing | Gate 1's declared categories and regions (section 7) | 1091 | `declarations.ts:2643`, `declarations.ts:2908` |
| `baskets` | object keyed by subject | no | no basket | Gate 2's class basket (section 7) | 1102 | `declarations.ts:2710`, `declarations.ts:3537` |
| `harm` | object keyed by subject | no | no harm stanza | Gate 2's harm stanza (section 7) | 1113 | `declarations.ts:2712`, `declarations.ts:3800` |

The three keyed objects take subject ids as keys, at least one key each, and never the key `__proto__` (`declarations.schema.json:1091-1124`).

## 4. `readers`

Required inside `readers`: `readableLoadStates`, `logPath`, `logKind`, `eng`, `sig` (`declarations.schema.json:25`). Every other block is optional. For an optional reader block, presence is the switch: absent, the reader is not wired and composes nothing; present, it is wired (`declarations.schema.json:143`, `to-wire-options.ts:595-602`).

| field | type | required | absent | meaning | schema line |
|---|---|---|---|---|---|
| `readableLoadStates` | L | yes | rejected | the log load states a reader may read from; any other state reads CANNOT_ASSESS | 33 |
| `logPath` | S | yes | rejected | the log the readers read | 36 |
| `logKind` | S, one of `mica`, `witness`, `subject-chain` | yes | rejected | which grammar `logPath` is in; stated, never detected | 40 |
| `eng` | object | yes | rejected | Eng's settings | 59 |
| `eng.structureThreshold` | N | yes | rejected | adjusted mutual information below which the signature counts as collapsed | 67 |
| `eng.minimumSampleSize` | N, integer ≥ 0 | yes | rejected | entry count below which Eng does not read | 70 |
| `eng.minimumClassCoverage` | N, integer ≥ 1 | no | no per-class floor | observations a declared class needs before Eng reads it | 85 |
| `sig` | object | yes | rejected | Sig's settings | 103 |
| `sig.clockToleranceMs` | N, number ≥ 0 | yes | rejected | a backwards time step within this window is not a contradiction | 113 |
| `sig.clockToleranceBasis` | S | yes | rejected | the stated reason for that tolerance | 128 |
| `sig.preconditionMap` | M | yes | rejected | which eventType requires which prior eventType | 131 |
| `sig.reentryMap` | M | yes | rejected | which eventType may not re-enter while a state is active | 134 |
| `sig.clerkStampLag` | S | no | the pre-clerk state | the declared lag between a record's arrival and the clerk's stamp; a disclosure, not a wire | 137 |
| `narrowK` | object | no | narrow-K not wired | constraint-activity reader | 143 |
| `narrowK.declaredProfile` | L | yes, in the block | rejected | the eventTypes that make up the profile; drives both legs | 150 |
| `narrowK.correlationThreshold` | N | no; with `correlationMinimumConstraintEvents` | leg 2 not declared | leg 2 alarms below this AMI | 154 |
| `narrowK.correlationMinimumConstraintEvents` | N, integer ≥ 0 | no; with the threshold | as above | paired events below which leg 2 is not attempted | 158 |
| `narrowK.correlationCeilingMargin` | N | no | ceiling check does not run | distance below the AMI maximum that reads CANNOT_ASSESS | 174 |
| `narrowK.correlationPermutationSamples` | N, integer ≥ 1 | no; with the seed | no percentile | reshuffles for a report-only percentile | 178 |
| `narrowK.correlationPermutationSeed` | N, integer | no; with the samples | no percentile | seed for those reshuffles | 194 |
| `narrowW` | object | no | narrow-W not wired | inquiry reader; same keys as `narrowK`, with `correlationMinimumInquiryEvents` | 212 |
| `narrowW.declaredProfile` | L | yes, in the block | rejected | the inquiry eventTypes | 219 |
| `narrowW.correlationThreshold` | N | no | leg 2 not declared | as for narrow-K | 223 |
| `narrowW.correlationMinimumInquiryEvents` | N, integer ≥ 0 | no | as above | as for narrow-K | 227 |
| `narrowW.correlationCeilingMargin` | N | no | as for narrow-K | as for narrow-K | 243 |
| `narrowW.correlationPermutationSamples` | N, integer ≥ 1 | no | as for narrow-K | as for narrow-K | 247 |
| `narrowW.correlationPermutationSeed` | N, integer | no | as for narrow-K | as for narrow-K | 263 |
| `narrowR` | object | no | narrow-R not wired | verification reader; same keys, with `correlationMinimumVerificationEvents` | 281 |
| `narrowR.declaredProfile` | L | yes, in the block | rejected | the verification eventTypes | 288 |
| `narrowR.correlationThreshold` | N | no | leg 2 not declared | as for narrow-K | 292 |
| `narrowR.correlationMinimumVerificationEvents` | N, integer ≥ 0 | no | as above | as for narrow-K | 296 |
| `narrowR.correlationCeilingMargin` | N | no | as for narrow-K | as for narrow-K | 312 |
| `narrowR.correlationPermutationSamples` | N, integer ≥ 1 | no | as for narrow-K | as for narrow-K | 316 |
| `narrowR.correlationPermutationSeed` | N, integer | no | as for narrow-K | as for narrow-K | 332 |
| `narrowT` | object | no | narrow-T not wired | drift between the record's early and late windows | 350 |
| `narrowT.driftTolerance` | N | yes, in the block | rejected | AMI above which the signature counts as drifted (ALARM) | 359 |
| `narrowT.minimumEventsPerWindow` | N, integer ≥ 0 | yes, in the block | rejected | records each window needs before the read is tried | 363 |
| `narrowT.temporalWindowSize` | N, integer ≥ 1 | no | the record is split in halves | records taken from each end | 379 |
| `narrowT.driftCeilingMargin` | N | no | no ceiling check | distance below the AMI maximum that reads CANNOT_ASSESS | 395 |
| `narrowT.driftPermutationSamples` | N, integer ≥ 0 | no; with the seed | no percentile | reshuffles, report-only | 399 |
| `narrowT.driftPermutationSeed` | N, integer | no; with the samples | no percentile | seed for those reshuffles | 415 |
| `doctorCadence` | object | no | op1 not wired | op1: the doctor's attestations in the subject log | 432 |
| `doctorCadence.attestationClass` | C, `eventType` pinned to `DOCTOR_ATTESTED` | yes, in the block | rejected | the class op1 counts | 439 |
| `doctorCadence.cadenceBoundSteps` | N, integer ≥ 1 | no | presence mode | op1 bound mode: the most steps allowed between attestations | 458 |
| `nodeResponse` | object | no | op3 not wired | op3: responses to declared calls | 477 |
| `nodeResponse.expectationClass` | C | yes, in the block | rejected | the class a response is expected for | 487 |
| `nodeResponse.responseClass` | C | yes, in the block | rejected | the one class that answers it; must differ from the expectation | 491 |
| `nodeResponse.responseBoundSteps` | N, integer ≥ 1 | yes, in the block | rejected | steps within which a response must follow | 495 |
| `nodeResponse.flatness` | object | no | leg B reads CANNOT_ASSESS (`OP3_FLATNESS_ABSENT`) | op3 leg B settings | 511 |
| `nodeResponse.flatness.amiFloor` | N, 0 < x < 1 | yes, in the block | rejected | AMI below which leg B alarms | 521 |
| `nodeResponse.flatness.amiCeilingMargin` | N, 0 < x < 1 | yes, in the block | rejected | distance below the AMI maximum that reads CANNOT_ASSESS | 537 |
| `nodeResponse.flatness.minSample` | N, integer ≥ 3 | yes, in the block | rejected | pairs needed before leg B reads | 553 |
| `nodeResponse.since` | N, integer ≥ 1 | no | op3 pairs over the whole log | the first sequence number op3 pairs over | 570 |
| `gate4Sunset` | object | no | Gate 4 not wired | Gate 4 reader | 588 |
| `gate4Sunset.subject` | S | yes, in the block | rejected | the declared subject whose endings it reads | 596 |
| `gate4Sunset.paperFreshnessBound` | N | no | order-only mode | how many sequence steps a paper may be old | 600 |
| `gate1Scope` | object | no | Gate 1 not wired | Gate 1 reader | 610 |
| `gate1Scope.subject` | S | yes, in the block | rejected | the subject whose labels it counts; must have a frame | 618 |
| `gate2Direction` | object | no | Gate 2 not wired | Gate 2 reader | 624 |
| `gate2Direction.subject` | S | yes, in the block | rejected | the subject it reads; must have a frame and a basket | 632 |
| `gate2Direction.book` | `{value: "witnessBook", basis, proxy}` | no; with `witnessMethod` | Gate 2 reads the subject log | read the witness's book instead | 636 |
| `gate2Direction.witnessMethod` | `{value: 64 hex, basis, proxy}` | no; with `book` | as above | sha256 naming the witness's seeing method | 658 |

Gate 1 on a log is CANNOT_ASSESS by construction, so declaring it puts a permanent CANNOT_ASSESS term into the floor; see the machine tree's `GATES.md`, section 1.

## 5. `stakes`, `subjects`, `routes`, `pilot`, `notice`, `subjectLog`, `paths`

| field | type | required | absent | meaning | schema line |
|---|---|---|---|---|---|
| `stakes.lineClasses` | list of unique strings `^[A-Za-z0-9_]+$`, at least 1, ordered low to high | yes | rejected | the impact classes; order decides the split | 693 |
| `stakes.baseline.holdAtOrAbove` | S, a member of `lineClasses` | yes | rejected | lowest class at which a CANNOT_ASSESS act is held, not passed | 711 |
| `subjects[]` | object | `subjects` may be `[]` | — | one declared subject | 718 |
| `subjects[].subject` | identifier, never `__proto__` | yes | rejected | the subject's id | 732 |
| `subjects[].toolName` | identifier | yes | rejected | the tool name `/guard` must be called with | 738 |
| `subjects[].stakesClass` | string, a member of `lineClasses`, not the top one | yes | rejected | the subject's impact class | 743 |
| `subjects[].peerUid` | integer ≥ 0 | yes | rejected | the uid whose socket speaks for this subject | 747 |
| `subjects[].unit` | systemd unit name, no leading `-` | no | no unit named | the subject's service unit | 751 |
| `routes[].uid` | integer ≥ 0 | yes | rejected | the caller's uid; one socket per row | 772 |
| `routes[].role` | `subject`, `alerter`, `operator`, `verifier` | yes | rejected | the caller's role | 776 |
| `routes[].allow[]` | `{method, path}`, at least 1 | yes | rejected | the grants: `GET` or `POST` on one of seven paths | 784-801 |
| `pilot.active` | boolean | yes | rejected | `false`: no other key allowed; `true`: the three below are required | 827, 842 |
| `pilot.sessionId` | string | when active | rejected | the session the override applies to | 845 |
| `pilot.expiresAt` | `YYYY-MM-DDTHH:MM:SSZ` | when active | rejected | when the override stops | 849 |
| `pilot.holdAtOrAbove` | S, a member of `lineClasses` | when active | rejected | the line used while the pilot is active and the session matches | 854 |
| `notice.window` | N, integer ≥ 1 | yes | rejected | the notice window | 869 |
| `notice.maxPerMinute` | N, integer ≥ 1 | yes | rejected | most notices per minute | 884 |
| `subjectLog.maxUnacknowledged` | N, integer ≥ 1 | yes | rejected | consecutive failed appends before `stale` turns true | 910 |
| `subjectLog.chainBoundary.retiredPath` | S | yes | rejected | the file this chain replaced, named in its first record | 936 |
| `subjectLog.chainBoundary.retiredRecords` | N, integer ≥ 0 | yes | rejected | record count of that file | 939 |
| `subjectLog.chainBoundary.retiredBytes` | N, integer ≥ 0 | yes | rejected | byte size of that file | 954 |
| `subjectLog.chainBoundary.retiredSha256` | S | yes | rejected | sha256 of that file | 969 |
| `paths.journal` | path under `/var/lib/mica-bridge/` | yes | rejected | the decision journal `/explain` reads | 996 |
| `paths.eventBook` | as above | yes | rejected | the bridge's event book (`/events`) | 999 |
| `paths.subjectLog` | as above | yes | rejected | the subject log (`/subject-events`) | 1002 |
| `paths.decisionEvents` | as above | yes | rejected | the decision events book | 1005 |
| `paths.floorTrail` | as above | yes | rejected | the floor trail (`/log`) | 1009 |
| `paths.ledger` | as above | yes | rejected | the ledger | 1012 |
| `paths.history` | as above | yes | rejected | the history book | 1015 |
| `paths.noticeDir` | as above | yes | rejected | the notices directory | 1018 |
| `paths.interestBook` | `/var/lib/mica-bridge/<name>.jsonl` | no | no interest book | where Gate 1 labels are written | 1021 |
| `paths.clerkStamps` | `{value, basis}`; value under `/var/lib/mica/` or `/var/lib/mica-bridge/`; basis ≥ 80 characters | no | no clerk stamps read | another principal's stamps file | 1026-1040 |
| `paths.witnessIntake` | `{value, basis}`; value under `/var/lib/mica/`; basis ≥ 80 characters | no | no intake | the witness's intake directory | 1047-1061 |
| `paths.witnessBook` | `{value, basis}`; same rules | no | no witness book | the witness's book of effects | 1068-1082 |

The eight required paths must sit under `/var/lib/mica-bridge/` (`declarations.schema.json:989-994`) and be distinct after canonicalisation (`declarations.ts:2553-2555`). `MICA_BRIDGE_STATE_DIR` moves where they are written, not what is declared (section 6).

## 6. Cross-field rules (loader only)

The schema cannot express these; the loader refuses a declaration that breaks one.

| rule | what it refuses | loader line |
|---|---|---|
| X1 | baseline `holdAtOrAbove` not in `lineClasses` | `declarations.ts:1896-1901` |
| X2 | a subject's `stakesClass` not in `lineClasses` | `declarations.ts:1954-1959` |
| sentinel | a subject on the top rung of `lineClasses` | `declarations.ts:1960-1971` |
| X3 | pilot `holdAtOrAbove` not in `lineClasses` | `declarations.ts:2176-2182` |
| X4 | a duplicate subject id | `declarations.ts:1972-1975` |
| X5 | a duplicate route uid | `declarations.ts:2040-2042` |
| X6 | a subject whose `peerUid` has no `subject` route row | `declarations.ts:2050-2057` |
| X7 | two declared paths equal after canonicalisation | `declarations.ts:2553-2555` |
| X8 | a new pilot activation whose `expiresAt` is already past | `declarations.ts:3979` |
| X9 | replacing a pilot that is still active | `declarations.ts:3964` |
| X10 | a route row for uid 0 | `declarations.ts:2005-2007` |
| X11 | a route row for the bridge's own uid | `declarations.ts:2008-2016` |
| X12 | a POST other than `/guard` and `/subject-events` for a subject's peer | `declarations.ts:2060-2078` |
| X13 | `/explain` for a subject's peer | `declarations.ts:2081-2117` |
| X20, X22 | Gate 1 declared for an undeclared subject, without a frame, or without `paths.interestBook` | `declarations.ts:2652-2693` |
| Z2 | a `subject` route row that no subject names | `declarations.ts:2127-2134` |
| Z3 | an active pilot with no subjects | `declarations.ts:2191-2196` |
| Z4 | a reload (SIGHUP) that changes membership, route uids or grants | `declarations.ts:4006` |
| Z5 | `POST /guard` for a uid that is no subject's peer | `declarations.ts:2137-2150` |

The frame, basket and harm stanzas carry further rules (X16 to X19, R1 to R16, H1 to H12, W1 to W4) in `validateFrame` (`declarations.ts:2908`), `validateBaskets` (`declarations.ts:3537`), `validateHarm` (`declarations.ts:3800`) and the paths block (`declarations.ts:2600-2640`). They are not listed one by one here.

## 7. `frame`, `baskets`, `harm` (one entry per subject id)

**`frame.<subject>`** (`$defs/subjectFrame`, `declarations.schema.json:1271-1380`). Both keys required.

| field | type | meaning | schema line |
|---|---|---|---|
| `categories` | envelope; `value` a list of at least 2 | the categories of the frame M | 1280-1289 |
| `categories.value[].id` | identifier, never `UNDERIVED` | the category id | 1303 |
| `categories.value[].label` | string | a readable name | 1309 |
| `categories.value[].grounding` | `vulnerability`, `agency` or `need` | the declared trait-space the category grounds in | 1313 |
| `categories.value[].self` | boolean; exactly one `true` | marks the subject's own category | 1321 |
| `regions` | envelope; `value` a list, may be empty | path prefixes mapped to categories | 1337-1346 |
| `regions.value[].prefix` | `/` or an absolute path, no `//`, `.`, `..` or trailing `/` | the prefix; the longest match wins | 1357 |
| `regions.value[].category` | a category id | where acts under the prefix are counted | 1362 |

**`baskets.<subject>`** (`$defs/subjectBasket`, `declarations.schema.json:1381-1582`). All six keys required.

| field | type | meaning | schema line |
|---|---|---|---|
| `classes.value.value[]` | signed class | value classes | 1412 |
| `classes.value.damage[]` | signed class | damage classes | 1419 |
| `classes.value.unknown[]` | unknown class | classes whose sign is not known; `damage` and `unknown` may not both be empty | 1426 |
| `epsilonNum` | N, number ≥ 0 | a numeric tolerance | 1445 |
| `grades.value.establishAt` | grade `{lane, eg}` | damage counts toward ALARM only at or above this | 1478 |
| `grades.value.creditAt` | grade | value counts toward SILENT only at or above this | 1481 |
| `window.value.kind` | const `sinceBoundary` | the only window built | 1512 |
| `nMin` | N, integer ≥ 1 | fewer classed records read CANNOT_ASSESS (`G2_STARVED`) | 1527 |
| `latchClearedBy.value[].kind` | upper-case kind, at least 1 | the record kinds that clear a latched ALARM | 1553-1564 |

A grade (`declarations.schema.json:1583-1609`): `lane` is `A`, `B` or `C`; `eg` is 0 to 3.

A signed class (`declarations.schema.json:1610-1701`), all keys required: `kind` (an upper-case subject-log kind), `outcome` (`null` for any, or one word), `weight` (`{lo, hi}`, both ≥ 0), `lane`, `eg`, `rhoCausal` (0 to 1), `falsifiability` (text), `bearsOn` (category ids, at least 1), `basis`.

An unknown class (`declarations.schema.json:1702-1777`): `kind`, `outcome`, `lane`, `eg`, `bearsOn`, `basis` required; `magnitude.hi` (> 0) optional. No weight.

**`harm.<subject>`** (`$defs/subjectHarm`, `declarations.schema.json:1778-2063`). Required: `harmOnly`, `origins`, `items`, `grants`, `clearances`; optional: `errand`.

| field | type | meaning | schema line |
|---|---|---|---|
| `harmOnly.value` | const `true` | the explicit harm-mode flag | 1800 |
| `origins.value.<id>` | `{subject, basis}`; id `^[A-Za-z0-9_-]{1,32}$` | a principal an act is bound to; `subject` is a declared subject | 1822-1841 |
| `items.value.<id>` | `{path, category, control, basis}` | a protected thing: one exact absolute path, its category, and whether the subject cannot change it | 1868-1897 |
| `grants.value.<itemId>` | `{origins, since, basis}` | which origins may change the item, and from when (`since`, a UTC instant with milliseconds) | 1924-1957 |
| `clearances.value[]` | `{record, hat: "doctor", basis}`; `record` 64 hex | a witness record the doctor clears | 1984-2003 |
| `errand.value` | `{categories, maxWindowMinutes}`; minutes 1 to 1440 | which categories an errand may grant, and the longest window | 2029-2046 |

## 8. Environment variables

The service (`mica-service.ts`):

| variable | read at | when unset |
|---|---|---|
| `MICA_BRIDGE_DECLARATIONS` | `mica-service.ts:7154-7155` | `declarations.config.json` beside `mica-service.ts` (not shipped in this tree) |
| `MICA_BRIDGE_SOCKET_DIR` | `mica-service.ts:7163` | `/run/mica-bridge` |
| `MICA_BRIDGE_STATE_DIR` | `mica-service.ts:3818` | no override: the declared `/var/lib/mica-bridge/...` paths are used as written. When set, that prefix is replaced by this value (`mica-service.ts:4748-4751`) |
| `MICA_BRIDGE_RELAY_MARKER` | `mica-service.ts:7081` | `/opt/mica-bridge.relay-in-progress`; if that file exists, `--check` refuses and `/status.relay` reports it (`mica-service.ts:7080-7096`) |
| `MICA_BRIDGE_TEST_BRIDGE_GID` | `mica-service.ts:7169` | the gid of group `mica-bridge` from `/etc/group` (`mica-service.ts:4872`). For tests only (`mica-service.ts:7164-7168`) |

The unit template sets the first two to installed paths (`deploy/mica-bridge.service:86-87`). R-85 in the machine tree's ROADMAP is about running with both unset.

The alerter (`mica-alerter.py`):

| variable | read at | when unset |
|---|---|---|
| `MICA_BRIDGE_SOCKET` | `mica-alerter.py:1168` | refuses to start |
| `MICA_ALERTER_POLL_SECONDS` | `mica-alerter.py:1169` | refuses to start; must be a number > 0 |
| `MICA_ALERTER_STATE_DIR` | `mica-alerter.py:1170` | refuses to start |
| `MICA_ALERTER_MAX_PER_MINUTE` | `mica-alerter.py:1171` | refuses to start |
| `MICA_TG_TOKEN`, `MICA_TG_CHAT_ID` | `mica-alerter.py:1175-1176` | refuses to start, unless the stdout transport is chosen; the placeholder chat id `CHANGEME` is refused too (`mica-alerter.py:129`, `mica-alerter.py:1177-1180`) |
| `MICA_ALERTER_TRANSPORT` | `mica-alerter.py:1164-1165` | Telegram; `stdout` (or `--dry-run`) prints instead |
| `MICA_ALERTER_HEARTBEAT_POLLS` | `mica-alerter.py:1208` | `0`: heartbeat off (`mica-alerter.py:348`) |

The refusal for a missing variable is `require_env` (`mica-alerter.py:136-140`).

Scripts and tests:

| variable | read at | when unset |
|---|---|---|
| `MICA_BRIDGE_RELAY_MARKER` | `relay-bridge.sh:174` | `/opt/mica-bridge.relay-in-progress` |
| `MICA_BRIDGE_RELAY_READY_TIMEOUT` | `relay-lib.sh:537` | `90` (seconds) |
| `TSNODE`, `TSC` | `run-suite.sh:8-9` | `node_modules` beside this directory |
| `MICA_BRIDGE_REFERENCE_SET` | `reference-only.ts:22` | reference-only tests are skipped; `run-suite.sh --reference` sets it to `1` (`run-suite.sh:13`) |
| `MICA_TREE`, `REHEARSAL_WORK`, `REHEARSAL_PLACES` | `tools/witness-rehearsal.ts:33-40` | the system temp directory for the last two; the first was not traced (unconfirmed) |

`relay-bridge.sh` sets `MICA_RELAY_LOCK_DIR=/run/mica-relay` itself; it does not read it from the environment (`relay-bridge.sh:392`).

The machine root is not an environment variable: the bridge imports the machine from `/opt/mica-machine` by absolute path (see the root `README.md`, "Which machine release the bridge needs").
