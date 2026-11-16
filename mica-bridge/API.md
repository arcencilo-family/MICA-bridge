# mica-bridge socket API

A reference of the bridge's HTTP API, built from the code in this tree. Every fact cites a file and line in `mica-bridge/` at this tree's head. Line numbers move when the code changes; the code wins over this file. Where the code did not settle a point, this file says "unconfirmed".

## 1. How a caller connects

- **Transport.** HTTP/1.1 over Unix domain sockets only. Every server listens on a filesystem path, never on a TCP port (`mica-service.ts:5-6`, `mica-service.ts:4891-4895`).
- **One socket per caller.** The service opens one socket for each row of the declaration's `routes[]`, at `<socketDir>/peers/<uid>/guard.sock` (`peer-auth.ts:115-121`). `<socketDir>` is `MICA_BRIDGE_SOCKET_DIR`, or `/run/mica-bridge` when that is unset (`mica-service.ts:7163`).
- **Who the caller is.** The service never asks the kernel for the peer's uid. A connection's uid is the uid of the socket that accepted it, fixed when the socket is bound (`peer-auth.ts:74-79`, `mica-service.ts:4891`).
- **The directory is the boundary.** At start the service checks every `<socketDir>/peers/<uid>/` directory before it binds any socket. Each must exist, be a directory, be owned by exactly that uid, have exactly the gid of group `mica-bridge`, and have mode exactly `0770` (`peer-auth.ts:137-161`, `mica-service.ts:4872-4882`). One failed check refuses the whole start (`mica-service.ts:4878-4881`). The service never creates these directories (`peer-auth.ts:35-39`, `peer-auth.ts:138-140`).
- **The socket file.** After `listen()`, an old socket file at the path is first removed and the new one is set to mode `0666` (`mica-service.ts:4890`, `mica-service.ts:4900`, `peer-auth.ts:170-172`). The directory, not the file, limits who can reach it (`peer-auth.ts:54-68`).
- **Stated limit.** Root can connect to any of these sockets whatever the directory bits say (`peer-auth.ts:70-72`). The loader refuses a `routes[]` row for uid 0 (`declarations.ts:2005-2007`).
- **Example.** `curl --unix-socket <socketDir>/peers/<uid>/guard.sock http://unix/status`. The host part of the URL is not read; only the path and query are (`mica-service.ts:5347-5348`).

## 2. What every request goes through, in order

1. **No declaration ever loaded.** `503 {"error":"PREFLIGHT_NO_DECLARATION"}` (`mica-service.ts:5351-5354`).
2. **Unknown path.** Any path other than the seven below gives `404 {"error":"UNKNOWN_PATH"}` (`mica-service.ts:5356-5360`).
3. **Route check.** `authorizeRoute` looks up the caller's uid in `routes[]` and needs an exact `(method, path)` grant (`peer-auth.ts:188-209`, `mica-service.ts:5362-5367`).
   - No `routes[]` row for the uid: `403 FORBIDDEN` (`peer-auth.ts:194-197`).
   - The path is granted with another method: `405 METHOD_NOT_ALLOWED`. Otherwise: `403 FORBIDDEN` (`peer-auth.ts:198-206`).
   - Both refusals set the header `Allow: GET, POST` (`mica-service.ts:5364`).
4. **POST bodies** (`mica-service.ts:5394-5449`):
   - More than 4096 bytes: `413 BODY_TOO_LARGE` (`mica-service.ts:5426-5431`).
   - No complete body within 5 s: `500 REQUEST_TIMEOUT` (`mica-service.ts:5416-5420`).
   - `Content-Type` other than exactly `application/json`: `415 UNSUPPORTED_MEDIA_TYPE` (`mica-service.ts:5436-5439`).
   - Body that is not JSON: `400 MALFORMED_JSON`. An empty body is read as `{}` (`mica-service.ts:5440-5446`).
5. **A handler that throws** is answered, not left hanging, through `failRequest` (`mica-service.ts:5377-5391`, `mica-service.ts:5458-5462`).

Every response is JSON with `Content-Type: application/json` and a `Content-Length` (`mica-service.ts:7012-7016`). Error bodies carry `error` (a code), `detail` (text) and `identity` (the act's identity or `null`) (`mica-service.ts:5352`, `mica-service.ts:5358`, `mica-service.ts:5365`).

Who may hold which grant is set by the declaration, not by the code. The loader adds these limits:
- `POST /guard` only for a declared subject's `peerUid` (`declarations.ts:2137-2150`).
- A subject's peer may hold no POST beyond `/guard` and `/subject-events` (`declarations.ts:2060-2078`).
- A subject's peer may not hold `/explain` (`declarations.ts:2081-2117`).
- No row for uid 0, no row for the bridge's own uid, no duplicate uid (`declarations.ts:2005-2016`, `declarations.ts:2040-2042`).

## 3. Routes

| method | path | read-only | handler |
|---|---|---|---|
| POST | `/guard` | no: appends a decision and events | `mica-service.ts:5823` |
| POST | `/subject-events` | no: appends to the subject log | `mica-service.ts:6261` |
| GET | `/status` | yes (see the note below) | `mica-service.ts:5245`, `mica-service.ts:5527-5528` |
| GET | `/events` | yes | `mica-service.ts:5529-5580` |
| GET | `/log` | yes | `mica-service.ts:5583-5629` |
| GET | `/explain` | yes | `mica-service.ts:5681` |
| GET | `/sunset-order` | yes | `mica-service.ts:5497-5521`, `mica-service.ts:5525-5526` |

The path list is `KNOWN_PATHS` (`mica-service.ts:5356`); the same seven are the only values the loader accepts in `routes[].allow[].path` (`declarations.ts:1992`). A GET on `/guard` or `/subject-events`, or a POST on a read path, that passes the route check is answered `405 METHOD_NOT_ALLOWED` (`mica-service.ts:5464-5466`, `mica-service.ts:5630-5632`).

Note on "read-only": no GET handler appends to a book in the code read for this file. Whether `buildStatus()` writes anything was not traced line by line: unconfirmed.

### POST /guard

Asks the bridge for a disposition on one act before it runs.

**Request body** (`mica-service.ts:1305-1340`). A JSON object with exactly these four keys, each a non-empty string matching `^[A-Za-z0-9_.:-]+$`:

| key | meaning |
|---|---|
| `subject` | a declared `subjects[].subject` |
| `sessionId` | the caller's session; decides whether an active pilot applies (`to-guard-flags.ts:69-72`) |
| `actionId` | the act's id |
| `toolName` | must equal the subject's declared `toolName` (`to-guard-flags.ts:45-52`) |

The caller may not send `stakesClass`; the bridge reads it from the declaration (`mica-service.ts:1319-1321`, `to-guard-flags.ts:80`).

**Response 200** (`mica-service.ts:5941-5960`):

| key | meaning |
|---|---|
| `decision` | trimmed to `disposition`, `execute`, `decisionHash`, `floorKind`, `blindSplit`, `rationale`; a key the decision lacks stays absent (`mica-service.ts:311-318`) |
| `delivery` | the delivery record from the adapter (`guard-adapter.ts:172`) |
| `readerFootings` | per reader: `reader`, `loadState`, `verifiedChain` (`stage1-guard-adapter.ts:661-662`) |
| `readerFootingsBasis` | `{"kind":"THIS_CALL"}` or `{"kind":"NO_READING_TAKEN","reason":...}` (`stage1-guard-adapter.ts:663-664`) |
| `quarantined` | an array (`guard-adapter.ts:197`) |

`disposition` is one of `RELEASE`, `HOLD`, `HOLD_BLIND`, `PASS_BLIND`; how the machine picks one is in the machine tree's `GATES.md`, section 1. The journal, `/explain` and the event book keep the full decision; only the reply is trimmed (`mica-service.ts:5942-5951`).

**Errors:**

| status | error | when | where |
|---|---|---|---|
| 503 | `NOTHING_DECLARED` | the declaration names no subject | `mica-service.ts:5827-5834` |
| 400 | `MALFORMED_BODY`, `UNKNOWN_FIELD`, `CALLER_SUPPLIED_STAKES`, `MALFORMED_FIELD` | body checks | `mica-service.ts:1312-1330` |
| 400 | `UNKNOWN_SUBJECT`, `TOOL_NAME_MISMATCH` | subject or tool not declared as sent | `mica-service.ts:5866-5879` |
| 403 | `SUBJECT_NOT_BOUND_TO_PEER` | the subject's `peerUid` is not the caller's uid | `mica-service.ts:5881-5885` |
| 409 | `IDENTITY_HASH_CONFLICT` | the identity already has a final decision under another request hash | `stage1-guard-adapter.ts:643-653` |
| 400 | `MALFORMED_FIELD` | the machine refused the call's usage | `stage1-guard-adapter.ts:738` |
| 500 | `SERVICE_FAULT` | the evaluation threw | `stage1-guard-adapter.ts:740-745` |
| 503 | `GUARD_NOT_BOUND` | the not-bound adapter is in use (tests only; the default is the Stage 1 adapter) | `guard-adapter.ts:233-240`, `mica-service.ts:4463-4470` |

### POST /subject-events

Appends one record to the subject log.

**Request body** (`mica-service.ts:3258-3360`):

| key | type | required | meaning |
|---|---|---|---|
| `identity` | object `{subject, sessionId, actionId}`, each a non-empty identifier | yes | the act this record belongs to (`mica-service.ts:3296-3305`) |
| `kind` | one of `SUBJECT_EVENT_KINDS` | yes | the record's kind (`mica-service.ts:1835-1851`, `mica-service.ts:3306-3308`) |
| `eventHash` | 64 lowercase hex | yes | sha256 of the canonical `{identity, kind, payload?}`; the service recomputes it (`mica-service.ts:3309-3311`, `mica-service.ts:6563-6579`) |
| `payload` | object of scalars (string, number, boolean, null) | no | kind-specific fields (`mica-service.ts:3312-3323`) |
| `targetIdentity` | string | no; only on `TOOL_ATTEMPTED` | the plain target; the service keeps a fingerprint and never stores the value (`mica-service.ts:3264-3284`, `mica-service.ts:3337-3351`) |

**Which hand may post which kind** (`mica-service.ts:1981-2095`):
- `ERRAND_GRANTED` and `ERRAND_CLOSED`: refused for every caller (`mica-service.ts:1989-1999`, `mica-service.ts:2365`).
- A uid with no route row, or a role other than `operator` or `subject`: refused (`mica-service.ts:2016-2034`).
- `DOCTOR_ATTESTED`, the five ending papers, `ENDING_ORDERED` and `ARBITER_RESOLVED`: operator only (`mica-service.ts:1668-1676`, `mica-service.ts:2036-2052`).
- Every other kind: subject only (`mica-service.ts:2075-2095`).

**Response 200:** `{"seq": <n>, "duplicate": false}` for a new record (`mica-service.ts:6851`); `{"seq": <n>, "duplicate": true}` when the same identity and kind was already stored with the same hash (`mica-service.ts:6588-6592`).

**Errors** (from `handleSubjectEvents`, `mica-service.ts:6261-6851`):

| status | error | when |
|---|---|---|
| 400 | `MALFORMED_BODY`, `UNKNOWN_FIELD`, `MALFORMED_FIELD` | body checks (`mica-service.ts:3286-3360`) |
| 403 | `FORBIDDEN` | the kind is not this hand's (`mica-service.ts:6300`) |
| 400 | `UNKNOWN_SUBJECT` | `identity.subject` is not declared (`mica-service.ts:6306`) |
| 403 | `SUBJECT_NOT_BOUND_TO_PEER` | a subject posting for another subject (`mica-service.ts:6316`) |
| 400 | `CITATION_UNRESOLVED`, `ORDER_CITATION_REFUSED`, `ORDER_ALREADY_STANDING`, `ORDER_REF_UNRESOLVED`, `RESOLUTION_UNRESOLVED`, `MALFORMED_FIELD` | kind-specific payload checks (`mica-service.ts:6334-6431`) |
| 400 | `EVENT_HASH_MISMATCH` | `eventHash` does not match (`mica-service.ts:6571-6579`) |
| 409 | `EVENT_HASH_CONFLICT` | same identity and kind already stored with a different hash (`mica-service.ts:6594`) |
| 400 | a refusal code from the appender | the append was refused (`mica-service.ts:6787-6789`) |
| 503 | `RECORD_NOT_PERSISTED` | the append failed; the body adds `stale` (`mica-service.ts:6795-6807`) |

A `503 RECORD_NOT_PERSISTED` is retryable. After `subjectLog.maxUnacknowledged` consecutive failures, `stale` reads `true` (`mica-service.ts:576-584`).

### GET /status

No query parameters are read (`mica-service.ts:5527-5528`). The body is `StatusResponse` (`mica-service.ts:522-655`). Its top-level keys:

`preflight`, `declarationHash`, `declarationPath`, `declarationLoadedAt`, `lastRejectedDeclaration`, `pilot`, `instruments` (one row per instrument: `id`, `state`, `reason`, and a `footing` for wired readers), `subjects`, `guardBound`, `startedAt`, `uptimeSeconds`, `persistence`, `droppedRecords`, `quarantine`, `release`, `relay`, `subjectEvents`, `historyOwner`, `appendLocks`, `door`, `targetFingerprint` (`mica-service.ts:522-655`).

The fields inside `instruments[]` rows other than `id`, `state`, `reason` and `footing` were not traced for this file: unconfirmed.

### GET /events

Reads the bridge's own event book (`mica-service.ts:5529-5580`).

| parameter | meaning |
|---|---|
| `after` | return events with `seq` greater than this; default 0 |
| `limit` | page size; default 100, at most 1000 |
| `tail` | the newest n events, at most 1000 |

`after` and `tail` together: `400 MALFORMED_FIELD` (`mica-service.ts:5555-5566`). Any other parameter: `400 MALFORMED_FIELD` (`mica-service.ts:5541-5554`).

Response 200: `{"events": [...], "lastSeq": <n>, "more": <bool>}` (`mica-service.ts:5573`, `mica-service.ts:5580`).

### GET /log

Reads the floor trail: one line per decision (`mica-service.ts:5583-5629`).

| parameter | meaning |
|---|---|
| `tail` | the newest n lines; a positive integer in plain digits; at most 500; default 50 |

Any other parameter, or a `tail` that is not a positive integer: `400 MALFORMED_FIELD` (`mica-service.ts:5594-5618`).

Response 200: `{"lines": [...], "total": <n>, "subjectsDeclared": ...}` (`mica-service.ts:5629`). When the trail file does not exist yet: `{"lines": [], "total": 0, "reason": ..., "subjectsDeclared": ...}` (`mica-service.ts:5621-5626`). `subjectsDeclared` is `"NOTHING_DECLARED"` or the count of declared subjects (`mica-service.ts:5817-5821`).

### GET /explain

What each reader read for one decision (`mica-service.ts:5681-5815`).

| parameter | meaning |
|---|---|
| `decisionHash` | required; exactly 64 lowercase hex; the value `/guard` returned |

Missing or malformed: `400 MALFORMED_FIELD` (`mica-service.ts:5683-5691`).

Response 200 (`mica-service.ts:5750-5814`): `decisionHash`, `identity`, `at`, `sequenceNumber`, `declarationBinding`, `disposition`, `execute`, `narrowed`, `floorKind`, `blindSplit`, `bindingMinimum`, `readings`, `sigF3`, `readingsBasis`, `sigF3Basis`, `rationale`, `findings`, `blindPaths`, `book`, `ceiling`, `subjectsDeclared`. A decision recorded before per-reader margins existed has `readings: null` and `readingsBasis.kind: "PRE_R1_RECORD"` (`mica-service.ts:5762`, `mica-service.ts:5771-5782`).

**Errors:**

| status | error | when |
|---|---|---|
| 500 | `SERVICE_FAULT` | the decision journal could not be opened (`mica-service.ts:5696-5704`) |
| 503 | `JOURNAL_NOT_VERIFIED` | not found, and the journal's chain is broken, so absence proves nothing (`mica-service.ts:5716-5730`) |
| 404 | `DECISION_NOT_FOUND` | not found in a cleanly verified journal (`mica-service.ts:5731-5742`) |

The journal is re-read on every call; there is no cache (`mica-service.ts:5662-5668`).

### GET /sunset-order

The standing ending order for the caller's own declared subject (`mica-service.ts:5476-5521`).

- Takes no parameters. Any parameter: `400 MALFORMED_FIELD` (`mica-service.ts:5498-5508`).
- The subject is the one whose `peerUid` is the caller's uid. A caller bound to no subject gets `403 SUBJECT_NOT_BOUND_TO_PEER` (`mica-service.ts:5509-5520`).
- Response 200 (`mica-service.ts:3530-3560`): `subject`, `standing`, `order` (`seq`, `tenureRef`, `endingType`, `arbiterWord`, `holdWindowOpensAt`, or `null`), `papers[]` (`field`, `expectedKind`, `seq`, `kind`, `ref`), `resolution`, `respondedWith[]`, `presentations`, `ceiling`.
- "Standing" means an order is present and no `ARBITER_RESOLVED` cites it; the route cannot tell whether a timebox has run out (`mica-service.ts:5490-5495`).

## 4. Signals the process takes

- `SIGHUP` reloads the declaration. A rejected declaration keeps the last good one (`mica-service.ts:7182-7189`). Some fields may change only by a restart (`declarations.ts:4006`).
- `SIGTERM` stops the servers and exits 0, or exits 1 if the stop fails (`mica-service.ts:7191-7205`).
- `--check` loads the declaration, prints `OK declarationHash=... pilot=...` or `REJECTED ...`, exits 0 or 2, and binds no socket (`mica-service.ts:7098-7148`, `mica-service.ts:7157-7161`).

The environment variables the service reads are listed in `DECLARATION.md`, section 6.
