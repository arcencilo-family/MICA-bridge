import {
  GATE4_RESPONSE_ROLE_KINDS,
  GATE4_INVOCATION_KIND,
  GATE4_PAPER_ROLE_KINDS,
} from "./mica-service";
// GATE 1 · Stop 2. The underived word and the label CLASS come from the modules
// the WRITER uses, so the reader is told exactly the values the bridge puts in
// the interest book — never a second spelling of either. Round 2 (placement D):
// the class is `frameLabelEventType(frame)`, the same call mica-service makes
// when it files a label, so written and read agree by construction. Round 3
// (B2): `derivable` asks the writer's own deriver, not the region list.
import { deriveInterestLabel, INTEREST_UNDERIVED } from "./interest-label";
import { frameLabelEventType } from "./interest-book";
import { witnessRecordClass } from "./witness-pointer";
// ── to-wire-options — declaration -> mica-machine's WireOptions ────────────
//
// C9 / PART D. THIS IS NOW THE ONE OPTION BUILDER. It was written for AMENDMENT 9
// / RULING P as the /status census's own option set, parallel to the gate's; the
// auditor's finding (Abgleich §0.3) was that a parallel builder lets the census
// describe a reading the gate never takes — `/status` said "2 WIRED" while every
// live decision composed ZERO sensors. Register A2/E1.
//
// So `wireOptionsFor` (stage1-guard-adapter.ts) now BUILDS ON this function and
// adds only the gate-only fields. The census and the gate cannot disagree about
// which readers are wired, because there is one place that decides.
//
// ── WHAT THIS FUNCTION MUST NEVER CARRY ──────────────────────────────────────
//
//   `noticeDir`, `noticeWindow`, `witnessIntake`, `transport`. Since C8, `wire()`
//   REFUSES `notifierOverride` together with any of those four (`WireUsageError`),
//   and the gate always supplies `notifierOverride`. So a notifier-construction
//   field added here would not be ignored — it would throw on the first guarded
//   act and every act after it. It has never carried one; the test in
//   mica-service.test.ts is what keeps it that way.
//
// ── THE MACHINE ROOT, FIXED HERE (C9, register E8 / C8 receipt §E.1) ─────────
//
//   This file used to `import type { WireOptions } from "../../../mica-machine/..."`.
//   That relative specifier resolves to TWO DIFFERENT TREES depending on where the
//   code sits: `/opt/mica-machine` from the release tree (three levels under /opt,
//   via the release symlink's realpath) and `~/mica-machine` from the dev worktree.
//   Production was correct by accident of the release layout; DEV AND TEST read
//   `main`, which is older than what runs and lacks `floorTrailOverride` /
//   `ledgerOverride` entirely. Harmless only while this file's options and the
//   gate's were separate objects — which is exactly what Part D ends.
//
//   Fixed by taking the type from `stage1-guard-adapter.ts`, the ONE file that
//   imports mica-machine by absolute path (design §A.1, W1). This is a TYPE-ONLY
//   import and is erased at compile time, so it adds no runtime edge and no import
//   cycle: at runtime the graph stays mica-service -> stage1-guard-adapter ->
//   to-wire-options.
//
// Only the fields Ruling P and Part D are about are mapped: logPath, logKind,
// readableLoadStates, eng, sig (both Sig maps included since C9). Every other
// WireOptions field is the GATE's to add, in wireOptionsFor.

import { createHash } from "crypto";
import type { Declarations, SubjectBasket, SubjectHarm } from "./declarations";
import { harmSinceMs } from "./declarations";
import { toSensorConfig } from "./to-sensor-config";
import type { DeclaredGrant, GrantMemoryState } from "./grant-memory";
import type { WireOptions } from "./stage1-guard-adapter";

// ── GATE 2 · Stop 2 · THE MACHINE'S Gate2Basket, MIRRORED FIELD FOR FIELD ────
//
// The build contract §1 fixes the machine type (src/mica/gate2-direction); the
// bridge emits exactly it as `WireOptions.gate2`. It is spelt HERE because
// `WireOptions` comes from `/opt/mica-machine` (stage1-guard-adapter's one
// absolute import), and the installed machine predates Gate 2's reader: until
// the machine relays, `wire()` does not look for `gate2`, and the spread below
// is what lets this compile against it — the hole register E11 already names.
// The relay order (machine first) and the census are the guard, not tsc. [owed]
export type WireGate2Lane = "A" | "B" | "C";
export interface WireGate2Grade {
  readonly lane: WireGate2Lane;
  readonly eg: 0 | 1 | 2 | 3;
}
export interface WireGate2ClassKey {
  readonly moduleId: string;
  readonly eventType: string;
  readonly outcome: string | null;
}
export interface WireGate2SignedClass extends WireGate2ClassKey {
  readonly weight: { readonly lo: number; readonly hi: number };
  readonly grade: WireGate2Grade;
  readonly rhoCausal: number;
  readonly bearsOn: readonly string[];
}
export interface WireGate2UnknownClass extends WireGate2ClassKey {
  readonly grade: WireGate2Grade;
  readonly bearsOn: readonly string[];
  readonly magnitude?: { readonly hi: number };
}
export interface WireGate2Basket {
  readonly basketClass: string;
  readonly frameCategories: readonly string[];
  readonly value: readonly WireGate2SignedClass[];
  readonly damage: readonly WireGate2SignedClass[];
  readonly unknown: readonly WireGate2UnknownClass[];
  readonly epsilonNum: number;
  readonly establishAt: WireGate2Grade;
  readonly creditAt: WireGate2Grade;
  readonly window: { readonly kind: "sinceBoundary" };
  readonly nMin: number;
  readonly latchClearedBy: readonly { readonly moduleId: string; readonly eventType: string }[];
}

// ── GATE 2 · Long Run A Stop 2 · THE MACHINE'S HARM TYPES, MIRRORED FIELD FOR FIELD ──
//
// Contract M1 fixes the machine types (src/mica/gate2-direction: Gate2HarmOrigin,
// Gate2HarmItem, Gate2Harm) and M3 the WireOptions keys (`gate2Harm`,
// `gate2RosterPath`, `gate2DecidingActionId`). They are spelt HERE for the
// WireGate2Basket reason: `WireOptions` comes from the INSTALLED machine
// (/opt/mica-machine, eedfda8), which has none of them. Verified at bytes
// 2026-10-15: the installed wire() reads its options by NAMED key only and no
// file under /opt/mica-machine/src/{glue,mica} enumerates the options object
// (`Object.keys(options` / `Object.entries(options` occur nowhere), so the three
// keys are ignored there and Gate 2 reads UNWIRED in harm mode (no `gate2`)
// until the machine relays. Machine first is the guard, as for `gate2`. [owed]
export interface WireGate2HarmOrigin {
  readonly id: string;
  readonly subject: string;
}
export interface WireGate2HarmItem {
  readonly id: string;
  readonly category: string;
  readonly control: boolean;
  /** fingerprintTarget(salt, item.path, TARGET_CANON_VERSION) — B-1's function and version; null with no epoch. */
  readonly fingerprint: string | null;
}
export interface WireGate2GrantSince {
  readonly at: number;
  readonly utc: string;
  readonly declaredAt: number;
  readonly declaredUtc: string;
}

/**
 * S216-2 · WHAT THE SERVICE KNOWS OF ITS GRANT MEMORY, handed in so this function stays pure (the memory is a file
 * the service owns; no IO here). Absent or null: the wire carries NO grantMemory and the declared since only, which
 * the S216-2 machine refuses whole (WIRED AND BLIND, "Grant memory: not printed") — never a since the memory did not
 * vouch for. Built by mica-service's grantMemoryViewFor.
 */
export interface HarmGrantMemoryView {
  readonly tag: string;
  readonly state: GrantMemoryState;
  /** The effective since of one declared grant; null = the memory holds no entry (a wiring fault, refused loudly). */
  readonly effective: (g: DeclaredGrant) => { readonly at: number; readonly utc: string } | null;
}

export interface WireGate2Harm {
  /** "G2_HARM@" + 16 lower hex, computed here (gate2HarmClass), printed on every verdict. */
  readonly harmClass: string;
  readonly origins: readonly WireGate2HarmOrigin[];
  readonly items: readonly WireGate2HarmItem[];
  /** itemId -> originIds; EVERY item has an entry; [] is a grant list. */
  readonly grants: Readonly<Record<string, readonly string[]>>;
  /**
   * S216 · itemId -> originId -> the instant the grant counts from. S216-2: `at`/`utc` are the EFFECTIVE since (the
   * latest of the declared since, the grant memory's first sight and its high-water since), `declaredAt`/`declaredUtc`
   * the declared one; every spelling is toISOString's of its number (the machine checks it).
   */
  readonly grantSince: Readonly<Record<string, Readonly<Record<string, WireGate2GrantSince>>>>;
  /** S216-2 · the grant memory's tag and state (printed by the machine in its own fixed words). */
  readonly grantMemory: { readonly tag: string; readonly state: GrantMemoryState };
  /** S208-2 · the errand grants the service derived from its chain ([] when none). */
  readonly errandGrants: readonly WireErrandGrant[];
  /** 64-hex witness RECORD hashes (the record's own `hash`) — C1, the doctor's hat. */
  readonly clearances: readonly string[];
  /** ms; null = the bridge holds no target-salt epoch (or does not know when it began). */
  readonly saltEpochSince: number | null;
}

/**
 * WHAT THE SERVICE KNOWS ABOUT ITS TARGET-SALT EPOCH, handed in so this function
 * stays pure (no salt, no IO here). Built by mica-service, where the salt lives:
 * `itemFingerprints` keyed by item PATH, computed with `fingerprintTarget` —
 * the SAME function and TARGET_CANON_VERSION the pointer uses after B-1 — and
 * `saltEpochSince` = the `ts` of this epoch's SALT_EPOCH_STARTED / _ADOPTED row
 * in the event book (null when the bridge cannot say). Absent or null: every
 * fingerprint null and saltEpochSince null — the machine then reads item
 * membership NOT READABLE (A-5), never a match.
 */
export interface HarmTargetEpoch {
  readonly saltEpochSince: number | null;
  readonly itemFingerprints: Readonly<Record<string, string>>;
  /**
   * S208-2 · the service's OTHER per-request harm input: the errand grants it derived from the arbiter's
   * ERRAND_GRANTED / ERRAND_CLOSED records on its own chain (deriveErrandGrants). Absent = none.
   */
  readonly errandGrants?: readonly WireErrandGrant[];
}

/** S208-2 · one errand grant on the wire: ms compared, UTC spellings printed. */
export interface WireErrandGrant {
  readonly errandId: string;
  readonly origin: string;
  readonly items: readonly string[];
  readonly from: { readonly at: number; readonly utc: string };
  readonly until: { readonly at: number; readonly utc: string };
  /** AA2 · the granting ERRAND_GRANTED record's subjectSeq and the uid that posted it (printed on the grant line). */
  readonly seq: number;
  readonly peerUid: number;
}

/** The version tag inside the harmClass digest. A change to WHAT the digest covers bumps it. */
export const GATE2_HARM_CLASS_VERSION = "G2_HARM_V3";

/**
 * harmClass = "G2_HARM@" + the first 16 hex of sha256 over
 *   JSON.stringify([ GATE2_HARM_CLASS_VERSION, subject,
 *                    origins  as [id, subject]                 sorted by id,
 *                    items    as [id, path, category, control]  sorted by id,
 *                    grants   as [itemId, sorted originIds]     sorted by itemId,
 *                    clearances as sorted record hashes,
 *                    since    as [itemId, [[originId, since]…]]  both sorted by id ])
 * V2 (S216): the grants' DECLARED since instants are covered — a moved declared since is a new class, printed on
 * every verdict; a since moved by the grant memory (S216-2) moves the memory tag, not the class (F-4 (a)): the class
 * names what the deployer declared, and stays predictable from a tree declaration.
 * V3 (S208-2): the errand envelope (sorted categories, max window) is covered, null when absent; the errand
 *   GRANTS are records, not declaration, and never enter the class.
 * Deterministic and version-tagged; BASES EXCLUDED (contract B2), and so are
 * hats (always "doctor") and proxies. The PATH is covered, not the fingerprint:
 * the class names what the deployer declared, not the salt epoch it is read in.
 */
export function gate2HarmClass(subject: string, harm: SubjectHarm): string {
  const byId = <T>(m: Readonly<Record<string, T>>): [string, T][] =>
    Object.keys(m)
      .sort()
      .map((id) => [id, m[id]]);
  const input = JSON.stringify([
    GATE2_HARM_CLASS_VERSION,
    subject,
    byId(harm.origins.value).map(([id, o]) => [id, o.subject]),
    byId(harm.items.value).map(([id, it]) => [id, it.path, it.category, it.control]),
    byId(harm.grants.value).map(([id, g]) => [id, [...g.origins].sort()]),
    harm.clearances.value.map((c) => c.record).sort(),
    byId(harm.grants.value).map(([id, g]) => [id, Object.keys(g.since).sort().map((o) => [o, g.since[o]])]),
    harm.errand === undefined ? null : [[...harm.errand.value.categories].sort(), harm.errand.value.maxWindowMinutes],
  ]);
  return `G2_HARM@${createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16)}`;
}

/** The harm stanza -> the machine's Gate2Harm (contract M1). Every list in ONE fixed order (by id). */
export function gate2WireHarm(
  subject: string,
  harm: SubjectHarm,
  epoch: HarmTargetEpoch | null | undefined,
  memory?: HarmGrantMemoryView | null
): WireGate2Harm {
  const ids = (m: Readonly<Record<string, unknown>>): string[] => Object.keys(m).sort();
  // m3 (cold canon refuter): NEVER A SILENT NULL WHILE AN EPOCH EXISTS. A null
  // fingerprint means "no epoch" to the reader; handed an epoch that lacks an
  // item, the honest answer is a wiring fault, loud, here — not an item that can
  // never match and reads as quiet. No epoch at all: every fingerprint is null.
  const fp = (id: string, path: string): string | null => {
    if (epoch === null || epoch === undefined) return null;
    if (!Object.hasOwn(epoch.itemFingerprints, path) || !/^[0-9a-f]{64}$/.test(epoch.itemFingerprints[path])) {
      throw new Error(
        `gate2Harm wiring fault: a target-salt epoch was handed in, but it carries no fingerprint for harm item ` +
          `"${id}". A null here would read as "no epoch" and the item could never match. The service's ` +
          `harmEpochFor must fingerprint every declared item path.`
      );
    }
    return epoch.itemFingerprints[path];
  };
  const grants: Record<string, readonly string[]> = {};
  for (const id of ids(harm.items.value)) grants[id] = [...harm.grants.value[id].origins];
  // S216 · the instant each grant counts from, as ms, for exactly the origins listed.
  // S216-2 · GM2: the EFFECTIVE since the grant memory gives (never earlier than the declared one), beside the declared.
  const grantSince: Record<string, Record<string, WireGate2GrantSince>> = {};
  for (const id of ids(harm.items.value)) {
    grantSince[id] = {};
    for (const o of harm.grants.value[id].origins) {
      const utc = harm.grants.value[id].since[o];
      const declaredAt = harmSinceMs(utc);
      let at = declaredAt;
      let eff = utc;
      if (memory !== null && memory !== undefined) {
        const g: DeclaredGrant = {
          key: { subject, itemId: id, path: harm.items.value[id].path, originId: o, originSubject: harm.origins.value[o].subject },
          sinceAt: declaredAt,
          sinceUtc: utc,
        };
        const e = memory.effective(g);
        if (e === null) {
          throw new Error(
            `gate2Harm wiring fault: the grant memory holds no entry for the grant of "${o}" on "${id}". A since the ` +
              `memory did not vouch for would reopen the restart exit (S216-2); every accepted load first-sees every grant.`
          );
        }
        if (e.at < declaredAt) throw new Error(`gate2Harm wiring fault: the grant memory's since for "${o}" on "${id}" is earlier than the declared one.`);
        at = e.at;
        eff = e.utc;
      }
      grantSince[id][o] = { at, utc: eff, declaredAt, declaredUtc: utc };
    }
  }
  const wired: Omit<WireGate2Harm, "grantMemory"> = {
    harmClass: gate2HarmClass(subject, harm),
    origins: ids(harm.origins.value).map((id) => ({ id, subject: harm.origins.value[id].subject })),
    items: ids(harm.items.value).map((id) => {
      const it = harm.items.value[id];
      return { id, category: it.category, control: it.control, fingerprint: fp(id, it.path) };
    }),
    grants,
    grantSince,
    errandGrants: epoch === null || epoch === undefined ? [] : [...(epoch.errandGrants ?? [])],
    clearances: harm.clearances.value.map((c) => c.record),
    saltEpochSince: epoch === null || epoch === undefined ? null : epoch.saltEpochSince,
  };
  // No memory view: no grantMemory key, so the S216-2 machine reads WIRED AND BLIND (fail closed, said above).
  if (memory === null || memory === undefined) return wired as WireGate2Harm;
  return { ...wired, grantMemory: { tag: memory.tag, state: memory.state } };
}

/** The version tag inside the basketClass digest. A change to WHAT the digest covers bumps it. */
export const GATE2_BASKET_CLASS_VERSION = "G2_BASKET_V1";

/**
 * The basket's wire classes, built from `.value` only, every object in ONE
 * fixed key order (contract §1's), so the declaration's own key order never
 * reaches the bytes. moduleId is the SUBJECT, by use (contract §4).
 */
function gate2WireLists(
  subject: string,
  basket: SubjectBasket,
  eventTypeOf: (kind: string) => string = (kind) => kind
): Pick<WireGate2Basket, "value" | "damage" | "unknown"> {
  const lists = basket.classes.value;
  const signed = (c: SubjectBasket["classes"]["value"]["value"][number]): WireGate2SignedClass => ({
    moduleId: subject,
    eventType: eventTypeOf(c.kind),
    outcome: c.outcome,
    weight: { lo: c.weight.lo, hi: c.weight.hi },
    grade: { lane: c.lane, eg: c.eg },
    rhoCausal: c.rhoCausal,
    bearsOn: [...c.bearsOn],
  });
  return {
    value: lists.value.map(signed),
    damage: lists.damage.map(signed),
    unknown: lists.unknown.map((c) => ({
      moduleId: subject,
      eventType: eventTypeOf(c.kind),
      outcome: c.outcome,
      grade: { lane: c.lane, eg: c.eg },
      bearsOn: [...c.bearsOn],
      ...(c.magnitude === undefined ? {} : { magnitude: { hi: c.magnitude.hi } }),
    })),
  };
}

/**
 * basketClass = "G2_BASKET@" + the first 16 hex of sha256 over
 *   JSON.stringify([ "G2_BASKET_V1", subject, value, damage, unknown, epsilonNum,
 *                    establishAt, creditAt, window, nMin, latchClearedBy ])
 * (contract §4), where each list holds the WIRE objects (fixed key order, each
 * class's bearsOn sorted) SORTED by their own JSON text, and latchClearedBy is
 * sorted the same way. Deterministic, sorted, version-tagged: a reorder of keys,
 * entries or bearsOn keeps it; any field the reader reads moves it.
 *
 * ⚠ WHAT IT DOES NOT COVER, by the contract's formula: `basis`, `proxy`,
 *   `falsifiability` (none reaches the reader) and `frameCategories` (the
 *   frame's own widening is X21's). Those move declarationHash, not this class.
 */
export function gate2BasketClass(subject: string, w: Omit<WireGate2Basket, "basketClass" | "frameCategories">): string {
  const byJson = <T>(xs: readonly T[]): T[] =>
    xs
      .map((x) => [JSON.stringify(x), x] as const)
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map((p) => p[1]);
  const sortedBears = <T extends { bearsOn: readonly string[] }>(xs: readonly T[]): T[] =>
    byJson(xs.map((c) => ({ ...c, bearsOn: [...c.bearsOn].sort() })));
  const input = JSON.stringify([
    GATE2_BASKET_CLASS_VERSION,
    subject,
    sortedBears(w.value),
    sortedBears(w.damage),
    sortedBears(w.unknown),
    w.epsilonNum,
    { lane: w.establishAt.lane, eg: w.establishAt.eg },
    { lane: w.creditAt.lane, eg: w.creditAt.eg },
    { kind: w.window.kind },
    w.nMin,
    byJson(w.latchClearedBy.map((l) => ({ moduleId: l.moduleId, eventType: l.eventType }))),
  ]);
  return `G2_BASKET@${createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16)}`;
}

/**
 * C9, FOUND BY A FAILING TEST AND WORTH THE SCAR TISSUE: `logPath` must be
 * RESOLVED, not taken raw from the declaration.
 *
 * The declaration names `/var/lib/mica-bridge/subject-events.jsonl`. The service
 * rewrites that prefix when `MICA_BRIDGE_STATE_DIR` is set (`resolvePath`), which
 * every test does and a redirected deployment could. This function used to return
 * the raw declared string — harmless while it fed only `/status`'s read-only
 * census, because in production `resolvePath` is the identity. The moment Part D
 * made it the GATE's option builder too, it became a path that points at one file
 * in production and a different, unreadable one anywhere else.
 *
 * The symptom was not a missing file, which is why it is worth naming: the reader
 * came back `verify()` invalid at index -1, Sig reported a BROKEN_CHAIN blind
 * path, the floor went CANNOT_ASSESS, and the disposition was a perfectly
 * ordinary PASS_BLIND. A test asserting "the gate does not close" PASSED — for
 * the wrong reason. Two tests that expected a HOLD are what caught it.
 *
 * `resolveLogPath` defaults to the identity so no existing caller changes
 * behaviour; the service passes its own `resolvePath`.
 */
/**
 * ── T26 · readers.gate4Sunset -> gate 4's profile and K, ONE BUILDER ─────────
 *
 * The served reader's config, minus `readableLoadStates` (the wire's). Undefined
 * when the declaration has no `readers.gate4Sunset` — the reader is then not
 * wired and there is no profile to read. S199: exported so the order writer
 * computes the reader's order bound over exactly this profile.
 *
 * ⛔ R1 · THE PROFILE IS BUILT HERE FROM THE BRIDGE'S OWN KIND CONSTANTS AND
 *    THE DECLARED SUBJECT'S ID. Nothing in the declaration names a class.
 *    Four refusals of this reader came from deployer-typed class lists for
 *    kinds mica-service.ts defines — swapped outcome words, two roles naming
 *    one class, a vacuous `resolved: []` that stopped any order ever closing,
 *    a misdeclared moduleId reading as a missing paper. A PROFILE NOBODY
 *    TYPES CANNOT BE MISTYPED, so N2, N3, N5 and the whole collision door go
 *    away by construction.
 *
 * ⚠ AND THE COLLISION CASE IS NOW STRUCTURAL: these maps are distinct kinds
 *   by construction, so no two roles can name one class unless THIS FILE and
 *   mica-service.ts are changed together — which is a code review, not a
 *   declaration act. The reader keeps its own check anyway (R2): a floor
 *   instrument does not trust its caller.
 *
 * ⚠ ONE INVOCATION CLASS: (declared subject, ENDING_ORDERED). Another subject's
 *   order is therefore NOT an order to the served reader (S199's whole-chain rule
 *   bites only across classes a profile declares).
 */
export function gate4SunsetConfigFor(declarations: Declarations):
  | {
      readonly profile: {
        sunsetResponses: Record<string, readonly { moduleId: string; eventType: string }[]>;
        warrantForm: {
          invocation: readonly { moduleId: string; eventType: string }[];
          papers: Record<string, readonly { moduleId: string; eventType: string }[]>;
        };
      };
      readonly paperFreshnessBound?: number;
    }
  | undefined {
  const gate4 = declarations.readers.gate4Sunset;
  if (gate4 === undefined) return undefined;
  const subject = gate4.subject.value;
  const cls = (eventType: string) => [{ moduleId: subject, eventType }];
  return {
    profile: {
      sunsetResponses: Object.fromEntries(
        Object.entries(GATE4_RESPONSE_ROLE_KINDS).map(([role, kind]) => [role, cls(kind)])
      ),
      warrantForm: {
        invocation: cls(GATE4_INVOCATION_KIND),
        papers: Object.fromEntries(
          Object.entries(GATE4_PAPER_ROLE_KINDS).map(([role, kind]) => [role, cls(kind)])
        ),
      },
    },
    ...(gate4.paperFreshnessBound === undefined ? {} : { paperFreshnessBound: gate4.paperFreshnessBound.value }),
  };
}

export function toWireOptions(
  declarations: Declarations,
  resolveLogPath: (declaredPath: string) => string = (p) => p,
  // ── ACT B · the clerk stamps loader, INJECTED for the same reason
  //    `resolveLogPath` is: this function maps a declaration, it does not do IO.
  //    The bridge passes the real reader; a test passes a fake; absent means the
  //    leg is not configured, which is exactly today's behaviour.
  loadClerkStamps?: (
    resolvedPath: string,
    // SHAPE (b) · the log the READERS stand on, so the loader can ask this
    // bridge's own book whether stamps for THIS chain were ever loaded. Passed
    // rather than re-derived, and passed from the SAME two locals the chain
    // identity is taken from — one resolution, so the witness and the identity
    // cannot come to be about two different chains.
    resolvedLogPath?: string,
    logKind?: string
  ) => NonNullable<NonNullable<WireOptions["sig"]>["clerkClockSource"]>,
  // ── T8 · THE CHAIN IDENTITY THIS RUN EXPECTS, INJECTED FOR THE SAME REASON ──
  //
  //   Under T8 a clerk stamp joins ONLY when it names the chain this run was
  //   told to expect, so `expectedChainIdentity` is no longer an optional extra:
  //   WITHOUT IT F3 REFUSES EVERY STAMP AND GOES BLIND. It is injected rather
  //   than read here because this function maps a declaration and does not do
  //   IO — the same rule `resolveLogPath` and `loadClerkStamps` obey.
  //
  //   ⛔ AND IT IS NOT DECLARABLE, DELIBERATELY. The identity is the position-0
  //   boundary hash of the log the readers read: it CHANGES AT EVERY ROTATION
  //   and it is a fact about the record, not a choice the deployer makes. A
  //   declared copy would be a second answer that goes stale the moment Act A
  //   runs again, and a stale expected identity refuses every stamp of the live
  //   chain while looking perfectly well-formed.
  loadChainIdentity?: (resolvedLogPath: string, logKind: string) => string | undefined,
  // ── LONG RUN A STOP 2 · THE TARGET-SALT EPOCH, INJECTED FOR THE SAME REASON ──
  //   The salt lives in mica-service and never leaves it; the item fingerprints
  //   and the epoch's start come in here as values (see HarmTargetEpoch). Read
  //   only when the Gate-2 subject declares a harm stanza; absent means null
  //   fingerprints and a null saltEpochSince, which the reader reads NOT READABLE.
  harmEpoch?: HarmTargetEpoch | null,
  // S216-2 · THE GRANT MEMORY, INJECTED FOR THE SAME REASON (see HarmGrantMemoryView).
  grantMemory?: HarmGrantMemoryView | null
): WireOptions {
  // C9: eng/sig come from `toSensorConfig`, not from a second hand-written copy
  // of the same mapping. Before Part D this file and that one each projected the
  // declaration's eng/sig block independently; two copies of one mapping is how a
  // census and a gate drift apart one field at a time.
  const sensor = toSensorConfig(declarations);
  // ── ACT B · clerkClockSource, AND THE ONLY WAY IT MAY ARRIVE ────────────────
  //
  //   `to-sensor-config.ts` REFUSES `clerkClockSource` from a config file and
  //   still does: a reader's EVIDENCE is not a declarable value. What is
  //   declarable is the PATH, and `paths.clerkStamps` is where it lives.
  //
  //   ⛔ ABSENT IS TODAY'S BEHAVIOUR, NOT A DEFAULT. No declared path, or no
  //   loader injected, and `sig` is byte-identical to what this function
  //   returned before Act B — F3 reads NOT_CONFIGURED and discloses it. THAT IS
  //   WHY THIS BRIDGE RELAY CHANGES NOTHING ON ITS OWN: the behaviour moves when
  //   a declaration act adds the path, and not when this code lands.
  //
  //   The path goes through `resolveLogPath` for the same reason the log path
  //   does — one resolver, so a test tree and the box differ in one place.
  const declaredStampsPath = declarations.paths.clerkStamps;
  // ⛔ A DECLARED PATH WITH NO LOADER IS A WIRING ERROR, NOT AN ABSENT LEG.
  //
  //   Codex, 2026-09-28. The first version fell through to `sensor.sig` when the
  //   path was declared but no loader had been injected, so F3 read
  //   NOT_CONFIGURED — "no clerkClockSource was injected" — on a deployment that
  //   HAD declared one. The declaration would have said the stamps are read and
  //   the reader would have said nobody configured them, and BOTH would look
  //   ordinary. That is the same shape as the swallowed --log that exits 0
  //   reporting "nothing to do".
  //
  //   A caller that declares the path and omits the loader is miswired, and it
  //   is told so here rather than at the far end of a blind leg.
  if (declaredStampsPath !== undefined && loadClerkStamps === undefined) {
    throw new Error(
      `paths.clerkStamps is declared as ${declaredStampsPath.value} but toWireOptions was called ` +
        `without a clerk-stamps loader. A declared stamps path with no reader is a WIRING ERROR: ` +
        `F3 would report "no clerkClockSource was injected" on a deployment that declared one. ` +
        `Pass loadDeclaredClerkStamps, or do not declare the path.`
    );
  }
  // ── T8 · THE EXPECTED CHAIN IDENTITY, TAKEN FROM THE LOG THE READERS READ ───
  //
  //   Not from `paths.subjectLog` and not from the stamps path: from
  //   `readers.logPath`, resolved, which IS the file Sig reads. Asking a
  //   different file for the identity would compare a stamp against a chain no
  //   reader is standing on.
  //
  //   ⚠ A LOADER THAT RETURNS `undefined` IS NOT AN ERROR HERE. An unchained
  //   `logKind`, an absent log, a chain that did not verify — all of them mean
  //   "there is no identity to expect", and F3's own refusal names that case in
  //   its own words ("NO expectedChainIdentity WAS INJECTED INTO THIS RUN ...
  //   that is a WIRING fault in the caller"). Throwing here would move a
  //   reader's disclosure into a bridge crash.
  const resolvedReaderLogPath = resolveLogPath(declarations.readers.logPath.value);
  const readerLogKind = declarations.readers.logKind.value;
  const expectedChainIdentity =
    loadChainIdentity === undefined
      ? undefined
      : loadChainIdentity(resolvedReaderLogPath, readerLogKind);
  const sigWithIdentity =
    expectedChainIdentity === undefined
      ? sensor.sig
      : { ...sensor.sig, expectedChainIdentity };
  const sigWithStamps =
    declaredStampsPath !== undefined && loadClerkStamps !== undefined
      ? {
          ...sigWithIdentity,
          // SHAPE (b) · THE ERASURE WITNESS IS NOT A DECLARED PATH ANY MORE, AND
          // THAT IS WHY NOTHING ABOUT IT APPEARS HERE. It was `paths.clerkCursor`,
          // an `lstat` on the carrier's own cursor file — and Codex FAILED that on
          // 2026-09-29 because the cursor and the stamps sit in one directory under
          // one principal and are CO-DELETABLE. Under SHAPE (b) the witness is a
          // record the BRIDGE writes in its own hash-chained book, which is not a
          // declaration's business: a deployer does not choose whether the bridge
          // remembers what it saw. The loader this function is handed already
          // carries that answer.
          clerkClockSource: loadClerkStamps(
            resolveLogPath(declaredStampsPath.value),
            resolvedReaderLogPath,
            readerLogKind
          ),
        }
      : sigWithIdentity;
  // ── THE FIVE OPTIONAL READER BLOCKS — four from the bundle, op3 from `opa` ─
  //
  // ONE MECHANISM FOR ALL FIVE, and that is the merge's only real decision here.
  // The two lines each grew their own optional-block path through this function:
  // the bundle line built an `optional` object and spread it, the `opa` line
  // built a standalone `op3` const and spread that. Two spreads would have
  // worked and would have been two places to get "absent stays absent" right.
  // `op3` is therefore a member of `optional` like the other four.
  //
  // ABSENT STAYS ABSENT. Each key is added to `optional` only when the
  // declaration carries the block, and `optional` is SPREAD into the returned
  // object — so an undeclared reader produces NO KEY AT ALL, not a key holding
  // `undefined`. `wire()` gates on `options.narrowW === undefined` and friends,
  // which those two spellings satisfy identically today; the distinction is kept
  // anyway because the census prints what it was handed, and a present-but-
  // undefined field is the shape that reads as configured to anything that
  // enumerates keys.
  //
  // ── THE SPREAD IS ALSO LOAD-BEARING FOR THE BUILD ORDER, AND THAT IS A HOLE
  //    RATHER THAN A DESIGN ──────────────────────────────────────────────────
  //
  // `WireOptions` is imported from `/opt/mica-machine` (through
  // stage1-guard-adapter, the one absolute-path importer). Friday's relay order
  // is MACHINE FIRST, THEN BRIDGE, so by the time this file runs in production
  // `/opt` carries the `narrowW`/`narrowR`/`op1` fields. At BUILD time it does
  // not, and object-spread properties are not subject to excess-property
  // checking, so this compiles against the un-relaid machine. That is convenient
  // and it is the same hole register E11 already names: IT WOULD ALSO HAVE
  // COMPILED A FIELD NAME THAT DOES NOT EXIST. The guard is the relay order and
  // the acceptance step that reads the census, not the compiler. [owed]
  const readers = declarations.readers;
  const optional: {
    narrowK?: { declaredProfile: readonly string[] } & Record<string, unknown>;
    narrowW?: { declaredProfile: readonly string[] } & Record<string, unknown>;
    narrowR?: { declaredProfile: readonly string[] } & Record<string, unknown>;
    // narrow-T is NOT `& { declaredProfile }` — it has no declared class. See
    // `Declarations["readers"].narrowT`. It is bare numbers, and today it is
    // handed to a `wire()` that does not look for it; the key is emitted anyway
    // so that the machine-side gate, when it lands, finds the option already
    // arriving rather than a second bridge relay standing between it and use.
    narrowT?: Record<string, number>;
    // H12 · op3's WINDOW, and it is TOP-LEVEL rather than a member of `op3`
    // BY DESIGN: op3 must not learn about this deployment's record. The
    // instrument takes a profile; the window is a fact about which rows this
    // deployment can honestly pair, so it travels BESIDE the profile and the
    // instrument's own type never grows a field about our ACT_CLOSED history.
    op3Since?: number;
    // T26 · gate 4's profile, shaped exactly as `Gate4SunsetProfile`, and NO
    // window: the reader derives it. `gate4HoldWindow` was removed from
    // `WireOptions` in the same act, so if this mapping ever grows one the
    // compiler on a relaid machine refuses it — which is the only guard that
    // does not depend on somebody remembering.
    gate4?: {
      sunsetResponses: Record<string, readonly { moduleId: string; eventType: string }[]>;
      warrantForm: {
        invocation: readonly { moduleId: string; eventType: string }[];
        papers: Record<string, readonly { moduleId: string; eventType: string }[]>;
      };
    };
    gate4PaperFreshnessBound?: number;
    op1?: { attestationClass: { moduleId: string; eventType: string }; cadenceBoundSteps?: number };
    // GATE 1 · Stop 2 · shaped exactly as the machine's `Gate1ScopeFrame`.
    gate1?: {
      categories: readonly { id: string; self: boolean; derivable: boolean }[];
      labelClass: { moduleId: string; eventType: string };
      underivedWord: string;
    };
    // GATE 1 · round 2 · the interest book the reader reads, RESOLVED like
    // `logPath` (the service's `resolvePath`), so the reader opens the file the
    // writer writes and not its declared spelling under a redirected state dir.
    gate1BookPath?: string;
    // GATE 2 · Stop 2 · shaped exactly as the machine's `Gate2Basket` (contract §1).
    gate2?: WireGate2Basket;
    // TIER 1 · the witness's book Gate 2 reads, RESOLVED like `logPath`; present
    // only when readers.gate2Direction.book says so. The installed machine before
    // the witness build ignores it (and then reads logFile) — the relay order
    // (machine first) is the guard, as for `gate2` itself.
    gate2BookPath?: string;
    // LONG RUN A STOP 2 · HARM MODE (contract M3), all three only when the Gate-2
    // subject declares a harm stanza — and then NO `gate2` (the two are exclusive).
    gate2Harm?: WireGate2Harm;
    // The interest book (paths.interestBook, resolved): the act ROSTER, never effects.
    gate2RosterPath?: string;
    // The deciding act's actionId: null here (a status read); wireOptionsFor sets it per /guard.
    gate2DecidingActionId?: string | null;
    // The word the bridge writes into the interest book for an act placed in no
    // frame category — INTEREST_UNDERIVED (interest-label.ts), the SAME constant
    // gate1's `underivedWord` carries — so the reader never compares the roster
    // label against a literal of its own.
    gate2UnderivedWord?: string | null;
    op3?: {
      expectationClass: { moduleId: string; eventType: string };
      responseClass: { moduleId: string; eventType: string };
      responseBoundSteps: number;
      flatness?: { amiFloor: number; amiCeilingMargin: number; minSample: number };
    };
  } = {};
  // The envelope is stripped here and ONLY here: the instruments take bare
  // numbers and lists, the declaration carries `{value, basis, proxy}`, and the
  // basis does not travel into the reader — it stays in the declaration, which
  // is the thing an operator reads.
  const unwrapProfile = (
    block: Record<string, { value: unknown } | undefined>
  ): { declaredProfile: readonly string[] } & Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const [key, declared] of Object.entries(block)) {
      if (declared !== undefined) out[key] = declared.value;
    }
    return out as { declaredProfile: readonly string[] } & Record<string, unknown>;
  };
  if (readers.narrowK !== undefined) {
    optional.narrowK = unwrapProfile(readers.narrowK as unknown as Record<string, { value: unknown } | undefined>);
  }
  if (readers.narrowW !== undefined) {
    optional.narrowW = unwrapProfile(readers.narrowW as unknown as Record<string, { value: unknown } | undefined>);
  }
  if (readers.narrowR !== undefined) {
    optional.narrowR = unwrapProfile(readers.narrowR as unknown as Record<string, { value: unknown } | undefined>);
  }
  if (readers.narrowT !== undefined) {
    // Same envelope-stripping as the three profiles above, and the same spread
    // discipline. `readers.sig.clerkStampLag` is deliberately NOT carried here:
    // it is a disclosure about what a promoted F3 means, not a parameter any
    // instrument takes. Adding it to the wire would invent a consumer.
    const t: Record<string, number> = {};
    for (const [key, declared] of Object.entries(readers.narrowT)) {
      if (declared !== undefined) t[key] = declared.value;
    }
    optional.narrowT = t;
  }
  if (readers.doctorCadence !== undefined) {
    optional.op1 = {
      attestationClass: readers.doctorCadence.attestationClass.value,
      ...(readers.doctorCadence.cadenceBoundSteps === undefined
        ? {}
        : { cadenceBoundSteps: readers.doctorCadence.cadenceBoundSteps.value }),
    };
  }
  // ── T26 · readers.gate4Sunset -> WireOptions.gate4 ────────────────────────
  //
  // `.value` only, as everywhere else here. Absent declaration, ABSENT KEY —
  // `wire()` gates on `options.gate4 === undefined` and pushes an UNWIRED census
  // row carrying GATE4_NOT_DECLARED, so an undeclared gate 4 yields the
  // byte-identical options object this function yielded before T26.
  //
  // ⚠ AND NOTHING HERE CARRIES A WINDOW. That is not an omission to be tidied up
  //   later: the reader derives the window from the record, and the predecessor's
  //   declared window is the defect T26 exists for.
  // S199 · built by `gate4SunsetConfigFor` below — the SAME builder the order
  // writer (mica-service.ts, the ENDING_ORDERED admit path) hands to the
  // reader's `gate4OrderBound`, so the bound the writer refuses by is computed
  // over the profile the reader reads, not a second spelling of it.
  const gate4 = gate4SunsetConfigFor(declarations);
  if (gate4 !== undefined) {
    optional.gate4 = gate4.profile as never;
    if (gate4.paperFreshnessBound !== undefined) {
      optional.gate4PaperFreshnessBound = gate4.paperFreshnessBound;
    }
  }

  // ── GATE 1 · Stop 2 · readers.gate1Scope + frame[subject] -> WireOptions.gate1
  //                                     + paths.interestBook -> gate1BookPath
  //
  // The gate4Sunset (R1) pattern: the block names a SUBJECT and nothing else,
  // and the profile is built here from the bridge's own constants and the
  // declared frame. Nothing in the declaration names the label class, so it
  // cannot be mistyped: it is (subject, frameLabelEventType(frame[subject])),
  // which is exactly the (moduleId, eventType) mica-service files each label
  // under in the interest book.
  //
  // ROUND 2 · THE CLASS IS FRAME-SCOPED (placement D; review C2-2, C2-3). It
  // names the derivation that produced a label — round 3 (B1): the derivation
  // rules' version, the canonicaliser's version and the regions as (prefix,
  // category) pairs; category ids enter only through their regions. A label
  // written under an earlier derivation is another class and is NOT counted
  // against today's frame, so `derivable` (computed from today's regions) and
  // the cases (derived under today's regions and rules) describe ONE
  // derivation. A wording edit (labels, groundings, basis, proxy, self) and a
  // new category with no region do not move the class.
  //
  // `derivable` is computed, not declared: a category no region maps to can
  // never receive a label, and the reader prints it as NOT READABLE rather than
  // as an unreached category. Saying "0 cases" about a category the bridge
  // CANNOT label would read as the subject having stayed out of it.
  // ROUND 3 (B2; review K1R1-2, belt and braces with the loader's A2 rule):
  // "some region names c" was not enough — a region whose prefix holds a
  // not-a-path segment (`/srv/-scratch`, `Program Files (x86)`) places NOTHING,
  // because the deriver refuses every target under it, yet it counted c
  // derivable. So derivable now asks THE WRITER'S OWN DERIVER: some region r of
  // c whose own prefix, handed in as both canonical and raw target, derives c.
  // A region always wins at its own prefix (longest match; prefixes are unique
  // on a loaded declaration), so this is true exactly when r can place anything.
  // The loader refuses such prefixes now; this keeps the flag honest for a
  // Declarations that reached here some other way, and for any later rule the
  // deriver gains before the door does.
  //
  // ABSENT BLOCK, ABSENT KEYS — `wire()` gates on `options.gate1 === undefined`
  // and an undeclared reader yields the byte-identical options object. A frame
  // WITHOUT the block switches nothing on here (the bridge still writes its
  // labels; nobody reads them).
  //
  // ⚠ THE LOADER (X20, X22) GUARANTEES `frame[subject]` AND `paths.interestBook`
  //   EXIST WHEN THE BLOCK DOES. This function does not re-check them and would
  //   throw on a hand-built Declarations that skipped the loader — loudly, at
  //   wiring, which is the right place for a declaration the front door never saw.
  // ⚠ `.value` only, as everywhere else here: labels, groundings, `basis` and
  //   `proxy` stay in the declaration, which is what an operator reads. The
  //   reader needs ids, the self flag and derivability, and nothing more.
  const gate1 = readers.gate1Scope;
  if (gate1 !== undefined) {
    const subject = gate1.subject.value;
    const frame = declarations.frame![subject];
    optional.gate1 = {
      categories: frame.categories.value.map((c) => ({
        id: c.id,
        self: c.self,
        derivable: frame.regions.value.some(
          (r) => r.category === c.id && deriveInterestLabel(r.prefix, frame.regions.value, r.prefix) === c.id
        ),
      })),
      labelClass: { moduleId: subject, eventType: frameLabelEventType(frame) },
      underivedWord: INTEREST_UNDERIVED,
    };
    optional.gate1BookPath = resolveLogPath(declarations.paths.interestBook!);
  }

  // ── GATE 2 · Stop 2 · readers.gate2Direction + baskets[subject] + frame[subject]
  //                                     -> WireOptions.gate2
  //
  // The gate1Scope pattern: the block names a SUBJECT and nothing else; the
  // basket and the frame are the declaration's, keyed by that subject. Every
  // class key's moduleId is the subject, BY USE — nothing in the declaration
  // names a moduleId, so a class cannot name another subject's records.
  //
  // `.value` only: basis, proxy and falsifiability stay in the declaration,
  // which is what an operator reads. frameCategories is frame M's ids for the
  // subject, in declared order — the ids every class's bearsOn names (R12).
  //
  // ABSENT BLOCK, ABSENT KEY — `wire()` gates on `options.gate2 === undefined`
  // (contract §5) and an undeclared reader yields the byte-identical options
  // object. A basket WITHOUT the block switches nothing on here.
  //
  // ⚠ THE LOADER (R1) GUARANTEES `frame[subject]` AND `baskets[subject]` EXIST
  //   WHEN THE BLOCK DOES. Not re-checked: a hand-built Declarations that skipped
  //   the front door throws here, at wiring, loudly.
  const gate2 = readers.gate2Direction;
  // LONG RUN A STOP 2 · HARM MODE FIRST. When the Gate-2 subject declares a harm
  // stanza (H9: then it declares no basket) the reader is handed the stanza, the
  // book, the roster and the deciding act — and NO `gate2`: `gate2` and
  // `gate2Harm` together are a WireUsageError on the machine (M3).
  // ⚠ THE LOADER GUARANTEES the book (H8), its method, paths.witnessBook (R16)
  //   and paths.interestBook (H1 needs a frame; X22 needs the book for a frame).
  //   Not re-checked: a hand-built Declarations that skipped the door throws here.
  const harmStanza =
    gate2 !== undefined && declarations.harm !== undefined && Object.hasOwn(declarations.harm, gate2.subject.value)
      ? declarations.harm[gate2.subject.value]
      : undefined;
  if (gate2 !== undefined && harmStanza !== undefined) {
    optional.gate2Harm = gate2WireHarm(gate2.subject.value, harmStanza, harmEpoch, grantMemory);
    optional.gate2BookPath = resolveLogPath(declarations.paths.witnessBook!.value);
    optional.gate2RosterPath = resolveLogPath(declarations.paths.interestBook!);
    optional.gate2DecidingActionId = null;
    optional.gate2UnderivedWord = INTEREST_UNDERIVED;
  } else if (gate2 !== undefined) {
    const subject = gate2.subject.value;
    const basket = declarations.baskets![subject];
    // TIER 1 · ON THE WITNESS'S BOOK every class's kind is CONSEQUENCE (the loader
    // allows nothing else there), and its record class is named from the
    // declared METHOD and THIS frame's derivation class — the same class the
    // label site files the act's label under — so a re-drawn frame or another
    // method opens another class and old records are not summed with new ones.
    const onBook = gate2.book !== undefined && gate2.witnessMethod !== undefined;
    const bookClass = onBook
      ? witnessRecordClass(gate2.witnessMethod!.value, frameLabelEventType(declarations.frame![subject]))
      : null;
    const lists = gate2WireLists(subject, basket, bookClass === null ? undefined : () => bookClass);
    const rest = {
      ...lists,
      epsilonNum: basket.epsilonNum.value,
      establishAt: { lane: basket.grades.value.establishAt.lane, eg: basket.grades.value.establishAt.eg },
      creditAt: { lane: basket.grades.value.creditAt.lane, eg: basket.grades.value.creditAt.eg },
      window: { kind: "sinceBoundary" as const },
      nMin: basket.nMin.value,
      latchClearedBy: basket.latchClearedBy.value.map((l) => ({ moduleId: subject, eventType: l.kind })),
    };
    optional.gate2 = {
      basketClass: gate2BasketClass(subject, rest),
      frameCategories: declarations.frame![subject].categories.value.map((c) => c.id),
      value: rest.value,
      damage: rest.damage,
      unknown: rest.unknown,
      epsilonNum: rest.epsilonNum,
      establishAt: rest.establishAt,
      creditAt: rest.creditAt,
      window: rest.window,
      nMin: rest.nMin,
      latchClearedBy: rest.latchClearedBy,
    };
    if (onBook) optional.gate2BookPath = resolveLogPath(declarations.paths.witnessBook!.value);
  }

  // ── H12 · readers.nodeResponse -> WireOptions.op3 ─────────────────────────
  //
  // THE ONE RULE THIS MAPPING MUST NOT BREAK: absent declaration, ABSENT FIELD.
  // Not `op3: undefined` with a comment beside it — `wire()` gates on
  // `options.op3 === undefined`, so the two are equivalent to it today, but
  // this object is also the one place the census and the gate are held to the
  // same reading, and a key that is present-and-undefined is the first step
  // toward a key that is present-and-something. Built by spread, so the
  // undeclared case yields the byte-identical object this function yielded
  // before H12 existed.
  //
  // `.value` only, as everywhere else here: `basis` is the deployer's stated
  // reasoning, read by the declaration hash and by no instrument.
  const nodeResponse = readers.nodeResponse;
  if (nodeResponse !== undefined) {
    optional.op3 = {
      expectationClass: nodeResponse.expectationClass.value,
      responseClass: nodeResponse.responseClass.value,
      responseBoundSteps: nodeResponse.responseBoundSteps.value,
      ...(nodeResponse.flatness === undefined
        ? {}
        : {
            flatness: {
              amiFloor: nodeResponse.flatness.amiFloor.value,
              amiCeilingMargin: nodeResponse.flatness.amiCeilingMargin.value,
              minSample: nodeResponse.flatness.minSample.value,
            },
          }),
    };
    // ── H12 · readers.nodeResponse.since -> WireOptions.op3Since ─────────────
    //
    // ABSENT DECLARATION, ABSENT FIELD — the same rule as `op3` itself, and for
    // the same reason: `wire()` gates on `options.op3Since === undefined`, and a
    // key that is present-and-undefined is the first step toward a key that is
    // present-and-something.
    //
    // ⚠ IT IS SET ONLY INSIDE THIS BRANCH. A `since` without a `nodeResponse`
    // would be a window on a reader that is not declared — the front door
    // cannot produce that shape (since lives under nodeResponse), and nesting
    // the assignment here means a later refactor cannot produce it either.
    const declaredSince = (nodeResponse as { since?: { value: number } }).since;
    if (declaredSince !== undefined) {
      optional.op3Since = declaredSince.value;
    }
  }
  return {
    logPath: resolveLogPath(declarations.readers.logPath.value),
    logKind: declarations.readers.logKind.value,
    readableLoadStates: declarations.readers.readableLoadStates.value,
    eng: sensor.eng,
    sig: sigWithStamps,
    ...optional,
  };
}
