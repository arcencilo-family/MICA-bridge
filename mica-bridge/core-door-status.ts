// ── core-door-status — the `door` section of `/status`: a census of the ──
// ── core door, never a verdict about it ───────────────────────────────────
//
// ARC_MICA-BRIEF_Status-Door_20260922. `/status` reports what the core door
// (`/opt/mica-machine/src/core-door/core-door.ts`) says about itself right
// now — CLOSED, OPEN under named tickets, or REFUSED — plus a fourth word
// this bridge adds, UNREADABLE, for when the door cannot be consulted at
// all. It never gates anything; see mica-service.ts's own "census, never a
// verdict" rule, which this section is bound by exactly as every other row
// in `/status` is.
//
// ── WHY THIS FILE, AND NOT stage1-guard-adapter.ts ────────────────────────
//
// stage1-guard-adapter.ts's header is explicit: it is "the ONE file that
// imports mica-machine's glue by absolute path", done EAGERLY, at module top
// level, on purpose — a `TSError` there must stop the unit at ExecStart,
// never surface as a 500 mid-request, because `/guard` cannot honestly serve
// anything if evaluateAndRecord is unavailable. That is the right rule for
// every surface `/guard` and `/subject-events` depend on to function AT ALL.
//
// The core door is not one of those surfaces, and constraint #2 of the brief
// asks for the OPPOSITE failure behaviour: "a door that cannot be read is
// reported as unreadable, never as CLOSED" and "/status itself must still
// answer 200 — a census endpoint must not 500 on one bad row." `core-door.ts`
// is also, concretely, the newest surface this bridge touches (its own
// header is dated the same day as this brief) — a release-order skew where
// `/opt/mica-machine` has shipped everything `/guard` needs but not yet this
// file is a real near-term shape, not a hypothetical.
//
// So this file's ONE `/opt/mica-machine` import is deliberately LAZY — a
// function-scoped `require()`, never a module-top-level `import` of a VALUE
// — and it is the only other place in this codebase that names
// `/opt/mica-machine` by absolute path. `import type` below is compile-time
// only (erased before emit; no runtime `require` results from it), so taking
// the door's real types costs nothing at runtime and does not weaken the
// lazy-load: a tree that has the .ts file for `tsc`/`ts-node` to type-check
// against but fails to `require()` it at run time (or never did, in a build
// that only ships .js) still degrades to UNREADABLE cleanly.
import { readFileSync } from "fs";
import { join } from "path";
import type { DoorResult, Ticket } from "/opt/mica-machine/src/core-door/core-door";

export interface DoorTicketSummary {
  readonly id: string;
  readonly opens: readonly string[];
  readonly expiresAt: string;
}

export interface DoorSection {
  /** The door's own three words, plus this bridge's fourth for "could not ask it at all". */
  readonly state: "CLOSED" | "OPEN" | "REFUSED" | "UNREADABLE";
  /** null when the door did not reach a pin count (REFUSED, UNREADABLE). */
  readonly pinnedFileCount: number | null;
  /** The door's own shippable bit, copied verbatim — a fact about the pins, not a verdict this endpoint renders. */
  readonly shippable: boolean | null;
  readonly baseline: { readonly commit: string; readonly pinnedOn: string } | null;
  /** null when the inventory could not be independently re-read (see `InventoryPeek`). */
  readonly repinCount: number | null;
  readonly liveTickets: readonly DoorTicketSummary[];
  /** Live-ticket-covered drift not yet re-pinned (OPEN, NOT SHIPPABLE only) — the door's own words, verbatim. */
  readonly unpinnedDrift: readonly string[];
  /** The door's own refusal reasons, verbatim, including any drifted file it refuses (REFUSED only). */
  readonly refused: readonly string[];
  /** Carried verbatim from the door. null only when the door could not be read at all. */
  readonly authorshipNotVerified: string | null;
  /** The UNREADABLE reason, verbatim. null in every other state. */
  readonly detail: string | null;
  /** How long this read took, wall-clock, this call — the honest answer to "measure the cost". */
  readonly readMs: number;
}

/**
 * The independently re-read baseline/repin facts. `DoorResult` itself does
 * not carry the baseline commit or a repin COUNT as structured fields — only
 * as prose inside `lines` (see core-door.ts's own `DoorResult` type: CLOSED
 * and OPEN carry `pinned`/`live`/`unpinnedDrift`, nothing named `baseline`).
 * `parseInventory`/`INVENTORY_REL` are the door's own exported primitives,
 * not a re-implementation of its parsing, so this is the same read the door
 * itself just did, taken again through the same code. Best-effort: if this
 * second read fails for any reason, the door's own verdict above still
 * stands and this is simply `null` — never a reason to downgrade `state`.
 */
export interface InventoryPeek {
  readonly commit: string;
  readonly pinnedOn: string;
  readonly repins: number;
}

/** The structural shape this file depends on from the door module — see the header for why this is `import type`, not a runtime import. */
export interface CoreDoorProbe {
  readonly evaluateRealDoor: (repoRoot: string, now?: Date) => DoorResult;
  readonly parseInventory: (raw: string) => {
    readonly baseline: { readonly commit: string; readonly pinnedOn: string };
    readonly repins: readonly unknown[];
  };
  readonly AUTHORSHIP_NOT_VERIFIED: string;
  readonly INVENTORY_REL: string;
}

export type DoorReadResult =
  | {
      readonly kind: "READ";
      readonly door: DoorResult;
      readonly authorshipNotVerified: string;
      readonly inventoryPeek: InventoryPeek | null;
      readonly readMs: number;
    }
  | { readonly kind: "UNREADABLE"; readonly reason: string; readonly readMs: number };

/** The default, real loader — a lazy `require()`, on purpose (see this file's header). */
function loadCoreDoorModule(): CoreDoorProbe {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require("/opt/mica-machine/src/core-door/core-door") as CoreDoorProbe;
}

/**
 * Reads the core door fresh, every call — no caching. Constraint #3 of the
 * brief: a cache's lifetime would have to be bounded by a ticket's
 * `expiresAt`, and the simplest way to honour "the door's reading depends on
 * the clock" exactly is to not have a cache to bound. Cost is measured, not
 * assumed: `readMs` is this call's own wall-clock time, and see the receipt
 * for a standalone measurement against the live tree (median ~20ms over the
 * real 81-file baseline, 25 runs) — negligible against a 30s poll.
 *
 * `loadModule` is the seam a test uses to prove the UNREADABLE path (a
 * loader that throws — module missing/unparseable) and the "door throws"
 * path (a loader that returns a working module whose `evaluateRealDoor`
 * throws) without touching the filesystem at all, and to prove the door is
 * read fresh (an injected `evaluateRealDoor` whose answer depends on the
 * `now` it is actually called with) against a REAL `evaluateDoor` run over a
 * scratch tree this bridge does not own (constraint #6: never the live
 * `/opt` state as the only fixture).
 */
export function readCoreDoor(repoRoot: string, now: Date, loadModule: () => CoreDoorProbe = loadCoreDoorModule): DoorReadResult {
  const t0 = process.hrtime.bigint();
  const readMs = (): number => Number(process.hrtime.bigint() - t0) / 1e6;

  let mod: CoreDoorProbe;
  try {
    mod = loadModule();
  } catch (err) {
    return { kind: "UNREADABLE", reason: `core-door module unavailable: ${err instanceof Error ? err.message : String(err)}`, readMs: readMs() };
  }

  let door: DoorResult;
  try {
    door = mod.evaluateRealDoor(repoRoot, now);
  } catch (err) {
    return { kind: "UNREADABLE", reason: `evaluateRealDoor threw: ${err instanceof Error ? err.message : String(err)}`, readMs: readMs() };
  }

  let inventoryPeek: InventoryPeek | null = null;
  try {
    const raw = readFileSync(join(repoRoot, mod.INVENTORY_REL), "utf8");
    const inv = mod.parseInventory(raw);
    inventoryPeek = { commit: inv.baseline.commit, pinnedOn: inv.baseline.pinnedOn, repins: inv.repins.length };
  } catch {
    inventoryPeek = null; // best effort only — the door's own verdict above already stands without it.
  }

  return { kind: "READ", door, authorshipNotVerified: mod.AUTHORSHIP_NOT_VERIFIED, inventoryPeek, readMs: readMs() };
}

function ticketSummaries(tickets: readonly Ticket[]): readonly DoorTicketSummary[] {
  return tickets.map((t) => ({ id: t.id, opens: t.opens, expiresAt: t.expiresAt }));
}

function driftLine(d: { readonly path: string; readonly pinned: string | null; readonly onDisk: string | null }): string {
  return `${d.path}: pinned ${d.pinned ?? "(absent)"}, on disk ${d.onDisk ?? "(absent)"}`;
}

/** Pure — no I/O. Shapes a `DoorReadResult` into the JSON `/status.door` actually serves. */
export function buildDoorSection(read: DoorReadResult): DoorSection {
  const baseline = read.kind === "READ" && read.inventoryPeek !== null ? { commit: read.inventoryPeek.commit, pinnedOn: read.inventoryPeek.pinnedOn } : null;
  const repinCount = read.kind === "READ" && read.inventoryPeek !== null ? read.inventoryPeek.repins : null;

  if (read.kind === "UNREADABLE") {
    return {
      state: "UNREADABLE",
      pinnedFileCount: null,
      shippable: null,
      baseline: null,
      repinCount: null,
      liveTickets: [],
      unpinnedDrift: [],
      refused: [],
      authorshipNotVerified: null,
      detail: read.reason,
      readMs: read.readMs,
    };
  }

  const { door } = read;
  if (door.kind === "CLOSED") {
    return {
      state: "CLOSED",
      pinnedFileCount: door.pinned,
      shippable: door.shippable,
      baseline,
      repinCount,
      liveTickets: [],
      unpinnedDrift: [],
      refused: [],
      authorshipNotVerified: read.authorshipNotVerified,
      detail: null,
      readMs: read.readMs,
    };
  }
  if (door.kind === "OPEN") {
    return {
      state: "OPEN",
      pinnedFileCount: door.pinned,
      shippable: door.shippable,
      baseline,
      repinCount,
      liveTickets: ticketSummaries(door.live),
      unpinnedDrift: door.unpinnedDrift.map(driftLine),
      refused: [],
      authorshipNotVerified: read.authorshipNotVerified,
      detail: null,
      readMs: read.readMs,
    };
  }
  // REFUSED
  return {
    state: "REFUSED",
    pinnedFileCount: null,
    shippable: false,
    baseline,
    repinCount,
    liveTickets: [],
    unpinnedDrift: [],
    refused: door.reasons,
    authorshipNotVerified: read.authorshipNotVerified,
    detail: null,
    readMs: read.readMs,
  };
}
