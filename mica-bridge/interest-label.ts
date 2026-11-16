// ── interest-label — Gate 1's touch label, derived by the bridge ────────────
//
// GATE 1 · Stop 2. Canon 03b §2: Gate 1 reads the WEIGHT distribution over a
// declared frame M, revealed under cost. What this deployment can record is
// narrower, and this file is where the narrowing happens, so it is named here:
//
//   the bridge places each TOOL_ATTEMPTED's OWN CLAIMED TARGET (R6's
//   targetIdentity, canonicalised) into one of the declared frame's REGIONS,
//   and writes that region's category id into the INTEREST BOOK — a separate
//   chained file that nothing in this code but Gate 1 reads (placement D,
//   round 2; nothing enforces that beyond the loader's X23, which keeps
//   readers.logPath off it). The subject chain's own TOOL_ATTEMPTED outcome
//   is NOT touched: it stays the toolName, so no sibling reader sees anything
//   new.
//
// That is REACH / EXPOSURE (03a §1) — which declared region an act was pointed
// at — and NEVER weight. The machine-side reader counts these labels against M
// and its weight leg is CANNOT_ASSESS by construction.
//
// ⛔ WHAT THE LABEL IS NOT, at true width:
//    · not "whose interests mattered": a region is a declared PROXY for a
//      category, not ownership (S160: owner ≠ who matters);
//    · not "what changed": the label is derived at ATTEMPT, before any
//      decision, so a held act carries one too (attempted ≠ changed);
//    · not a fact about the world: the target is the HARNESS'S OWN CLAIM (its
//      first path-like token). This function gives a TRUE label of a POSSIBLY
//      FALSE claim, and it does not check the claim — it cannot: the bridge runs
//      with ProtectHome=yes and PrivateTmp=yes, and a label that depended on what
//      the bridge could stat would depend on the bridge's sandbox, not on the act.
//
// ⛔ PURE. No fs, no clock, no I/O, no imports at runtime. The plain target
//    arrives canonicalised (and, optionally, raw — see R-c on the function) and
//    leaves as a category id or one fixed word; the string is never stored,
//    echoed or logged here, which is what lets mica-service call this inside
//    the R6 block without widening where the plain lives.
//
// ⚠ THE COST OF REFUSING TO GUESS: every target this function cannot place
//   honestly reads INTEREST_UNDERIVED — a bare program word, a path through
//   "." or "..", an absent target, a target outside every region, a raw target
//   the canonicaliser had to rewrite into another file's name, a segment shaped
//   like a URL, a host:port, an scp/git remote, a flag, a redirect or a quoted
//   argument (since S211, all but ONE matching pair of quotes around an
//   otherwise-absolute path — see `unquoteOnePair`) — and, since round 3, a REAL file whose name holds a ":" (the
//   price of not placing `host:path` in the caller's home). The reader
//   counts those separately and prints them; they lower the envelope's coverage
//   rather than inflating some category's count.

// TYPE-ONLY: erased at compile time, so mica-service -> interest-label stays a
// one-way runtime edge (no cycle). It makes the label kind a member of the
// bridge's own closed kind alphabet, checked by the compiler.
import type { SubjectEventKind } from "./mica-service";

/**
 * The word written for an act whose target could not be placed in any declared
 * region. NEVER a category id — the front door refuses a category of this name
 * (declarations.ts spells the same word as a literal, for the import-cycle reason
 * given there; interest-label.test.ts holds the two together by behaviour).
 */
export const INTEREST_UNDERIVED = "UNDERIVED";

/**
 * The kind whose target is labelled. ROUND 2 (placement D): the label no longer
 * rides on this kind's own `outcome` — that masked Eng and let pre-frame
 * outcomes collide with category ids. It is written to the interest book, one
 * book record per TOOL_ATTEMPTED that persisted; the book record's class is
 * frame-scoped and lives in interest-book.ts, not here.
 */
export const GATE1_LABEL_KIND: SubjectEventKind = "TOOL_ATTEMPTED";

/**
 * THE DERIVATION RULES' VERSION. A positive integer, bumped whenever a change to
 * this file can change WHICH label some target gets under an unchanged frame
 * (a new not-a-path shape, a new dot rule, a new raw-target rule). Exported so
 * the book's label class can carry it (interest-book.ts): labels derived under
 * different rules must not be summed as one derivation.
 *   1 — round 1: prefixes, dot segments.
 *   2 — round 2: + the not-a-path shapes (a trailing ":" only), + R-c.
 *   3 — round 3: a ":" ANYWHERE in a segment is not a path (host:port,
 *       user@host:path, git remotes) — review K2W-1.
 *   4 — S211: ONE matching pair of quotes around an otherwise-absolute path
 *       is stripped before the shape refusal (`unquoteOnePair`). A new label
 *       class: the envelope restarts under it.
 */
export const INTEREST_DERIVATION_VERSION = 4;

/** One declared region: a path prefix and the category id it stands for. Structurally `FrameRegion`. */
export interface FrameRegionRule {
  readonly prefix: string;
  readonly category: string;
}

/** A path SEGMENT that the canonical form keeps but does not resolve. */
function hasDotSegment(path: string): boolean {
  return path.split("/").some((seg) => seg === "." || seg === "..");
}

/**
 * Could this prefix be matched honestly? The front door (declarations.ts,
 * `framePrefixDefect`) refuses every prefix this rejects, so on a loaded
 * declaration this never fires. It is here because this function is exported
 * and pure: a caller that hands it rules WITHOUT the loader must not get a
 * label out of a prefix like "" (which, joined with "/", would claim every
 * absolute path) or "/srv/" (which would never match and look like it did).
 * A malformed rule is SKIPPED — it places nothing — never repaired.
 */
function prefixIsMatchable(prefix: unknown): prefix is string {
  if (typeof prefix !== "string") return false;
  if (prefix === "/") return true;
  if (!prefix.startsWith("/")) return false;
  if (prefix.includes("//")) return false;
  if (prefix.endsWith("/")) return false;
  return !hasDotSegment(prefix);
}

/**
 * A SEGMENT SHAPED LIKE SOMETHING THAT IS NOT A PATH. The caller's resolver
 * takes the first token that CONTAINS a "/" and joins a non-absolute one onto
 * its own cwd (the harness's resolveTargetIdentity; measured 2026-10-08: the
 * served caller's cwd and HOME are an operator's home directory). So a URL, a
 * host:port, an scp/rsync/git remote, a flag with a value, a redirect, a quoted
 * or a variable argument all ARRIVE AS PATHS UNDER THAT HOME —
 * `curl https://h/x` -> `<home>/https:/h/x`, `curl localhost:8080/api` ->
 * `<home>/localhost:8080/api`, `git clone git@host:org/repo` ->
 * `<home>/git@host:org/repo`, `cmd 2>/dev/null` -> `<home>/2>/dev/null`.
 * A region over the home would then place a network act, a remote, a redirect
 * or a flag into the home's category: a FALSE label, not a missing one. A
 * segment is refused when it
 *   · holds a ":" ANYWHERE           (a URL scheme `https:`, `host:port`,
 *                                      `[::1]:80`, scp/rsync `host:path`,
 *                                      `user@host:path`, `user:pw@host`) —
 *                                      round 3, review K2W-1. Round 2 refused
 *                                      only a TRAILING ":", which caught scp's
 *                                      `host:` only when the remote path was
 *                                      absolute; that claim is withdrawn.
 *   · holds WHITESPACE                (only a direct POST can carry one: R6's
 *                                      canonVersion 1 target is a whitespace-
 *                                      split token; round 3, NEW-K1R-1)
 *   · starts with "-", "+" or "~"     (a flag, a `date +%Y/…` format, `~user`)
 *   · holds a shell metacharacter     (quote, backtick, `$`, `=`, `<`, `>`, `|`,
 *                                      `;`, `&`, `(`, `)`, `{`, `}`, backslash)
 * ⚠ THE COST, CHOSEN: a REAL file or directory whose name holds a ":" (a
 *   timestamped `run:12`, `node:20`) now reads UNDERIVED, and the front door
 *   refuses a region prefix with such a segment (declarations.ts imports this
 *   same predicate). UNDERIVED lowers the coverage; a false category inflates
 *   one. This file chooses the first, as everywhere else.
 * ⚠ "@" ALONE IS NOT IN THE SET. `node_modules/@types/x` and npm scopes are real
 *   paths; an "@" is refused only together with a ":" (the remote forms above).
 *   So `curl -d @/tmp/f` (-> `<home>/@/tmp/f`) and `npm install @scope/pkg` are
 *   still placed under the home — part of the residual below.
 * ⚠ RESIDUAL, NOT FIXABLE HERE: an argument that merely CONTAINS a slash and
 *   has none of these shapes (`echo a/b`, `@scope/pkg`, `sed s/a/b/ f`,
 *   `ls #/x`) still lands under the caller's cwd, and so does a token whose
 *   non-path part the CALLER'S OWN ".." normalisation erased before the bridge
 *   saw it (`$HOME/../x` arrives as a clean `<home>/x`). The bridge cannot tell
 *   either from a relative path, because each arrives as one. That is disclosed
 *   in the reader's ceiling, not hidden behind this rule.
 * Glob metacharacters (`*`, `?`, `[`) are NOT in the set — see below.
 */
// \s (round 3 re-verify, NEW-K1R-1): R6's canonVersion 1 target is a
// WHITESPACE-SPLIT token, so no conforming caller sends one with a space in it;
// only a direct POST can, and a prefix with one is a region no caller reaches.
const NOT_A_PATH_SEGMENT = /:|\s|^[-+~]|["'`$=<>|;&(){}\\]/;

/**
 * Pure, exported: is this ONE path segment shaped like a non-path token? The
 * empty segment (between "//", or before the leading "/") is not. ONE
 * PREDICATE, TWO USERS: the label rule below and the front door's region-prefix
 * rule (declarations.ts framePrefixDefect), so a region the door admits is a
 * region this function can place a target in — a prefix with such a segment
 * would be a DEAD region counted derivable (reviews K2W-2, K3D2-1).
 */
export function segmentIsNotAPath(seg: string): boolean {
  return typeof seg === "string" && seg.length > 0 && NOT_A_PATH_SEGMENT.test(seg);
}
function hasNotAPathShape(path: string): boolean {
  return path.split("/").some(segmentIsNotAPath);
}

/** True when canonicalisation would change WHICH FILE a raw target names (R-c). */
function rewritesTheName(rawTarget: unknown): boolean {
  if (typeof rawTarget !== "string") return true;
  return rawTarget.trim() !== rawTarget || rawTarget.normalize("NFC") !== rawTarget;
}

/**
 * S211 (ruled by the audit 2026-10-14 08:18Z; the arbiter's go 2026-10-15): A PATH IN
 * ONE MATCHING PAIR OF QUOTES IS A PATH. Pure, exported: mica-service hands the
 * witness the SAME string the label was derived from.
 *
 * Exactly one pair, `"` or `'`, is stripped, and only when it wraps an
 * otherwise-ABSOLUTE path, in one of the two shapes a canonical target arrives in:
 *   · DIRECT  `"/abs"`          — a claim that is the quoted token itself;
 *   · JOINED  `<cwd>/"/abs"`    — the served caller joins any slash-bearing
 *     token that does not start with "/" onto its cwd, and a quoted one does
 *     not (`cat "/mnt/c/x"` arrives as `<home>/"/mnt/c/x"`). The shell reads
 *     the token as `/abs`, so the cwd is DROPPED with the quotes.
 * Refused — returned unchanged, so the quote stays and the shape rule below
 * reads it UNDERIVED — when the opening quote is not the first quote character
 * of the target, is not at its start or right after a "/", is not matched by
 * the SAME character as the target's last, or when the inside is not absolute
 * or holds another `"` or `'` (mismatched, nested, a second pair). Every other
 * refusal stands on the stripped path: dots, ":", "$", ">", whitespace, R-c.
 * The canonical form collapsed "//" over the whole target but could not drop
 * the inside's trailing "/" (the quote was last), so that is done here.
 * ⚠ THE COST, NAMED: the joined shape is textually identical to an ABSOLUTE
 *   token holding `/"/…"` at its end — `/srv/"/x"`, which the shell reads as
 *   `/srv/x` — and this rule places it at `/x`. The bridge knows no caller cwd
 *   to tell the two apart. Pinned by a test; disclosed, not hidden.
 * ⚠ THE FINGERPRINT DOES NOT MOVE: this is derivation, not canonicalisation —
 *   TARGET_CANON_VERSION and the HMAC input stay the canonical string.
 */
export function unquoteOnePair(canonicalTarget: string): string {
  const t = canonicalTarget;
  const i = t.search(/["']/);
  if (i < 0) return t;
  const q = t[i];
  if (i > 0 && t[i - 1] !== "/") return t;
  if (t.length < i + 3 || !t.endsWith(q)) return t;
  let inner = t.slice(i + 1, -1);
  if (!inner.startsWith("/") || /["']/.test(inner)) return t;
  if (inner.length > 1 && inner.endsWith("/")) inner = inner.slice(0, -1);
  return inner;
}

/**
 * Pure. Returns the category id of the LONGEST declared region the target lies
 * in, or INTEREST_UNDERIVED.
 *
 *   · ONE matching pair of quotes around an otherwise-absolute path is
 *     stripped FIRST (S211, `unquoteOnePair`); every rule below reads the
 *     stripped path
 *   · null / empty                              -> UNDERIVED
 *   · not starting with "/" (a program word)    -> UNDERIVED
 *   · any segment "." or ".."                   -> UNDERIVED — the canonical
 *     form collapses "//" and a trailing "/" but does NOT resolve these (there
 *     is no filesystem to resolve them against), so `/srv/a/../b` textually
 *     "lies under" `/srv/a` while naming a place that does not. A region match
 *     on such a path would be a lie, and the honest word is UNDERIVED.
 *   · any segment SHAPED LIKE A NON-PATH TOKEN (segmentIsNotAPath: a ":"
 *     anywhere, a leading flag/format/tilde character, a shell
 *     metacharacter) -> UNDERIVED
 *   · `rawTarget` GIVEN and the canonicaliser had to TRIM it or NFC-NORMALISE
 *     it -> UNDERIVED (R-c, review C3-1). Linux paths are byte-exact: a file
 *     named `/srv/a<NBSP>` is a SIBLING of the directory `/srv/a`, and a
 *     directory spelt with U+212B (or A + U+030A) is not the one spelt U+00C5.
 *     The canonical form merges them, which is right for a fingerprint (a missed
 *     revisit, never a false one) and wrong for a label: it would place an act
 *     OUTSIDE a region into it, by a name the subject can choose. So a label is
 *     derived only when the raw target already IS its own trimmed NFC form.
 *     ⚠ THE TRIM LEG GUARDS ONLY A DIRECT POST (review K2W3-2). The served
 *     caller tokenises its command on JavaScript's \s, which is exactly the set
 *     trim() removes, so a target it sends never carries surrounding Unicode
 *     whitespace: `/srv/a<NBSP>sib` (ONE word to the shell) arrives as `/srv/a`,
 *     already truncated, and is placed in /srv/a's region. That is the
 *     caller's split, out of this file's reach; the NFC leg still bites.
 *     ⚠ "//" collapsing and one trailing "/" are NOT in this rule: `/srv//a/`
 *     and `/srv/a` name one directory, so they stay placeable. A raw target that
 *     is given but is not a string reads UNDERIVED too (the canonicaliser would
 *     have refused it; this function does not guess past that).
 *     Absent `rawTarget` (undefined) skips the rule — the pure tests and any
 *     caller that holds only the canonical form.
 *   · otherwise, SEGMENT-AWARE: prefix p matches target t iff p === "/" or
 *     t === p or t starts with p + "/". So `/data/ab` is NOT under `/data/a`.
 *     Longest matching prefix wins; on an exact tie (only possible without the
 *     loader, which refuses duplicate prefixes) the FIRST declared wins.
 *
 * GLOB METACHARACTERS ARE MATCHED LITERALLY. `/tmp/x-*` lies under `/tmp`: the
 * glob's static directory is a real claim about a region, and expanding the
 * glob would need the filesystem this function must not touch.
 *
 * ⚠ PREFIXES ARE COMPARED AS LOADED. The front door refuses a prefix that is
 *   not its own canonical form (R-b: NFC, trimmed, no C0 or DEL control character, at most
 *   the canonicaliser's byte cap), so on a loaded declaration a prefix and a
 *   canonical target are in the same form and a byte comparison is the honest
 *   one. Without the loader, a non-canonical prefix simply never matches.
 */
export function deriveInterestLabel(
  canonicalTarget: string | null,
  regions: readonly FrameRegionRule[],
  rawTarget?: unknown
): string {
  if (typeof canonicalTarget !== "string" || canonicalTarget.length === 0) return INTEREST_UNDERIVED;
  const t = unquoteOnePair(canonicalTarget);
  if (!t.startsWith("/")) return INTEREST_UNDERIVED;
  if (hasDotSegment(t)) return INTEREST_UNDERIVED;
  if (hasNotAPathShape(t)) return INTEREST_UNDERIVED;
  if (rawTarget !== undefined && rewritesTheName(rawTarget)) return INTEREST_UNDERIVED;
  let best: FrameRegionRule | null = null;
  for (const r of regions) {
    if (!prefixIsMatchable(r.prefix)) continue;
    const p = r.prefix;
    const matches = p === "/" || t === p || t.startsWith(p + "/");
    if (!matches) continue;
    if (best === null || p.length > best.prefix.length) best = r;
  }
  return best === null ? INTEREST_UNDERIVED : best.category;
}
