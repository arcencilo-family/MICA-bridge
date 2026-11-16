// ── interest-label.test — Gate 1's touch label and its wire mapping ─────────
//
// GATE 1 · Stop 2. Two things are pinned here, both PURE, both without a
// service:
//
//   1. `deriveInterestLabel` — every rule of spec §2.1, one arm each, plus a
//      property arm: the function returns a declared category id or the one
//      underived word, and NEVER anything carrying the target. Round 2 adds the
//      RAW-TARGET rule (R-c) and runs the review's C3-1 cases through the
//      bridge's REAL canonicaliser, plus the front-door property that makes
//      the byte comparison honest (R-b: a loaded region is never dead).
//   2. `toWireOptions` -> `gate1` (spec §2.4), called DIRECTLY. The bridge's
//      `wire` comes from /opt, which does not know `gate1` until the machine is
//      relaid, so routing this through wire() would test the relay, not the map.
//
// The end-to-end half is NOT here. Round 2 (placement D): a real POST writes
// the label to the INTEREST BOOK, TOOL_ATTEMPTED's own outcome stays the
// toolName, and the plain never reaches either file — mica-service.test.ts and
// interest-book.test.ts, which also pin the frame-scoped label CLASS that
// toWireOptions emits (section 3 below asserts only what that class is not
// responsible for).
//
// No test framework, the house harness: each check() prints PASS/FAIL, the
// exit code is set AT the failure, and the tally is COUNTED. Run with:
//   /home/operator/mica-machine/node_modules/.bin/ts-node \
//     -P mica-bridge/tsconfig.json mica-bridge/interest-label.test.ts

import { readFileSync } from "fs";
import { join, posix } from "path";
import {
  deriveInterestLabel,
  INTEREST_UNDERIVED,
  GATE1_LABEL_KIND,
  INTEREST_DERIVATION_VERSION,
  unquoteOnePair,
  segmentIsNotAPath,
  type FrameRegionRule,
} from "./interest-label";
import { DeclarationRejected, validateDeclarations } from "./declarations";
import { canonicalHash } from "./canonical-json";
import { canonicaliseTargetIdentity } from "./target-fingerprint";
import { toWireOptions } from "./to-wire-options";
import { SUBJECT_EVENT_KINDS, subjectEventOutcome } from "./mica-service";

let passed = 0;
let failed = 0;

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
    // ⛔ THE EXIT CODE IS SET HERE, AT THE FAILURE, NOT AT THE TALLY (P5): a
    //    late arm cannot outrun a cumulative exitCode.
    process.exitCode = 1;
    console.log(`FAIL  ${name}`);
    console.log(`      ${err instanceof Error ? err.message : String(err)}`);
  }
}

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

// ── fixtures ─────────────────────────────────────────────────────────────────

/** Nested regions: a self area, an inner area inside it that is another's, and a root catch-all. */
const NESTED: readonly FrameRegionRule[] = Object.freeze([
  Object.freeze({ prefix: "/srv/a", category: "c-self" }),
  Object.freeze({ prefix: "/srv/a/b", category: "c-other" }),
  Object.freeze({ prefix: "/", category: "c-shared" }),
]);
/** No catch-all: a target outside both regions is placed nowhere. */
const NO_ROOT: readonly FrameRegionRule[] = Object.freeze([
  Object.freeze({ prefix: "/data/a", category: "c-self" }),
  Object.freeze({ prefix: "/tmp", category: "c-other" }),
]);

// ── 1 · deriveInterestLabel ─────────────────────────────────────────────────

check("UNDERIVED is a word of its own, and the labelled kind is a member of the bridge's closed kind alphabet whose own outcome is the toolName", () => {
  assert(INTEREST_UNDERIVED === "UNDERIVED", `the underived word moved: ${INTEREST_UNDERIVED}`);
  assert(
    (SUBJECT_EVENT_KINDS as readonly string[]).includes(GATE1_LABEL_KIND),
    `GATE1_LABEL_KIND ${GATE1_LABEL_KIND} is not a kind mica-service accepts — the label would ride a record nobody can post`
  );
  // AND ITS OWN OUTCOME IS THE TOOL NAME — which placement D leaves exactly as
  // it was (the label goes to the interest book), and which is why X17 still
  // refuses a category spelt as a toolName. Read by behaviour, not by the table.
  assert(
    subjectEventOutcome(GATE1_LABEL_KIND, { toolName: "tool-x" }) === "tool-x",
    "the labelled kind's own outcome is no longer the toolName; X17's reasoning in declarations.ts is stale"
  );
});

check("null, empty and absent targets are UNDERIVED, even over a root catch-all", () => {
  for (const t of [null, ""]) {
    const got = deriveInterestLabel(t, NESTED);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(t)} -> ${got}`);
  }
  // A non-string smuggled past the type is refused the same way, not thrown on.
  assert(deriveInterestLabel(undefined as unknown as string, NESTED) === INTEREST_UNDERIVED, "undefined target");
});

check("a target that does not start with '/' (a program word, a relative path) is UNDERIVED, even over '/'", () => {
  for (const t of ["tool-x", "ls", "srv/a/file", "./srv/a", "~/srv/a", " /srv/a"]) {
    const got = deriveInterestLabel(t, NESTED);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(t)} -> ${got}: a word is not a place`);
  }
});

check("a '.' or '..' SEGMENT anywhere makes the target UNDERIVED — the canonical form does not resolve them", () => {
  for (const t of ["/srv/a/../b", "/srv/a/./x", "/..", "/.", "/srv/a/b/..", "/srv/a/b/."]) {
    const got = deriveInterestLabel(t, NESTED);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(t)} -> ${got}: a region match through a dot segment is a lie`);
  }
  // A dot INSIDE a segment is an ordinary name, not a dot segment.
  assert(deriveInterestLabel("/srv/a/.hidden", NESTED) === "c-self", "a leading-dot NAME is a name");
  assert(deriveInterestLabel("/srv/a/x..y", NESTED) === "c-self", "'..' inside a name is a name");
  assert(deriveInterestLabel("/srv/a/...", NESTED) === "c-self", "'...' is a name, not a dot segment");
});

check("LONGEST matching prefix wins, whatever the declaration order", () => {
  assert(deriveInterestLabel("/srv/a/b/c", NESTED) === "c-other", "deepest region wins");
  assert(deriveInterestLabel("/srv/a/b", NESTED) === "c-other", "the prefix itself is inside its region");
  assert(deriveInterestLabel("/srv/a/x", NESTED) === "c-self", "the middle region");
  assert(deriveInterestLabel("/srv/z", NESTED) === "c-shared", "the root catch-all");
  assert(deriveInterestLabel("/", NESTED) === "c-shared", "'/' itself lies in the root region");
  const reversed = [...NESTED].reverse();
  for (const t of ["/srv/a/b/c", "/srv/a/x", "/srv/z"]) {
    assert(
      deriveInterestLabel(t, reversed) === deriveInterestLabel(t, NESTED),
      `${t}: declaration order changed the label — that is first-match, not longest-match`
    );
  }
});

check("SEGMENT-AWARE: /data/ab is NOT under /data/a; /data/a and /data/a/x are", () => {
  assert(deriveInterestLabel("/data/ab", NO_ROOT) === INTEREST_UNDERIVED, "/data/ab matched /data/a by string prefix");
  assert(deriveInterestLabel("/data/a-b", NO_ROOT) === INTEREST_UNDERIVED, "/data/a-b matched /data/a by string prefix");
  assert(deriveInterestLabel("/data/a", NO_ROOT) === "c-self", "the region's own path");
  assert(deriveInterestLabel("/data/a/x", NO_ROOT) === "c-self", "a path under the region");
  assert(deriveInterestLabel("/data", NO_ROOT) === INTEREST_UNDERIVED, "a PARENT of a region is not inside it");
});

check("no matching region, and EMPTY regions, are UNDERIVED — never a guessed category", () => {
  assert(deriveInterestLabel("/etc/x", NO_ROOT) === INTEREST_UNDERIVED, "outside every region");
  for (const t of ["/", "/srv/a", "/anything/at/all"]) {
    assert(deriveInterestLabel(t, []) === INTEREST_UNDERIVED, `${t} over no regions`);
  }
});

check("glob metacharacters are matched LITERALLY — the glob's static directory is the claim", () => {
  assert(deriveInterestLabel("/tmp/x-*", NO_ROOT) === "c-other", "/tmp/x-* lies under /tmp");
  assert(deriveInterestLabel("/tmp/[ab]?/*.log", NO_ROOT) === "c-other", "a bracket glob under /tmp");
  assert(deriveInterestLabel("/data/a*", NO_ROOT) === INTEREST_UNDERIVED, "/data/a* is a NAME beside /data/a, not under it");
  const starRegion: FrameRegionRule[] = [{ prefix: "/data/*", category: "c-self" }];
  assert(deriveInterestLabel("/data/x", starRegion) === INTEREST_UNDERIVED, "a '*' in a PREFIX is not expanded either");
  assert(deriveInterestLabel("/data/*/x", starRegion) === "c-self", "the literal '*' segment matches itself");
});

check("NOT-A-PATH SHAPES: a URL, a flag, a redirect, a quote, a variable, a ~user or a +format JOINED onto the caller's cwd is UNDERIVED, not the cwd's category", () => {
  // The caller joins any slash-containing token onto its cwd; these are the
  // shapes it produces from arguments that are not paths (neutral home here).
  const HOME_REGION: readonly FrameRegionRule[] = Object.freeze([
    Object.freeze({ prefix: "/home/op", category: "op" }),
    Object.freeze({ prefix: "/", category: "rest" }),
  ]);
  for (const joined of [
    "/home/op/https:/example.org/x", "/home/op/user@host:/srv/x", "/home/op/--out=/tmp/f", "/home/op/-o/tmp/f",
    // S211: `/home/op/"/etc/x"` and `/home/op/'/etc/x'` LEFT this list — one matching
    // pair around an absolute path is a path now (the S211 arms below). The quote
    // shapes that still refuse stay here.
    "/home/op/2>/dev/null", "/home/op/>/tmp/x", "/home/op/\"etc/x\"", "/home/op/'/etc/x", "/home/op/`cat`/x",
    "/home/op/$HOME/x", "/home/op/VAR=/x", "/home/op/a|b/c", "/home/op/a;b/c", "/home/op/a&b/c", "/home/op/(x)/y",
    "/home/op/{a,b}/c", "/home/op/a\\ b/c", "/home/op/~user/x", "/home/op/+%Y/%m",
  ]) {
    const got = deriveInterestLabel(joined, HOME_REGION);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(joined)} read ${got}, not UNDERIVED`);
  }
  // CONTROLS: ordinary relative paths under the cwd, dots, "-", "+" and "@"
  // INSIDE a segment, and globs keep their region. (Round 2 pinned a colon
  // inside a segment here as placeable; round 3 refuses it — see the next arm.)
  for (const [t, want] of [
    ["/home/op/notes/todo.txt", "op"], ["/home/op/src", "op"], ["/home/op/a.b/c-d", "op"],
    ["/home/op/*.log", "op"], ["/etc/hosts", "rest"], ["/home/op", "op"], ["/home/op/c++/x", "op"],
    ["/home/op/node_modules/@types/x", "op"], ["/home/op/x+y", "op"],
  ] as const) {
    const got = deriveInterestLabel(t, HOME_REGION);
    assert(got === want, `${t} read ${got}, want ${want}`);
  }
  // ⚠ THE RESIDUAL, PINNED SO IT CANNOT BE FORGOTTEN: `echo a/b` arrives as a
  //   plain relative path and IS placed. The bridge cannot tell it from one.
  assert(deriveInterestLabel("/home/op/a/b", HOME_REGION) === "op", "the residual moved: re-word the ceiling");
});

// ── ROUND 3 · A1 · a ":" anywhere in a segment is not a path ──────────────────

/**
 * What the served caller's resolver does to a non-absolute token: a
 * path.posix.join onto its cwd (which NORMALISES "." and ".."). The REAL
 * resolver lives in the harness, out of the bridge; this is its join, so the
 * arms below hand the bridge exactly the shape the review measured.
 */
function joinedUnderHome(token: string): string {
  return posix.join("/home/op", token);
}
/** The bridge's own pipeline on a joined target: canonicalise, then derive with the raw (as mica-service does). */
function homePipe(raw: string, regions: readonly FrameRegionRule[]): string {
  const c = canonicaliseTargetIdentity(raw);
  return c.ok ? deriveInterestLabel(c.canonical, regions, raw) : INTEREST_UNDERIVED;
}
const HOME_AND_REST: readonly FrameRegionRule[] = Object.freeze([
  Object.freeze({ prefix: "/home/op", category: "c-home" }),
  Object.freeze({ prefix: "/srv", category: "c-srv" }),
  Object.freeze({ prefix: "/tmp", category: "c-tmp" }),
]);

check("ROUND 3 (A1): host:port, scp/rsync/git remotes and user:pw@host JOINED under the caller's home are UNDERIVED — a ':' ANYWHERE in a segment, not only trailing", () => {
  // Reviews K2W-1 (two refuters), K1R2-3, K2W3-1: every form they measured
  // reading the HOME category, through the bridge's own canonicaliser.
  for (const token of [
    "localhost:8080/api", "localhost:8080/api/health", "127.0.0.1:3000/status", "10.0.0.9:80/x", "[::1]:80/x",
    "server:logs/app.log", "git@github.com:org/repo.git", "git@example.org:org/repo", "user@host:notes/x",
    "host:dir/", "backup:srv/data/", "backup-host:dir/notes.txt", "backup.example:var/data", "user:pw@host/x",
    "Accept:text/html/x", "library/ubuntu:22.04",
  ]) {
    const raw = joinedUnderHome(token);
    const got = homePipe(raw, HOME_AND_REST);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(token)} -> ${JSON.stringify(raw)} read ${got}, not UNDERIVED: a remote placed in the home's category`);
  }
  // A colon ANYWHERE in ANY segment — not only the first joined one.
  for (const t of ["/srv/a/localhost:8080/y", "/srv/node:20", "/srv/x:", "/srv/a:b/c", "/srv/a/b:"]) {
    assert(deriveInterestLabel(t, HOME_AND_REST) === INTEREST_UNDERIVED, `${t} was placed`);
  }
  // CONTROLS: the ordinary forms still land, through the same pipeline.
  for (const [token, want] of [["notes/todo.txt", "c-home"], ["src/a-b/c.ts", "c-home"], ["node_modules/@types/x", "c-home"]] as const) {
    const got = homePipe(joinedUnderHome(token), HOME_AND_REST);
    assert(got === want, `${token} -> ${got}, wanted ${want}`);
  }
  assert(homePipe("/tmp/restore/x", HOME_AND_REST) === "c-tmp", "an absolute /tmp target keeps its region");
});

check("ROUND 3 (A1): segmentIsNotAPath and INTEREST_DERIVATION_VERSION are EXPORTED — one predicate for the label rule and the front door, a version for the label class", () => {
  assert(Number.isSafeInteger(INTEREST_DERIVATION_VERSION) && INTEREST_DERIVATION_VERSION >= 1, `version ${String(INTEREST_DERIVATION_VERSION)}`);
  assert(INTEREST_DERIVATION_VERSION === 4, `S211 is derivation version 4, got ${String(INTEREST_DERIVATION_VERSION)} — a rule change must bump it`);
  for (const seg of ["localhost:8080", "a:b", "x:", ":x", "-x", "+x", "~x", "a=b", "a&b", "(x)", "{x}", "a$b", "a;b", "a|b", "a<b", "a>b", "a'b", 'a"b', "a`b", "a\\b"]) {
    assert(segmentIsNotAPath(seg), `${JSON.stringify(seg)} is not a path, the predicate says it is`);
  }
  for (const seg of ["", "a", "a-b", "c++", "@types", "a@b", "x*", "[ab]", "a.b", "...", ".hidden", "\u00e9"]) {
    assert(!segmentIsNotAPath(seg), `${JSON.stringify(seg)} is a path segment, the predicate refuses it`);
  }
  // THE SAME predicate decides the label: a segment it refuses makes the target UNDERIVED.
  for (const seg of ["a:b", "-x", "a=b"]) {
    assert(deriveInterestLabel(`/srv/${seg}/f`, HOME_AND_REST) === INTEREST_UNDERIVED, `/srv/${seg}/f was placed`);
  }
});

check("ROUND 3 · THE RESIDUALS, PINNED so the ceiling cannot outgrow them: a shape the CALLER's '..' normalisation erased, a slash word, an '@file', and a name the caller split at Unicode whitespace ARE placed", () => {
  // K2W-2: the caller's join normalises "..", so the non-path segment is gone
  // before the bridge sees the target. The bridge cannot tell; the reader's
  // ceiling must say so. If this arm goes red the residual moved: re-word it.
  for (const token of ["${HOME}/../x", "https://h.example/../../x", "--out=x/../y", '"$SRC"/../conf']) {
    const raw = joinedUnderHome(token);
    assert(homePipe(raw, HOME_AND_REST) === "c-home", `${token} -> ${raw}: the erased-shape residual moved`);
  }
  // K2W3-1: "@" alone is not refused (npm scopes are real paths).
  assert(homePipe(joinedUnderHome("@/tmp/payload.json"), HOME_AND_REST) === "c-home", "the @file residual moved");
  assert(homePipe(joinedUnderHome("a/b"), HOME_AND_REST) === "c-home", "the a/b residual moved");
  // K2W3-2: the caller splits its command on \s (the set trim() removes), so a
  // name holding a Unicode space arrives TRUNCATED and the R-c trim leg cannot
  // see it. Pinned with the split the caller uses, not with a copy of its code.
  for (const ws of ["\u00a0", "\u3000", "\u2028"]) {
    const head = `cat /srv/a${ws}sib`.split(/\s+/)[1];
    assert(head === "/srv/a", `the caller-style split did not truncate at U+${ws.codePointAt(0)!.toString(16)}: ${JSON.stringify(head)}`);
    assert(homePipe(head, HOME_AND_REST) === "c-srv", "the truncated head must be placed — that is the residual the R-c comment discloses");
  }
});

check("ROUND 3 · DISCLOSURE PINS: the docblock no longer claims scp's `host:` is caught by a trailing ':', and the R-c comment names the caller's \\s split", () => {
  // Reviews K2W3-1, K2W3-2. Comments are claims; these two were false. The
  // check reads the PROSE because the prose is the thing that was wrong.
  const src = readFileSync(join(__dirname, "interest-label.ts"), "utf8");
  assert(!/ends in ":"\s+\(a URL scheme, `host:` of scp\)/.test(src), "the withdrawn claim (a trailing ':' catches scp's host:) is back");
  assert(/THE TRIM LEG GUARDS ONLY A DIRECT POST/.test(src), "the R-c comment no longer discloses that the caller's \\s split truncates whitespace-bearing names");
});

check("a MALFORMED rule (only reachable without the loader) is SKIPPED, never repaired into a match", () => {
  const bad: FrameRegionRule[] = [
    { prefix: "", category: "c-empty" }, //          "" + "/" would claim every absolute path
    { prefix: "srv", category: "c-rel" }, //          relative
    { prefix: "/srv/", category: "c-slash" }, //      trailing slash
    { prefix: "/srv//a", category: "c-dslash" }, //   double slash
    { prefix: "/srv/../a", category: "c-dot" }, //    dot segment
    { prefix: 7 as unknown as string, category: "c-num" },
  ];
  for (const t of ["/srv", "/srv/a", "/srv/a/x", "/a/x", "/x"]) {
    const got = deriveInterestLabel(t, bad);
    assert(got === INTEREST_UNDERIVED, `${t} -> ${got}: a malformed rule placed a target`);
  }
  // And a malformed rule does not shadow a well-formed one beside it.
  const mixed = [...bad, { prefix: "/srv", category: "c-good" }];
  assert(deriveInterestLabel("/srv/a/x", mixed) === "c-good", "the well-formed rule must still win");
});

check("PROPERTY: over many targets the label is a declared category or UNDERIVED, never the target, and the rules are not mutated", () => {
  const declared = new Set(NESTED.map((r) => r.category));
  const before = canonicalHash(NESTED);
  const targets = [
    "/", "/srv", "/srv/a", "/srv/a/b", "/srv/a/b/c/d", "/srv/ab", "/srv/a b/c", "/srv/a/ü", "/x/y/z",
    "tool-x", "", "/..", "/srv/./a", "/tmp/x-*", "/srv/a/b/" + "q".repeat(300), "/srv/a\\b", "/srv/a:b",
  ];
  for (const t of targets) {
    const a = deriveInterestLabel(t, NESTED);
    const b = deriveInterestLabel(t, NESTED);
    assert(a === b, `not deterministic on ${JSON.stringify(t)}: ${a} then ${b}`);
    assert(a === INTEREST_UNDERIVED || declared.has(a), `${JSON.stringify(t)} -> ${a}: not a declared category`);
    if (t.length > 1) assert(!a.includes(t), `the label CARRIES THE TARGET: ${a}`);
  }
  assert(canonicalHash(NESTED) === before, "deriveInterestLabel mutated the rules it was handed");
});

// ── R-c · the raw target: a label only when canonicalising did not rename ────

check("R-c: a RAW target the canonicaliser had to TRIM (any Unicode whitespace) is UNDERIVED — a sibling, not the region", () => {
  for (const raw of ["/srv/a ", "/srv/a\u00a0", "/srv/a\u3000", "/srv/a\ufeff", "/srv/a\u2028", " /srv/a/x", "\u00a0/srv/a/x", "\t/srv/a/x"]) {
    const got = deriveInterestLabel(raw.trim(), NESTED, raw);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(raw)} -> ${got}: a byte-distinct name was placed in a region`);
  }
});

check("R-c: a RAW target the canonicaliser had to NFC-NORMALISE is UNDERIVED; the true NFC spelling is still placed", () => {
  const regions: FrameRegionRule[] = [{ prefix: "/home/\u00c5sa", category: "c-other" }, { prefix: "/", category: "c-shared" }];
  for (const raw of ["/home/\u212bsa/x", "/home/A\u030asa/x"]) {
    const canonical = raw.normalize("NFC");
    assert(deriveInterestLabel(canonical, regions) === "c-other", `control: without raw, ${JSON.stringify(raw)} would be placed`);
    const got = deriveInterestLabel(canonical, regions, raw);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(raw)} -> ${got}: another directory was placed in the declared one (even the root catch-all is not claimed)`);
  }
  assert(deriveInterestLabel("/home/\u00c5sa/x", regions, "/home/\u00c5sa/x") === "c-other", "the NFC name itself must still be placed");
});

check("R-c: '//' collapsing and ONE trailing '/' are benign — one directory, still placeable", () => {
  for (const [raw, canonical, want] of [
    ["//srv//a//x", "/srv/a/x", "c-self"],
    ["/srv/a/b/", "/srv/a/b", "c-other"],
    ["/srv///a/", "/srv/a", "c-self"],
  ] as const) {
    const got = deriveInterestLabel(canonical, NESTED, raw);
    assert(got === want, `${JSON.stringify(raw)} -> ${got}, wanted ${want}`);
  }
});

check("R-c: rawTarget ABSENT skips the rule; GIVEN but not a string is UNDERIVED; raw === canonical changes nothing", () => {
  assert(deriveInterestLabel("/srv/a/x", NESTED) === "c-self", "absent raw");
  assert(deriveInterestLabel("/srv/a/x", NESTED, undefined) === "c-self", "explicit undefined is absent");
  for (const raw of [null, 7, {}, ["/srv/a/x"]]) {
    const got = deriveInterestLabel("/srv/a/x", NESTED, raw);
    assert(got === INTEREST_UNDERIVED, `raw ${JSON.stringify(raw)} -> ${got}: a non-string raw was trusted`);
  }
  for (const t of ["/", "/srv/a", "/srv/a/b/c", "/srv/z", "/tmp/x-*", "/srv/a/\u00fc"]) {
    assert(deriveInterestLabel(t, NESTED, t) === deriveInterestLabel(t, NESTED), `${JSON.stringify(t)}: raw === canonical moved the label`);
  }
  // The raw rule does not rescue what the canonical form already refuses.
  assert(deriveInterestLabel("/srv/a/../b", NESTED, "/srv/a/../b") === INTEREST_UNDERIVED, "a dot segment stays UNDERIVED");
});

check("R-c THROUGH THE BRIDGE'S REAL CANONICALISER: the review's C3-1 cases now read UNDERIVED, the honest ones keep their category", () => {
  // The same pipeline mica-service runs: canonicaliseTargetIdentity, then
  // deriveInterestLabel(canonical, regions, raw). No copy of the canon rules here.
  const pipe = (raw: string): string => {
    const c = canonicaliseTargetIdentity(raw);
    return c.ok ? deriveInterestLabel(c.canonical, NESTED, raw) : INTEREST_UNDERIVED;
  };
  const underived = ["/srv/a ", "/srv/a\u00a0", "/srv/a\u3000", "/srv/a\ufeff", "/srv/a\u2028", " /srv/a/x", "\u00a0/srv/a/x", "/srv/a/x\u0001"];
  for (const raw of underived) assert(pipe(raw) === INTEREST_UNDERIVED, `${JSON.stringify(raw)} -> ${pipe(raw)}`);
  for (const [raw, want] of [["/srv/a/x", "c-self"], ["//srv//a//x/", "c-self"], ["/srv/a/b/c", "c-other"], ["/srv/ab", "c-shared"]] as const) {
    assert(pipe(raw) === want, `${JSON.stringify(raw)} -> ${pipe(raw)}, wanted ${want}`);
  }
});

check("PURITY FENCE: interest-label.ts has no runtime import and no require — the bridge's sandbox cannot steer a label", () => {
  // Matches USE (an import statement that brings a value in, a require call),
  // never a NAME in a comment. A type-only import is erased at compile time.
  const src = readFileSync(join(__dirname, "interest-label.ts"), "utf8");
  const code = src
    .split("\n")
    .filter((l) => !/^\s*\/\//.test(l))
    .join("\n");
  const valueImports = code.match(/^\s*import\s+(?!type\b)[^;]*;/gm) ?? [];
  assert(valueImports.length === 0, `a runtime import in the pure label module: ${JSON.stringify(valueImports)}`);
  assert(!/\brequire\s*\(/.test(code), "a require() call in the pure label module");
  assert(!/\bDate\b|\bprocess\./.test(code), "a clock or process read in the pure label module");
});

// ── 2 · the front door and the underived word agree ─────────────────────────

const FIXTURE = JSON.parse(readFileSync(join(__dirname, "declarations.fixture.json"), "utf8"));

/** The fixture, pilot neutralised, plus subject-a bound to the fixture subject's own peer (no uid typed). */
function base(): any {
  const d = JSON.parse(JSON.stringify(FIXTURE));
  d.pilot = { active: false };
  const s0 = d.subjects[0];
  d.subjects.push({ subject: "subject-a", toolName: "tool-x", stakesClass: s0.stakesClass, peerUid: s0.peerUid });
  return d;
}
const BASIS = "GATE 1 FIXTURE, not a declaration. Exercises the bridge's label map.";
/** Three categories, the third mapped by NO region (so not derivable). */
function frame(): any {
  return {
    categories: {
      value: [
        { id: "c-self", label: "own area", grounding: "agency", self: true },
        { id: "c-other", label: "another's area", grounding: "vulnerability", self: false },
        { id: "c-unmapped", label: "an area no region names", grounding: "need", self: false },
      ],
      basis: BASIS,
      proxy: true,
    },
    regions: {
      value: [
        { prefix: "/srv/a", category: "c-self" },
        { prefix: "/srv/a/b", category: "c-other" },
        { prefix: "/srv/c", category: "c-other" },
      ],
      basis: BASIS,
      proxy: true,
    },
  };
}
function framedWithReader(): any {
  const d = base();
  d.frame = { "subject-a": frame() };
  d.readers.gate1Scope = { subject: { value: "subject-a", basis: BASIS, proxy: false } };
  // X22 (round 2): the reader reads the interest book, so it must be declared.
  d.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  return d;
}

check("the front door REFUSES a category spelt as this module's underived word — the two spellings cannot drift", () => {
  const d = framedWithReader();
  d.frame["subject-a"].categories.value[2].id = INTEREST_UNDERIVED;
  d.frame["subject-a"].regions.value[2].category = INTEREST_UNDERIVED;
  try {
    validateDeclarations(d);
  } catch (err) {
    assert(err instanceof DeclarationRejected, `refused, but not by the front door: ${String(err)}`);
    assert(
      (err as DeclarationRejected).field === "frame.subject-a.categories.value[2].id",
      `refused at the wrong field: ${(err as DeclarationRejected).field} (${(err as Error).message})`
    );
    return;
  }
  throw new Error(`a category named ${INTEREST_UNDERIVED} LOADED: underived acts would count as its cases`);
});

check("R-b: every prefix the front door ACCEPTS is reachable — its own canonical target (and one below it) gets its category; a non-canonical spelling is REFUSED", () => {
  // The byte comparison in deriveInterestLabel is honest only because a loaded
  // prefix already IS its canonical form. Held here by behaviour: load, then
  // run the prefix itself through the real canonicaliser and the matcher.
  for (const prefix of ["/srv/q", "/srv/caf\u00e9", "/srv/\u00c5sa/x-*", "/srv/a.b", "/"]) {
    const d = framedWithReader();
    d.frame["subject-a"].regions.value = [{ prefix, category: "c-other" }];
    const regions = validateDeclarations(d).declarations.frame!["subject-a"].regions.value;
    for (const raw of [prefix, prefix === "/" ? "/x" : prefix + "/x"]) {
      const c = canonicaliseTargetIdentity(raw);
      const got = c.ok ? deriveInterestLabel(c.canonical, regions, raw) : `REFUSED(${c.reason})`;
      assert(got === "c-other", `loaded prefix ${JSON.stringify(prefix)}: target ${JSON.stringify(raw)} -> ${got} — a DEAD region loaded`);
    }
  }
  for (const prefix of [
    "/srv/cafe\u0301", "/srv/\u2126", "/srv/q ", "/srv/q\u00a0", "/srv/\u0001q", "/srv/" + "q".repeat(600),
    // ROUND 3 (A2): the DEAD shapes — every target under them reads UNDERIVED,
    // so the door refuses them with the label rule's own predicate.
    "/mnt/c/Program Files (x86)", "/srv/R&D", "/srv/a=b", "/home/op/~archive", "/srv/-scratch", "/srv/+inbox",
    "/srv/it's", "/srv/{x}", "/srv/node:20", "/srv/x:", "/srv/a$b", "/warehouse/t/year=2024", "/srv/a;b",
  ]) {
    const d = framedWithReader();
    d.frame["subject-a"].regions.value = [{ prefix, category: "c-other" }];
    let refusedAt: string | null = null;
    try {
      validateDeclarations(d);
    } catch (err) {
      assert(err instanceof DeclarationRejected, `refused, but not by the front door: ${String(err)}`);
      refusedAt = (err as DeclarationRejected).field;
    }
    assert(refusedAt === "frame.subject-a.regions.value[0].prefix", `non-canonical or dead prefix ${JSON.stringify(prefix)}: refusedAt ${String(refusedAt)}`);
  }
});

check("WHITESPACE IS NOT A PATH SEGMENT (round 3 re-verify, NEW-K1R-1): a direct POST carrying a space, NBSP or ideographic space under a region reads UNDERIVED — no whitespace-split R6 token can carry one", () => {
  const R: readonly FrameRegionRule[] = Object.freeze([Object.freeze({ prefix: "/srv", category: "c-srv" })]);
  for (const t of ["/srv/Program Files/x", "/srv/a\u00a0b", "/srv/a\u3000b/c", "/srv/a\tb"]) {
    const got = deriveInterestLabel(t, R, t);
    assert(got === INTEREST_UNDERIVED, `${JSON.stringify(t)} read ${got}, not UNDERIVED`);
  }
  assert(deriveInterestLabel("/srv/ProgramFiles/x", R, "/srv/ProgramFiles/x") === "c-srv", "the control lost its region");
  assert(segmentIsNotAPath("a b") && !segmentIsNotAPath("ab"), "the shared predicate does not carry whitespace");
});

check("R-b + A2 SWEEP: over every printable ASCII character at a segment's start, middle and end, the front door ACCEPTS a prefix IF AND ONLY IF the label rule can place a target at and under it", () => {
  // The round-2 arm tried five prefixes and its name claimed every one (review
  // K2W3-4). This sweep is the claim at the width it states: for each character
  // the door's verdict and the deriver's agree — accepted means reachable,
  // refused means a target there reads UNDERIVED (or the canonicaliser refuses).
  const mismatched: string[] = [];
  let accepted = 0;
  for (let code = 0x20; code <= 0x7e; code++) {
    const ch = String.fromCharCode(code);
    if (ch === "/") continue;
    for (const seg of [`${ch}q`, `q${ch}q`, `q${ch}`]) {
      const prefix = `/srv/${seg}`;
      const d = framedWithReader();
      d.frame["subject-a"].regions.value = [{ prefix, category: "c-other" }];
      let loads = true;
      try {
        validateDeclarations(d);
      } catch (err) {
        if (!(err instanceof DeclarationRejected)) throw err;
        loads = false;
      }
      const regions: FrameRegionRule[] = [{ prefix, category: "c-other" }];
      const reach = [prefix, prefix + "/x"].every((raw) => {
        const c = canonicaliseTargetIdentity(raw);
        return c.ok && c.canonical === raw && deriveInterestLabel(c.canonical, regions, raw) === "c-other";
      });
      if (loads) accepted++;
      if (loads !== reach) mismatched.push(`${JSON.stringify(prefix)}: door ${loads ? "ACCEPTS" : "refuses"}, label rule ${reach ? "reaches" : "cannot reach"}`);
    }
  }
  assert(mismatched.length === 0, `door and deriver disagree on ${mismatched.length} prefix(es):\n    ${mismatched.join("\n    ")}`);
  assert(accepted > 100, `the sweep accepted only ${accepted} prefixes — it is not exercising the door`);
  console.log(`      (${String(accepted)} accepted prefixes, all reachable; every refused one unreachable)`);
});

// ── 3 · toWireOptions -> gate1 (spec §2.4), called directly ─────────────────

check("toWireOptions maps readers.gate1Scope + frame[subject] to gate1 EXACTLY: ids, self, derivable, label class's subject, underived word", () => {
  const loaded = validateDeclarations(framedWithReader()).declarations;
  const opts = toWireOptions(loaded) as Record<string, unknown>;
  // ⚠ THE LABEL CLASS's eventType IS NOT PINNED HERE. Round 2 (placement D)
  //   makes it frame-scoped — `frameLabelEventType(frame)` in interest-book.ts,
  //   called by both the writer and toWireOptions — and interest-book.test.ts
  //   pins it. This arm pins everything else exactly, and that the class is
  //   for THIS subject and is a non-empty word.
  const expected = {
    categories: [
      { id: "c-self", self: true, derivable: true },
      { id: "c-other", self: false, derivable: true },
      // NO REGION NAMES IT, so the reader must print it NOT READABLE rather than "0 cases".
      { id: "c-unmapped", self: false, derivable: false },
    ],
    labelClassModuleId: "subject-a",
    underivedWord: INTEREST_UNDERIVED,
  };
  assert("gate1" in opts, `readers.gate1Scope loaded but toWireOptions emitted no gate1 key: ${Object.keys(opts).join(",")}`);
  const g = opts.gate1 as { categories: unknown; labelClass: { moduleId: unknown; eventType: unknown }; underivedWord: unknown };
  const got = { categories: g.categories, labelClassModuleId: g.labelClass?.moduleId, underivedWord: g.underivedWord };
  assert(
    canonicalHash(got) === canonicalHash(expected),
    `gate1 mapping wrong:\n  expected ${JSON.stringify(expected)}\n  got      ${JSON.stringify(got)}`
  );
  assert(
    typeof g.labelClass?.eventType === "string" && g.labelClass.eventType.length > 0,
    `gate1.labelClass.eventType is not a non-empty word: ${JSON.stringify(g.labelClass)}`
  );
  // DECLARED ORDER is kept: the reader prints counts in declared order.
  const ids = (opts.gate1 as { categories: { id: string }[] }).categories.map((c) => c.id);
  assert(ids.join(",") === "c-self,c-other,c-unmapped", `declared order lost: ${ids.join(",")}`);
});

check("toWireOptions carries NO label, grounding, basis or proxy into gate1 — the envelope stays in the declaration", () => {
  const opts = toWireOptions(validateDeclarations(framedWithReader()).declarations) as any;
  assert(Object.keys(opts.gate1).sort().join(",") === "categories,labelClass,underivedWord", `gate1 keys: ${Object.keys(opts.gate1).join(",")}`);
  for (const c of opts.gate1.categories) {
    assert(Object.keys(c).sort().join(",") === "derivable,id,self", `category keys: ${Object.keys(c).join(",")}`);
  }
  assert(Object.keys(opts.gate1.labelClass).sort().join(",") === "eventType,moduleId", JSON.stringify(opts.gate1.labelClass));
});

check("EMPTY regions: every category is derivable:false — legal, and the reader's ceiling reads 0 of n", () => {
  const d = framedWithReader();
  d.frame["subject-a"].regions.value = [];
  const opts = toWireOptions(validateDeclarations(d).declarations) as any;
  assert(opts.gate1.categories.length === 3, JSON.stringify(opts.gate1));
  assert(opts.gate1.categories.every((c: any) => c.derivable === false), `a category with no region read derivable: ${JSON.stringify(opts.gate1)}`);
});

check("ABSENT block, ABSENT key — and a frame WITHOUT readers.gate1Scope switches nothing on and leaves the options byte-identical", () => {
  const plain = toWireOptions(validateDeclarations(base()).declarations) as Record<string, unknown>;
  assert(!("gate1" in plain), "toWireOptions emitted gate1 for an undeclared reader");
  assert(!("gate1BookPath" in plain), "toWireOptions emitted gate1BookPath for an undeclared reader");
  const framedOnly = base();
  framedOnly.frame = { "subject-a": frame() };
  // X22, second half: a frame alone switches the WRITER on, so it needs its book.
  // The book is emitted to the wiring only with the reader, so the options still match.
  framedOnly.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  const opts = toWireOptions(validateDeclarations(framedOnly).declarations) as Record<string, unknown>;
  assert(!("gate1" in opts), "a frame alone switched the reader on — the block is the switch, not the frame");
  assert(
    canonicalHash(opts) === canonicalHash(plain),
    "declaring a frame without the reader moved the wire options; an undeclared reader must yield the byte-identical object"
  );
});

// ── S211 · a path in ONE matching pair of quotes is a path ──────────────────

/** The served frame's c1 regions, as declared (S31): the arbiter's home and his Windows home. */
const SERVED_C1: readonly FrameRegionRule[] = Object.freeze([
  Object.freeze({ prefix: "/home/operator", category: "c1" }),
  Object.freeze({ prefix: "/mnt/c/Users/operator", category: "c1" }),
  Object.freeze({ prefix: "/etc", category: "c3" }),
  Object.freeze({ prefix: "/home/mica-housekeeper", category: "c5" }),
]);
/**
 * The served caller's resolveTargetIdentity (~/citadel/richards-cat/claude-bot.ts),
 * VERBATIM in its rule: the first whitespace-split token holding a "/", "~"-expanded,
 * else path.posix.join onto home. Copied, not imported: the harness is the
 * subject's, and importing it would start its module.
 */
function callerClaim(command: string, home: string): string | null {
  const tokens = command.trim().split(/\s+/);
  for (const t of tokens) {
    if (t === "~" || t.startsWith("~/") || t.startsWith("/") || t.includes("/")) {
      if (t === "~") return home;
      if (t.startsWith("~/")) return home + t.slice(1);
      if (t.startsWith("/")) return t;
      return posix.join(home, t);
    }
  }
  return tokens[0] ?? null;
}
function servedPipe(command: string): string {
  const raw = callerClaim(command, "/home/operator");
  if (raw === null) return INTEREST_UNDERIVED;
  return homePipe(raw, SERVED_C1);
}

check("S211 · THE 10-11 COMMANDS: `cat \"/mnt/c/…\"` and `echo '' >> \"/mnt/c/…\"` read c1 through the caller's claim, the bridge's canonicaliser and the served c1 regions", () => {
  const f = "/mnt/c/Users/operator/THE-VAULT/witness-check.md";
  for (const cmd of [
    `cat "${f}"`, `cat '${f}'`, `echo '' >> "${f}"`, `echo "" >> '${f}'`, `cat "/mnt/c/Users/operator/THE-VAULT/"`,
  ]) {
    const got = servedPipe(cmd);
    assert(got === "c1", `${cmd} read ${got}, not c1`);
  }
  // The joined claim the diagnosis measured, by hand: <home>/"/mnt/c/…".
  assert(deriveInterestLabel(`/home/operator/"${f}"`, SERVED_C1) === "c1", "the joined quoted claim is not placed");
});

check("S211 · QUOTED, UNQUOTED: one matching pair (\" or ') around an absolute path places exactly where the bare path does, direct or joined", () => {
  for (const p of ["/etc/hosts", "/mnt/c/Users/operator/x", "/home/mica-housekeeper/a/b", "/home/operator", "/"]) {
    const bare = deriveInterestLabel(p, SERVED_C1);
    for (const q of ['"', "'"]) {
      assert(deriveInterestLabel(`${q}${p}${q}`, SERVED_C1) === bare, `direct ${q}${p}${q} differs from bare (${bare})`);
      assert(deriveInterestLabel(`/home/op/${q}${p}${q}`, SERVED_C1) === bare, `joined /home/op/${q}${p}${q} differs from bare (${bare})`);
      assert(deriveInterestLabel(`/${q}${p}${q}`.replace(/\/{2,}/g, "/"), SERVED_C1) === bare, `joined under "/" differs from bare`);
    }
  }
  assert(unquoteOnePair('/home/op/"/srv/a/"') === "/srv/a", "the inside's trailing '/' is not dropped like the canonicaliser's");
  assert(unquoteOnePair('"/"') === "/", "the quoted root is not the root");
  // The unquoted forms are untouched — byte for byte.
  for (const p of ["/etc/hosts", "/home/op/notes/x", "/", "/srv/a b", "/x/y.txt"]) {
    assert(unquoteOnePair(p) === p, `unquoted ${p} moved`);
  }
});

check("S211 · MISMATCHED, NESTED, PARTIAL, RELATIVE: every quote shape that is not ONE matching pair around an absolute path stays UNDERIVED", () => {
  for (const t of [
    `"/etc/x'`, `'/etc/x"`, `/home/op/"/etc/x'`, // mismatched
    `""/etc/x""`, `"'/etc/x'"`, `'"/etc/x"'`, `/home/op/""/etc/x""`, `/home/op/"'/etc/x'"`, // nested
    `"/etc/a"/"b"`, `"/etc/a"b`, `x"/etc/a"`, `/home/op/x"/etc/a"`, `/home/op/"/etc/a"/b`, // partial / a second pair
    `"/etc/x`, `/etc/x"`, `/home/op/"/etc/x`, `"`, `""`, `''`, // unclosed, empty
    `"etc/x"`, `/home/op/"etc/x"`, `"~/x"`, `"./x"`, `/home/op/"../etc"`, // inside not absolute
    `"/etc/a'b"`, `'/etc/a"b'`, // another quote inside
  ]) {
    const got = deriveInterestLabel(t, SERVED_C1);
    assert(got === INTEREST_UNDERIVED, `${t} read ${got}, not UNDERIVED`);
  }
  // A token split by the caller at a space never carries its closing quote.
  assert(servedPipe(`cat "/mnt/c/Users/operator/My Docs/x"`) === INTEREST_UNDERIVED, "a quoted path cut at a space was placed");
});

check("S211 · EVERY OTHER REFUSAL STANDS on the stripped path: dots, ':', '$', '>', whitespace, a flag, R-c", () => {
  for (const inner of ["/etc/../x", "/etc/./x", "/etc/a:b", "/etc/$HOME", "/etc/>x", "/etc/-x", "/etc/a`b", "/etc/a b"]) {
    for (const q of ['"', "'"]) {
      for (const t of [`${q}${inner}${q}`, `/home/op/${q}${inner}${q}`]) {
        const got = deriveInterestLabel(t, SERVED_C1);
        assert(got === INTEREST_UNDERIVED, `${t} read ${got}, not UNDERIVED`);
      }
    }
  }
  // R-c on the RAW claim stands: an NFC rewrite or a trim still refuses.
  const nfd = '/home/op/"/etc/Å"';
  const c = canonicaliseTargetIdentity(nfd);
  assert(c.ok && deriveInterestLabel(c.canonical, SERVED_C1, nfd) === INTEREST_UNDERIVED, "R-c did not bite through the strip");
});

check("S211 · THE COST, PINNED: an ABSOLUTE token ending `/\"/x\"` is placed at /x (the shell reads /srv/x) — the bridge knows no cwd to tell it from a join", () => {
  // If this arm goes red the cost moved: re-word the doc comment and the disclosure.
  assert(unquoteOnePair('/srv/"/etc/x"') === "/etc/x", "the ambiguous shape is no longer stripped — re-word the disclosure");
  assert(deriveInterestLabel('/srv/"/etc/x"', SERVED_C1) === "c3", "the ambiguous shape's placement moved — re-word the disclosure");
});

const total = passed + failed;
console.log(`${total} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
