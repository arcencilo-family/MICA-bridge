// TEST SUPPORT: the shipped example declaration, with its three invented route uids mapped to the identities the
// behaviour tests were written against (5101 -> 980 the subject, 5102 -> 981 the alerter, 5103 -> 1000 the operator).
// The example's SHAPE and CONTENT are what the tests exercise; only the three numbers move and the invented
// `example-` file-name prefix under /var/lib/mica* is dropped (the rigs redirect paths by base name), so a behaviour test runs
// against what ships. A deployer replaces the uids with real ones (see the README table of reference defaults).
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";

const UID_MAP: Readonly<Record<number, number>> = { 5101: 980, 5102: 981, 5103: 1000 };
const EXAMPLE = join(__dirname, "declarations.example.json");

/** The example, parsed, with the three invented uids mapped to the test identities. */
export function shippedDraft(): any {
  return JSON.parse(readFileSync(EXAMPLE, "utf8"), (_k, v) =>
    typeof v === "number" && UID_MAP[v] !== undefined
      ? UID_MAP[v]
      : typeof v === "string" && v.startsWith("/var/lib/mica")
        ? v.replace("/example-", "/")
        : v,
  );
}

/** The same, written to `path` (for a child process that loads a declaration by path). */
export function writeShippedDraft(path: string): string {
  writeFileSync(path, JSON.stringify(shippedDraft(), null, 2));
  return path;
}
