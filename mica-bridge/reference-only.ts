// REFERENCE-DEPLOYMENT-ONLY TESTS (publication ruling, MP50 (1)).
// A test listed here asserts a FACT OF THE REFERENCE BOX (its served declaration's hash, the S216 candidate tree, a
// laid release under /opt, a commit of the reference history), not a BEHAVIOUR of the shipped code. It is skipped in
// the shipped suite (the default) and runs, alone, with MICA_BRIDGE_REFERENCE_SET=1 (see run-suite.sh --reference).
// Every row carries its reason. A behaviour test is never listed to make it pass.
export interface ReferenceRow {
  readonly file: string; // base name of the test file
  readonly name: string; // the check's name, matched as a prefix
  readonly reason: string;
}
export const REFERENCE_ONLY: readonly ReferenceRow[] = [
  { file: "declarations.test.ts", name: "KNOWN-DRIFT: the CLOSED-OBJECT subset agrees", reason: "the closed-node walk needs the reference box's full served reader stanzas (narrowT/K/W/R, doctorCadence, nodeResponse, paths.clerkStamps); the example does not carry them" },
  { file: "declarations.test.ts", name: "S216 · the TREE declaration IS the S216 candidate", reason: "pins the reference box's served declaration bytes (sha256) and its S34-S36 lineage" },
  { file: "declarations.test.ts", name: "GATE 1 + S201 + S26 → S28", reason: "reads the S34 declaration from reference-history commit ac55113, which a publication tree does not carry" },
  { file: "declarations.test.ts", name: "S201: the TREE declaration declares a unit for EVERY subject", reason: "a fact of the reference deployment (its systemd unit per subject); the example declares no unit" },
  { file: "declarations.test.ts", name: "GATE 2 · THE LIVE CANDIDATE'S SHAPE", reason: "rebuilds the reference box's Gate 1 + Gate 2 stanzas from the served tree; the example carries no gate1Scope reader" },
  { file: "declarations.test.ts", name: "ZERO-SUBJECTS Z0: every committed declaration loads to the SAME hash", reason: "pins the served reference tree's declaration hash" },
  { file: "mica-service.test.ts", name: "GATE 1 · THE SERVED SHAPE (S26)", reason: "pins the reference tree's own Gate 1 stanza for its served subject; the example declares none" },
  { file: "relay-sunset.test.ts", name: "⛔ THE LAID BRIDGE IS A COMMITTED STATE OF THIS LINE", reason: "compares the release laid under /opt/mica-bridge with a commit of the reference history" },
  { file: "mica-service.test.ts", name: "deploy/mica-bridge.tmpfiles.conf: re-rendering from the draft equals the committed file", reason: "the committed file was rendered on the reference box, and the renderer names each peer folder's owner by asking the host (id -nu); on any other host the render differs" },
  { file: "mica-service.test.ts", name: "POST-CLOSURE FIX 1: every routes[] uid can traverse", reason: "asks the host (id -u) for the declared peer folders' owner accounts, which exist only on the reference box" },
  { file: "mica-service.test.ts", name: "POST-CLOSURE FIX 1 regression: the traversal checker itself", reason: "asks the host (id -nu, id -nG) for each declared caller's account and groups, and needs the reference box's group provisioning to find a blocked caller" },
  { file: "relay-lib.test.sh", name: "subject_units_confirmed_inactive: the tree config must declare every subject's unit", reason: "a fact of the reference deployment (a unit per subject); the example declares none" },
];
export const REFERENCE_MODE = process.env.MICA_BRIDGE_REFERENCE_SET === "1";
/** True when this check must NOT run in the current mode (shipped: listed ones skip; reference: unlisted ones skip). */
export function skipHere(file: string, name: string): boolean {
  const listed = REFERENCE_ONLY.some((r) => r.file === file && name.startsWith(r.name));
  return REFERENCE_MODE ? !listed : listed;
}
