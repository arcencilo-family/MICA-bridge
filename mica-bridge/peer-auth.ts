// ── peer-auth — how a connection's uid is known, and how it is authorized ──
//
// FORK, named plainly rather than routed around (see the Stage 2 receipt,
// "Peer credentials — the fork"): Node's core `net`/`http` modules expose NO
// way to read SO_PEERCRED (the kernel's actual peer-uid answer for a
// connected AF_UNIX socket). The two honest options were:
//
//   (a) a tiny native addon (node-gyp, a compiled binding) reading
//       SO_PEERCRED directly. Not built: Stage 0's discipline ("no runtime
//       deps beyond Node... ts-node runs it") extends to Stage 2 by the same
//       logic, and a native addon is exactly the kind of thing that breaks
//       silently between Node versions and deploy boxes (the box already
//       runs `/usr/bin/node` v18.19.1 for the unit and nvm's v22.22.0 in this
//       shell — a native addon compiled against one may not load under the
//       other without a rebuild step nobody has scheduled).
//   (b) a per-caller socket path with filesystem ownership, so the peer is
//       identified by WHICH socket it connected to, never by asking the
//       kernel who is on the other end.
//
// (b) is what this file implements: one Unix socket per `declarations.
// routes[]` row, at `<socketDir>/peers/<uid>/guard.sock`. The directory
// `<socketDir>/peers/<uid>/` must be owned `<uid>:mica-bridge`, mode EXACTLY
// 0770 (an ARBITER ACT — root/tmpfiles creates it, the way `mica-housekeeper`
// and `mica-callers` were created mid-session for Stage 0).
//
// AMENDMENT 3 / VERIFIER F1 — the boundary was not enforced and is now the
// whole point of this file. The prior version of this module CREATED a
// missing directory itself and checked only its mode, never its owner: run
// as an unprivileged uid (e.g. 1000), it happily created all three peer
// directories AS THAT UID and bound every socket, so a connection to the
// uid-980 path was trusted as uid 980 while nothing had verified the
// directory belonged to uid 980 at all. That is not a peer-identity
// boundary; it is a peer-identity assumption. Fixed:
//
//   - `validatePeerDir()` NEVER creates a directory. A missing directory is
//     a startup refusal, not something to provision on the fly — the
//     service (`User=mica-bridge`) has no privilege to chown to another uid
//     in the first place, so "create it if missing" could never have
//     produced a correctly-owned directory outside a dev accident.
//   - It checks, in order, and refuses on the FIRST failure: the path
//     exists and is a directory; `st.uid === route.uid` EXACTLY (not "close
//     enough", not "or root"); `st.gid === gid("mica-bridge")` EXACTLY; the
//     permission bits are EXACTLY 0770 (`st.mode & 0o777 === 0o770`) — not
//     "0770 or tighter", since a tighter mode (e.g. 0700) would mean the
//     `mica-bridge` group — which the SERVICE runs as — could not even
//     enter the directory to create the socket file, and a looser mode
//     would carry a world or extra bit this boundary depends on being
//     absent.
//   - `MicaBridgeService.start()` validates EVERY declared route's
//     directory BEFORE binding ANY socket. One bad directory refuses the
//     entire startup (exit 2) — a service that bound the good sockets and
//     silently skipped the bad one would be exactly the "half-authorized"
//     shape a verifier should never have to discover by probing.
//   - After a successful `listen()`, the socket FILE itself is chmoded
//     0666. This is deliberate, not a hole: the DIRECTORY is the boundary
//     (0770, no world bit, owned by the one uid allowed to enter it); the
//     socket file inside only needs to be connectable BY that uid, and that
//     uid is not a member of group `mica-bridge` (verified live on this box
//     — `mica-housekeeper`'s groups are `mica-housekeeper,mica-callers`,
//     `mica-bridge`'s own group is `mica-bridge,mica-readers` — no overlap).
//     A socket left at the service's own default mode (0750 under this
//     unit's `UMask=0027`, owned `mica-bridge:mica-bridge`) is NOT writable
//     by uid 980, who holds none of `mica-bridge`'s bits — the verifier
//     caught exactly this in F1. Widening the socket file's own mode is
//     safe here BECAUSE reaching that file at all already required passing
//     through the 0770, non-world, correctly-owned directory: nothing
//     outside that directory's owning uid (or root) can even resolve the
//     path to open the socket in the first place.
//
// Root can always connect regardless of any of this — a real, stated
// limitation, irrelevant to Phase A because no `routes[]` row may name uid
// 0 (Stage 0's rule X10) and no Phase A caller runs as root.
//
// This means: for THIS mechanism, the "peer uid" used everywhere below is
// not read from a credential at all — it is the uid the socket's OWN
// directory was verified to belong to, closure-captured at bind time. A
// connection that reaches the service handler on the uid-980 listener IS,
// by construction (0770 directory, EXACT uid/gid/mode match), a connection
// from uid 980 or from root. Nothing in this file claims otherwise.

import { existsSync, statSync, chmodSync, readFileSync } from "fs";
import { join } from "path";
import type { Route, RouteAllow } from "./declarations";

/**
 * `getgrnam`-equivalent: resolves a group name to a gid by parsing
 * `/etc/group` directly (no `child_process` spawn, no dependency). Returns
 * `null` if the group does not exist or `/etc/group` cannot be read — both
 * are startup refusals at the call site, never a silently-skipped check.
 */
export function resolveGid(groupName: string): number | null {
  let text: string;
  try {
    text = readFileSync("/etc/group", "utf8");
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const fields = line.split(":");
    if (fields[0] === groupName && fields[2] !== undefined) {
      const gid = Number(fields[2]);
      return Number.isInteger(gid) ? gid : null;
    }
  }
  return null;
}

export interface PeerSocketPlan {
  readonly uid: number;
  readonly role: Route["role"];
  readonly socketPath: string;
  readonly socketDir: string;
}

/** One socket path per declared route row, under `<socketDir>/peers/<uid>/guard.sock`. */
export function planPeerSockets(routes: readonly Route[], socketDir: string): readonly PeerSocketPlan[] {
  return routes.map((r) => {
    const dir = join(socketDir, "peers", String(r.uid));
    return { uid: r.uid, role: r.role, socketPath: join(dir, "guard.sock"), socketDir: dir };
  });
}

export type PeerDirCheck =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

const EXACT_PEER_DIR_MODE = 0o770;

/**
 * Verifies `<socketDir>/peers/<uid>/` — NEVER creates it (F1). Refuses on
 * the first mismatch: missing, not a directory, wrong owning uid, wrong
 * owning gid (must be exactly `mica-bridge`'s), or any mode but exactly
 * 0770. `bridgeGid` is resolved once by the caller (`resolveGid("mica-bridge")`)
 * and passed in so a missing `mica-bridge` group fails loudly at the one
 * call site that discovers it, not silently inside every plan's check.
 */
export function validatePeerDir(plan: PeerSocketPlan, bridgeGid: number): PeerDirCheck {
  if (!existsSync(plan.socketDir)) {
    return { ok: false, reason: `${plan.socketDir} does not exist — this service never creates route directories (F1); provision it via tmpfiles.d` };
  }
  let st;
  try {
    st = statSync(plan.socketDir);
  } catch (err) {
    return { ok: false, reason: `${plan.socketDir}: ${String(err)}` };
  }
  if (!st.isDirectory()) {
    return { ok: false, reason: `${plan.socketDir} exists but is not a directory` };
  }
  if (st.uid !== plan.uid) {
    return { ok: false, reason: `${plan.socketDir} is owned by uid ${st.uid}, expected exactly ${plan.uid}` };
  }
  if (st.gid !== bridgeGid) {
    return { ok: false, reason: `${plan.socketDir} has gid ${st.gid}, expected exactly ${bridgeGid} (mica-bridge)` };
  }
  const mode = st.mode & 0o777;
  if (mode !== EXACT_PEER_DIR_MODE) {
    return { ok: false, reason: `${plan.socketDir} is mode ${mode.toString(8)}, expected exactly ${EXACT_PEER_DIR_MODE.toString(8)}` };
  }
  return { ok: true };
}

/**
 * Widens the SOCKET FILE (never the directory) to 0666 after `listen()`
 * succeeds. Safe only because reaching this path at all already required
 * passing through the 0770, correctly-owned, non-world directory
 * `validatePeerDir` just checked — see this file's header, "the DIRECTORY
 * is the boundary."
 */
export function widenSocketFileMode(socketPath: string): void {
  chmodSync(socketPath, 0o666);
}

// ── route authorization — pure, testable independently of any socket ──────

export type AuthzResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly httpStatus: 403 | 405; readonly reason: string };

/**
 * Per-route authorization (brief Stage 2, Codex 4·2: "authorization is per
 * route, not per group"). `peerUid` here is whatever the caller identified
 * the connection as — in production, the uid whose socket accepted the
 * connection (see the header); in a test, an injected value, exactly as the
 * coordinator's note 4 permits ("test the authorization function directly
 * with injected creds and say so" — this is that function).
 */
export function authorizeRoute(
  routes: readonly Route[],
  peerUid: number,
  method: "GET" | "POST",
  path: RouteAllow["path"]
): AuthzResult {
  const row = routes.find((r) => r.uid === peerUid);
  if (!row) {
    return { allowed: false, httpStatus: 403, reason: `uid ${peerUid} has no routes[] row` };
  }
  const grant = row.allow.find((a) => a.method === method && a.path === path);
  if (!grant) {
    const methodExists = row.allow.some((a) => a.path === path);
    const httpStatus = methodExists ? 405 : 403;
    return {
      allowed: false,
      httpStatus,
      reason: `uid ${peerUid} (role ${row.role}) is not granted ${method} ${path}`,
    };
  }
  return { allowed: true };
}

/**
 * X12's runtime twin (Stage 0 checks it at load time; this checks it is
 * actually being respected at the socket layer): a subject's peerUid may
 * bind only through the uid-matching listener. Returns true iff `peerUid`
 * is the uid declared for `subjectPeerUid`.
 */
export function peerBoundToSubject(peerUid: number, subjectPeerUid: number): boolean {
  return peerUid === subjectPeerUid;
}
