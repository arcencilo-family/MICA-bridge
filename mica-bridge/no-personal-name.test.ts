// NO PERSONAL NAME IN WHAT THE BRIDGE PRINTS (Publication P2) — the bridge's copy; the machine holds its own
// (tools/no-personal-name.test.ts). Two copies on purpose: the trees share no code (S94).
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/no-personal-name.test.ts   (from the repo root)
//
// THE RULE (draft ticket P2, condition 1): a published MICA speaks of ROLES — the arbiter, the operator, the
// deployer, the doctor — never of a private person. No word on the hash list (NAME_HASHES) may appear in a STRING LITERAL or TEMPLATE
// LITERAL of shippable bridge source (every *.ts under mica-bridge/ except *.test.ts and *.d.ts).
//
// COMMENTS ARE ALLOWED, deliberately: the history (who ruled what, when) stays where it is read — in comments
// and in the vault. The walk uses the TypeScript compiler's own scanner, so a comment is excluded exactly.
//
// THE COMPILER is the one ts-node is running this file with (its registered instance), so this file names no
// path to any other tree. Run without ts-node, it fails loudly rather than passing.
//
// WHAT IT DOES NOT SEE, stated: non-.ts sources (relay-bridge.sh, mica-alerter.py, units); a name assembled at
// runtime from pieces; a name not on the list.
import { createHash } from "crypto";
import { readdirSync, readFileSync } from "fs";
import { join, relative, resolve } from "path";
/** The compiler module, untyped here: this tree resolves no `typescript` package of its own. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type TSModule = any;

/**
 * The declared list, as SHA-256 of the lower-cased, NFC-normalised WORD (a run of letters), not the names
 * themselves: the published tree carries no forbidden name, not even in its own fence. A literal is split into
 * letter-runs; each run is hashed and looked up here. Add to it; never shorten it without a ticket.
 */
const NAME_HASHES: ReadonlySet<string> = new Set([
  "77646f5a4f3166637627abe998e7a1470fe72d8b430f067dafa86263f1f23f94",
  "086beaf46b4b0fa4519792f181e97d5408cd9cf7222c07229d48fb7f4422f8f8",
  "500936e647e5d17905fe2e97a4396abbe1109b403d67b81b37a124da44d93bd9",
  "8e8ebed4ab57f4260ca40f49cc3b5cd79ec29e052bf55fa9de2308648abecba8",
  "c70442de124ba47f7691057dfc6be35239196b5c979d4ac5340d29e38d9fea84",
]);
function wordHash(w: string): string {
  return createHash("sha256").update(w.normalize("NFC").toLowerCase(), "utf8").digest("hex");
}
function namesWord(s: string, hashes: ReadonlySet<string>): boolean {
  return (s.match(/\p{L}+/gu) ?? []).some((w) => hashes.has(wordHash(w)));
}

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`PASS  ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL  ${name}\n      ${(e as Error).message}`);
    failed++;
  }
}
function assert(c: boolean, m: string): void {
  if (!c) throw new Error(m);
}

const HERE = resolve(__dirname);
const instance = (process as unknown as Record<symbol, { ts?: TSModule } | undefined>)[Symbol.for("ts-node.register.instance")];
const ts: TSModule | undefined = instance?.ts;

function shippable(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) shippable(p, out);
    else if (e.name.endsWith(".ts") && !e.name.endsWith(".test.ts") && !e.name.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

function namedLiterals(t: TSModule, fileName: string, text: string, hashes: ReadonlySet<string> = NAME_HASHES): string[] {
  const kinds = new Set<number>([
    t.SyntaxKind.StringLiteral,
    t.SyntaxKind.NoSubstitutionTemplateLiteral,
    t.SyntaxKind.TemplateHead,
    t.SyntaxKind.TemplateMiddle,
    t.SyntaxKind.TemplateTail,
  ]);
  const sf = t.createSourceFile(fileName, text, t.ScriptTarget.Latest, true);
  const hits: string[] = [];
  const visit = (node: TSModule): void => {
    if (kinds.has(node.kind)) {
      const s = node.getText(sf);
      if (namesWord(s, hashes)) hits.push(`${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}: ${s.slice(0, 160)}`);
    }
    t.forEachChild(node, visit);
  };
  visit(sf);
  return hits;
}

check("the compiler is reachable (the ts-node instance running this file)", () => {
  assert(ts !== undefined && typeof ts.createSourceFile === "function", "no ts-node registered instance — run this file under ts-node");
});

if (ts !== undefined) {
  const t = ts;
  check("the walker sees a name in a string, a template and a template part, and not in comments", () => {
    // The control plants a word whose hash is injected for this check only; the real list is exercised below
    // by the walk over the tree, and the demonstrated-run record (a real name planted in a copy) is in the commit.
    const planted = "zorkmid";
    const control = new Set([wordHash(planted)]);
    const src = [
      `// ${planted} ruled this in a line comment`,
      `/** ${planted} in a doc comment */`,
      `const a = '${planted}';`,
      `const b = \`${planted.toUpperCase()}\`;`,
      `const c = \`x \${a} ${planted}'s \${b} y\`;`,
      `/* ${planted} */ const d = 'the operator';`,
    ].join("\n");
    const hits = namedLiterals(t, "positive-control.ts", src, control);
    assert(hits.length === 3, `expected 3 literal hits, got ${hits.length}: ${hits.join(" | ")}`);
  });

  const files = shippable(HERE);
  check("the walk is not vacuous: it reads the shippable bridge tree", () => {
    const rels = files.map((f) => relative(HERE, f));
    assert(files.length >= 10, `only ${files.length} shippable .ts files found`);
    for (const must of ["mica-service.ts", "target-fingerprint.ts", "declarations.ts"]) assert(rels.includes(must), `${must} not walked`);
  });

  check("the hash list is live: it holds the five declared words, each a 64-hex digest", () => {
    assert(NAME_HASHES.size === 5 && [...NAME_HASHES].every((h) => /^[0-9a-f]{64}$/.test(h)), "hash list malformed");
  });

  check("no listed personal name (by hash) in a printed string of shippable bridge source", () => {
    const all = files.flatMap((f) => namedLiterals(t, f, readFileSync(f, "utf8")).map((h) => `${relative(HERE, f)}:${h}`));
    assert(all.length === 0, `${all.length} literal(s) name a person — use the role:\n      ${all.join("\n      ")}`);
  });
}

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
