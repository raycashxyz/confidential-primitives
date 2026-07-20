// Typecheck wrapper: `tsc --noEmit`, but tolerant of type errors that originate INSIDE
// node_modules — and nothing else.
//
// Why not a bare `tsc --noEmit`: tevm (1.0.0-next) and its nested `ox` copies ship raw
// .ts SOURCE rather than .d.ts. `tsc` type-checks imported .ts files and there is no way
// to skip them (`skipLibCheck` only skips declaration files), so a couple of pre-existing
// type errors inside `ox/tempo/KeyAuthorization.ts` surface on every run. We cannot fix
// third-party source, so a bare `tsc` would be permanently red and useless as a gate.
//
// This wrapper is STRICTER than a prefix filter: it fails on ANY error not under
// node_modules (i.e. anything in our own code, wherever it lives) and on a tsc invocation
// failure that produced no diagnostics (a crash), while letting the known upstream noise
// through. Drop this wrapper and call `tsc` directly once tevm ships declarations.
import { execSync } from "node:child_process";

let output = "";
let tscThrew = false;
try {
  output = execSync("node_modules/.bin/tsc --noEmit --pretty false", {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
} catch (err) {
  tscThrew = true;
  output = `${err.stdout ?? ""}${err.stderr ?? ""}`;
}

const errorLines = output.split("\n").filter((line) => /error TS\d+:/.test(line));
const ourErrors = errorLines.filter((line) => !line.startsWith("node_modules/"));

if (ourErrors.length > 0) {
  console.error("typecheck: FAILED — type errors in project code:\n");
  console.error(ourErrors.join("\n"));
  process.exit(1);
}

// tsc exited non-zero but emitted no attributable diagnostics → a real invocation failure
// (bad tsconfig, OOM, missing binary), not tolerated upstream noise.
if (tscThrew && errorLines.length === 0) {
  console.error("typecheck: FAILED — tsc did not run cleanly:\n");
  console.error(output || "(no output)");
  process.exit(1);
}

const upstream = errorLines.length - ourErrors.length;
console.error(
  `typecheck: OK — project code is clean` +
    (upstream > 0 ? ` (${upstream} tolerated error(s) inside node_modules)` : ""),
);
process.exit(0);
