// Cross-runtime parity harness for the counterparty co-signature.
//
// Verifies the Concordia-produced fixture
// (tests/fixtures/concordia_cosigned_receipt.json) on V8 / Node using
// Concordia's JavaScript implementation of RFC 8785 JCS canonicalization plus
// the recursive signature-stripping rule. The implementation is written
// against the RFC 8785 and Concordia SPEC byte contract, and the Python test
// suite validates it against the independent rfc8785 package.
//
// If Concordia's Python canonical_json diverges from V8's JSON.stringify
// behavior for JCS-relevant bytes (string escaping, number formatting, key
// sort), the Ed25519 signature produced by the Python producer fails to verify
// here. Exits 0 on PASS, 1 on verification failure, 2 on error.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { verifyCounterpartyCosignatureStructural } from "./cosignature.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const fixturePath = join(
  repoRoot,
  "tests",
  "fixtures",
  "concordia_cosigned_receipt.json",
);

function main() {
  let fixture;
  try {
    fixture = JSON.parse(readFileSync(fixturePath, "utf-8"));
  } catch (err) {
    console.error(`[ERROR] cannot read fixture ${fixturePath}: ${err.message}`);
    process.exit(2);
  }

  const ok = verifyCounterpartyCosignatureStructural(
    fixture.receipt,
    fixture.counterparty_did,
    fixture.publisher_did,
  );

  if (ok && fixture.expected_counterparty_verified === true) {
    console.log("PARITY: cosign fixture verifies under V8/Node JCS verifier");
    process.exit(0);
  }
  console.log(
    `PARITY FAIL: verify=${ok}, expected=${fixture.expected_counterparty_verified}`,
  );
  process.exit(1);
}

main();
