#!/usr/bin/env node
// pledge-cli.mjs
//
// Operator Register pledge-building tool.
//
// Three subcommands walk an operator from scratch to a signed blob ready
// to paste into the Register's web interface:
//
//   emit      Prints one plaintext binding message per bound vote account.
//             Sign each with the vote account's key (identity or withdrawer).
//
//   assemble  Builds the canonical pledge payload from the collected per-node
//             counter-signatures and prints the bytes to stdout. Save the
//             bytes to a file, then sign them with your root identity key.
//
//   finalize  Reads the canonical bytes from a file and attaches your root
//             signature. Prints the final JSON blob to paste into the UI.
//
// Zero dependencies. Node.js 20 or later. Uses the built-in Ed25519 primitive
// via node:crypto for message hashing. All Ed25519 signing is done by the
// operator via `solana sign-offchain-message`, not by this tool.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

// -------- Base58 (hand-rolled, Bitcoin alphabet, same as Solana) --------

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = {};
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_INDEX[BASE58_ALPHABET[i]] = i;
}

function isSolanaPubkey(s) {
  return typeof s === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
}

function isBase58Signature(s) {
  // Ed25519 signatures are 64 bytes which encode to ~86-88 base58 chars.
  return typeof s === "string" && /^[1-9A-HJ-NP-Za-km-z]{80,100}$/.test(s);
}

// -------- Canonical JSON (JCS-adjacent: sort keys, no whitespace) --------

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
}

// -------- Helpers --------

function die(msg) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
}

function challenge(identityBase58, voteBase58) {
  return `register-binding-v1:identity=${identityBase58}:vote_account=${voteBase58}`;
}

function currentRegisterEpoch() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  return parseInt(`${y}${m}${d}`, 10);
}

function parseNodeSpec(spec) {
  // Formats:
  //   emit mode:     <vote_account>:<status>:<coverage>
  //   assemble mode: <vote_account>:<status>:<coverage>[:<key_type>:<counter_sig>]
  //                  (counter-sig fields required when status=bound)
  const parts = spec.split(":");
  if (parts.length < 3) {
    die(`invalid --node '${spec}' (expected vote_account:status:coverage[:key_type:counter_sig])`);
  }
  const [vote, status, coverage, keyType, counterSig] = parts;
  if (!isSolanaPubkey(vote)) die(`invalid vote account in --node: '${vote}'`);
  if (!["bound", "hosted", "excluded"].includes(status)) {
    die(`invalid status in --node '${spec}' (must be bound|hosted|excluded)`);
  }
  if (!["beneficial_interest", "conduct_control"].includes(coverage)) {
    die(`invalid coverage in --node '${spec}' (must be beneficial_interest|conduct_control)`);
  }
  const node = {
    vote_account: vote,
    status,
    oath_coverage: coverage,
    counter_sig_key_type: null,
    counter_signature: null,
  };
  if (status === "bound") {
    if (keyType === undefined && counterSig === undefined) {
      // emit mode -- counter-sig fields not required
      return node;
    }
    if (!keyType || !counterSig) {
      die(`bound node ${vote} needs :key_type:counter_sig for assemble mode`);
    }
    if (!["withdrawer", "identity"].includes(keyType)) {
      die(`invalid key_type for ${vote}: '${keyType}' (must be withdrawer|identity)`);
    }
    if (!isBase58Signature(counterSig)) {
      die(`invalid counter_sig for ${vote}: '${counterSig}' (must be base58, ~86-88 chars)`);
    }
    node.counter_sig_key_type = keyType;
    node.counter_signature = counterSig;
  } else {
    if (keyType !== undefined || counterSig !== undefined) {
      die(`non-bound node ${vote} must not carry counter_sig fields`);
    }
  }
  return node;
}

function parseArgs(argv, startIdx) {
  const args = { nodes: [] };
  for (let i = startIdx; i < argv.length; i++) {
    const key = argv[i];
    if (!key.startsWith("--")) die(`unexpected positional argument: ${key}`);
    const next = argv[i + 1];
    if (next === undefined) die(`missing value for ${key}`);
    const name = key.slice(2);
    if (name === "node") {
      args.nodes.push(next);
    } else {
      args[name] = next;
    }
    i++;
  }
  return args;
}

// -------- Subcommands --------

function cmdEmit(args) {
  if (!args.identity) die("--identity required");
  if (!isSolanaPubkey(args.identity)) die(`invalid --identity: '${args.identity}'`);
  if (args.nodes.length === 0) die("at least one --node required");

  const nodes = args.nodes.map(parseNodeSpec);
  const bound = nodes.filter(n => n.status === "bound");
  if (bound.length === 0) die("at least one bound node required");

  process.stderr.write(`\n=== Per-node binding messages ===\n`);
  process.stderr.write(`Identity: ${args.identity}\n\n`);
  process.stderr.write(`For each vote account below, sign the message with that account's\n`);
  process.stderr.write(`key (withdrawer preferred, identity acceptable):\n\n`);
  process.stderr.write(`    solana sign-offchain-message -k <keypair>.json "<message>"\n\n`);
  process.stderr.write(`Collect the base58 signatures. You will pass them to 'assemble'.\n\n`);

  for (const node of bound) {
    const msg = challenge(args.identity, node.vote_account);
    process.stdout.write(`${node.vote_account}\n`);
    process.stdout.write(`  ${msg}\n`);
    process.stdout.write(`\n`);
  }
}

function cmdAssemble(args) {
  if (!args.identity) die("--identity required");
  if (!args.continuation) die("--continuation required");
  if (!args["rules-hash"]) die("--rules-hash required");
  if (!args["oracles-hash"]) die("--oracles-hash required");
  if (args.nodes.length === 0) die("at least one --node required");

  if (!isSolanaPubkey(args.identity)) die(`invalid --identity: '${args.identity}'`);
  if (!isSolanaPubkey(args.continuation)) die(`invalid --continuation: '${args.continuation}'`);
  if (!/^[0-9a-f]{64}$/i.test(args["rules-hash"])) die(`--rules-hash must be 64 hex chars`);
  if (!/^[0-9a-f]{64}$/i.test(args["oracles-hash"])) die(`--oracles-hash must be 64 hex chars`);

  const nodes = args.nodes.map(parseNodeSpec);
  const bound = nodes.filter(n => n.status === "bound");
  if (bound.length === 0) die("at least one bound node required");
  for (const n of bound) {
    if (!n.counter_signature) die(`bound node ${n.vote_account} missing counter_sig in assemble mode`);
  }

  // Reject duplicates.
  const seen = new Set();
  for (const n of nodes) {
    if (seen.has(n.vote_account)) die(`duplicate vote account: ${n.vote_account}`);
    seen.add(n.vote_account);
  }

  const epoch = args.epoch ? parseInt(args.epoch, 10) : currentRegisterEpoch();
  if (!Number.isInteger(epoch) || epoch < 20000000 || epoch > 99999999) {
    die(`invalid --epoch: ${args.epoch} (expected YYYYMMDD)`);
  }
  const signedAtUtc = args["signed-at"] ?? new Date().toISOString();
  if (Number.isNaN(new Date(signedAtUtc).getTime())) {
    die(`invalid --signed-at: '${signedAtUtc}' (expected ISO 8601)`);
  }
  const signedAtSlot = args["signed-at-slot"] ?? "0";

  const payload = {
    type: "operator-pledge.v1",
    identity_pubkey: args.identity,
    continuation_pubkey: args.continuation,
    register_rules_hash: args["rules-hash"].toLowerCase(),
    oracles_hash: args["oracles-hash"].toLowerCase(),
    covers_epochs: [epoch, epoch + 1, epoch + 2, epoch + 3],
    signed_at_slot: signedAtSlot,
    signed_at_utc: signedAtUtc,
    nodes: nodes.slice().sort((a, b) => a.vote_account.localeCompare(b.vote_account)),
  };

  const canonical = canonicalize(payload);
  const sha = createHash("sha256").update(canonical, "utf8").digest("hex");
  const bytes = Buffer.byteLength(canonical, "utf8");

  process.stderr.write(`\n=== Canonical pledge payload ===\n`);
  process.stderr.write(`identity:        ${args.identity}\n`);
  process.stderr.write(`continuation:    ${args.continuation}\n`);
  process.stderr.write(`register_rules:  ${payload.register_rules_hash}\n`);
  process.stderr.write(`oracles:         ${payload.oracles_hash}\n`);
  process.stderr.write(`covers_epochs:   ${payload.covers_epochs.join(", ")}\n`);
  process.stderr.write(`nodes:           ${nodes.length} (${bound.length} bound)\n`);
  process.stderr.write(`signed_at_utc:   ${signedAtUtc}\n`);
  process.stderr.write(`bytes:           ${bytes}\n`);
  process.stderr.write(`sha256:          ${sha}\n\n`);
  process.stderr.write(`Save these canonical bytes to a file, then sign them with your root key:\n\n`);
  process.stderr.write(`    node pledge-cli.mjs assemble ... > pledge.canonical\n`);
  process.stderr.write(`    solana sign-offchain-message -k <root-keypair>.json "$(cat pledge.canonical)"\n\n`);
  process.stderr.write(`Then run 'finalize' with the resulting signature.\n\n`);

  process.stdout.write(canonical);
}

function cmdFinalize(args) {
  if (!args.from) die("--from <path> required (file written by 'assemble')");
  if (!args["root-sig"]) die("--root-sig required (base58 signature from solana sign-offchain-message)");
  if (!isBase58Signature(args["root-sig"])) {
    die(`invalid --root-sig: '${args["root-sig"]}' (must be base58, ~86-88 chars)`);
  }
  const fmt = args["root-sig-format"] ?? "restricted-ascii";
  if (!["restricted-ascii", "utf8"].includes(fmt)) {
    die(`--root-sig-format must be restricted-ascii|utf8, got '${fmt}'`);
  }

  let canonical;
  try {
    canonical = readFileSync(args.from, "utf8");
  } catch (err) {
    die(`cannot read --from file '${args.from}': ${err.message}`);
  }
  // Strip a single trailing newline if present (common with shell > redirects).
  if (canonical.endsWith("\n")) canonical = canonical.slice(0, -1);

  // Sanity check that the file looks like a canonical pledge payload.
  let parsed;
  try {
    parsed = JSON.parse(canonical);
  } catch (err) {
    die(`--from file is not valid JSON: ${err.message}`);
  }
  if (parsed?.type !== "operator-pledge.v1") {
    die(`--from file is not an operator-pledge.v1 payload (type='${parsed?.type}')`);
  }

  const sha = createHash("sha256").update(canonical, "utf8").digest("hex");

  const blob = {
    canonical,
    root_sig: args["root-sig"],
    root_sig_format: fmt,
  };

  process.stderr.write(`\n=== Final pledge blob ===\n`);
  process.stderr.write(`canonical bytes: ${Buffer.byteLength(canonical, "utf8")}\n`);
  process.stderr.write(`canonical sha256: ${sha}\n`);
  process.stderr.write(`root_sig_format: ${fmt}\n\n`);
  process.stderr.write(`Paste the JSON below into the Register's web interface:\n`);
  process.stderr.write(`---\n`);

  process.stdout.write(JSON.stringify(blob, null, 2));
  process.stdout.write("\n");
}

// -------- Main --------

function usage() {
  process.stderr.write(`
Operator Register pledge-building tool.

Usage:
  node pledge-cli.mjs emit --identity <base58> \\
    --node <vote_account>:bound:beneficial_interest \\
    [--node <vote_account>:hosted:conduct_control] \\
    [--node <vote_account>:excluded:beneficial_interest]

  node pledge-cli.mjs assemble --identity <base58> \\
    --continuation <base58> \\
    --rules-hash <64hex> --oracles-hash <64hex> \\
    --node <vote_account>:bound:beneficial_interest:identity:<counter_sig> \\
    [--node <vote_account>:hosted:conduct_control] \\
    [--epoch <YYYYMMDD>] [--signed-at <ISO8601>] [--signed-at-slot <N>]

  node pledge-cli.mjs finalize --from <canonical.json> \\
    --root-sig <base58> [--root-sig-format restricted-ascii|utf8]

Subcommands:
  emit      Print one plaintext binding message per bound vote account.
            Sign each with: solana sign-offchain-message -k <keypair>.json <message>

  assemble  Build the canonical pledge payload. Prints to stdout. Save the
            output to a file, then sign the file contents with your root key.

  finalize  Attach a root signature to a saved canonical payload. Prints the
            final JSON blob to paste into the Register's web interface.

See README.md for the full ceremony flow.
`);
  process.exit(1);
}

function main() {
  const argv = process.argv;
  if (argv.length < 3) usage();
  const subcmd = argv[2];
  if (subcmd === "--help" || subcmd === "-h" || subcmd === "help") usage();
  const args = parseArgs(argv, 3);
  if (subcmd === "emit") cmdEmit(args);
  else if (subcmd === "assemble") cmdAssemble(args);
  else if (subcmd === "finalize") cmdFinalize(args);
  else {
    process.stderr.write(`unknown subcommand: ${subcmd}\n`);
    usage();
  }
}

main();
