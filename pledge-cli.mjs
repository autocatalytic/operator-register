#!/usr/bin/env node
// pledge-cli.mjs
//
// Operator Register pledge-building tool.
//
// Primary command:
//
//   sign      Interactive end-to-end ceremony. Prompts for your keypair paths,
//             spawns 'solana sign-offchain-message' for each signature, and
//             prints the final JSON blob to paste into the Register's web
//             interface. This tool never reads your private keys; it only
//             orchestrates the standard 'solana' CLI.
//
// Scripted-use subcommands (for integrators who want finer control):
//
//   emit      Print one plaintext binding message per bound vote account.
//   assemble  Build canonical pledge payload from collected counter-sigs.
//   finalize  Attach operator signature to a saved canonical payload.
//
// Zero dependencies. Node.js 20 or later. Requires 'solana' CLI on PATH for
// 'sign' subcommand. All Ed25519 signing is done by the operator via
// 'solana sign-offchain-message'; this tool never touches your private keys.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { homedir } from "node:os";
import { resolve as pathResolve } from "node:path";

// Expand a leading '~' to the operator's home directory so paths like
// '~/.config/solana/id.json' work from any prompt. Node's fs calls do not
// expand '~' the way shells do.
function resolvePath(p) {
  if (typeof p !== "string" || p.length === 0) return p;
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return pathResolve(homedir(), p.slice(2));
  return pathResolve(p);
}

// -------- Current Register version pins (bump on each Rules revision) --------

const CURRENT_RULES = {
  version: "v0.11",
  arweave_tx: "ojoqksJ_n32JfnnKCGyY64ZyjcMUijmEh5nsWwbAszo",
  arweave_url: "https://arweave.net/ojoqksJ_n32JfnnKCGyY64ZyjcMUijmEh5nsWwbAszo",
  sha256: "c21ec6230b592d43c4201b542fc6760aec53e9bd92b8cd31a949b7a61bb02352",
  sas_pda: "3T7ws2dkXvqy68Lt6UusqGVm85JFtuHriPuurBQk5VrW",
};

const CURRENT_ORACLES = {
  version: "v0.1",
  arweave_tx: "Eh8Q8I6a3lyO5FIqJxlIks6pUYrn7MN3qQdNpNJBtgQ",
  arweave_url: "https://arweave.net/Eh8Q8I6a3lyO5FIqJxlIks6pUYrn7MN3qQdNpNJBtgQ",
  sha256: "c9411cae3ae91acf02f478f6bed1e30774f4a7a57b9a14e2eb3c5f90e2f44b82",
  sas_pda: "6QWR4QErF4ygnjRfPfULamfs8u3HFCg5wFm1S1EzYXP8",
};

const CURRENT_PLEDGE = {
  version: "v0.3",
  arweave_tx: "M5zzpo4a39fi9IysLrqf595wiMUMT2ayFiC-QUD9mVI",
  arweave_url: "https://arweave.net/M5zzpo4a39fi9IysLrqf595wiMUMT2ayFiC-QUD9mVI",
  sha256: "02a2dcfae4aa2829415c50fb157c21f524949b783b22bfb28ae125292ed11eb5",
  sas_pda: "6VBX5pGWcy7d2rCH54z6vXtJKHAtMm8k5prFbu51aCQv",
};

// Register-held infrastructure keys. v0 ships with the Register holding the
// continuation key in non-extractable KMS; operators consent by naming it in
// their pledge. Rotations ship as a new continuation_pubkey here and a new
// CLI release; operators pull and re-pledge against the new key.
const CURRENT_INFRA_KEYS = {
  continuation_pubkey: "J7socF4aMnzkP9uh52STQ1hFuryvAxHh94AQmBoKWtVo",
};

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

function challenge(operatorBase58, voteBase58) {
  return `register-binding-v2:operator=${operatorBase58}:vote_account=${voteBase58}`;
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

// -------- Child-process signing (sign subcommand only) --------

function checkSolanaCli() {
  const r = spawnSync("solana", ["--version"], { encoding: "utf8" });
  if (r.status !== 0) {
    die(
      "'solana' CLI not found on PATH.\n" +
      "Install it from https://docs.anza.xyz/cli/install and re-run.",
    );
  }
  return r.stdout.trim();
}

function checkSolanaClusterDefault() {
  // Non-fatal: the tool passes --url mainnet-beta on every spawn that touches
  // the chain, so a mismatched local default never breaks the ceremony. We
  // warn anyway so operators who are mid-devnet-session see a reminder that
  // Register state (vote accounts, Rules, Pledge, Oracles) lives on mainnet.
  const r = spawnSync("solana", ["config", "get", "json_rpc_url"], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const match = r.stdout.match(/RPC URL:\s*(\S+)/);
  const url = match ? match[1] : r.stdout.trim();
  if (!/mainnet-beta|mainnet\.helius-rpc|api\.mainnet-beta\.solana/.test(url)) {
    process.stdout.write(
      `\nNote: your local 'solana' CLI default cluster is '${url}', not mainnet-beta.\n` +
      `  This tool passes --url mainnet-beta explicitly, so the ceremony will work.\n` +
      `  To align the rest of your Solana workflow, run:\n` +
      `    solana config set --url mainnet-beta\n`,
    );
  }
  return url;
}

function spawnSign(keypairPath, message) {
  // Spawn solana sign-offchain-message as a child process. The private key
  // bytes never leave the 'solana' CLI; this tool only passes the keypair
  // FILE PATH and the message text.
  const r = spawnSync(
    "solana",
    ["sign-offchain-message", "-k", keypairPath, message],
    { encoding: "utf8" },
  );
  if (r.status !== 0) {
    die(
      `solana sign-offchain-message failed (exit ${r.status}):\n` +
      `  stdout: ${r.stdout?.trim() || "(empty)"}\n` +
      `  stderr: ${r.stderr?.trim() || "(empty)"}`,
    );
  }
  const sig = r.stdout.trim();
  if (!isBase58Signature(sig)) {
    die(`solana returned unexpected output (expected base58 signature):\n${sig}`);
  }
  return sig;
}

function solanaAddress(keypairPath) {
  // Resolve the pubkey for a given keypair file. Used to confirm which
  // identity the operator is actually using before any signing.
  const r = spawnSync(
    "solana-keygen",
    ["pubkey", keypairPath],
    { encoding: "utf8" },
  );
  if (r.status !== 0) {
    die(
      `solana-keygen pubkey failed for '${keypairPath}' (exit ${r.status}):\n` +
      `  stderr: ${r.stderr?.trim() || "(empty)"}`,
    );
  }
  const pk = r.stdout.trim();
  if (!isSolanaPubkey(pk)) {
    die(`solana-keygen returned unexpected pubkey: '${pk}'`);
  }
  return pk;
}

function solanaVoteAccount(voteAccountPubkey) {
  // Fetch an on-chain vote account via the 'solana' CLI against mainnet-beta
  // and return the two keys needed for counter-sig verification: the
  // authorized withdrawer and the validator identity (nodePubkey).
  //
  // --url mainnet-beta is passed explicitly so the operator's local 'solana
  // config get' default (which may point at devnet or localhost for other
  // work) does not surprise us.
  const r = spawnSync(
    "solana",
    [
      "vote-account", voteAccountPubkey,
      "--url", "mainnet-beta",
      "--output", "json-compact",
    ],
    { encoding: "utf8" },
  );
  if (r.status !== 0) {
    die(
      `solana vote-account failed for '${voteAccountPubkey}' (exit ${r.status}):\n` +
      `  stderr: ${r.stderr?.trim() || "(empty)"}`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(r.stdout);
  } catch (err) {
    die(`solana returned non-JSON for '${voteAccountPubkey}':\n${r.stdout.trim()}`);
  }
  const identity = parsed.nodePubkey ?? parsed.validatorIdentity;
  const withdrawer = parsed.authorizedWithdrawer;
  if (!isSolanaPubkey(identity) || !isSolanaPubkey(withdrawer)) {
    die(
      `solana vote-account did not expose the expected keys for '${voteAccountPubkey}'.\n` +
      `  parsed: ${JSON.stringify(parsed).slice(0, 200)}...`,
    );
  }
  return { identity, withdrawer };
}

// -------- Interactive 'sign' subcommand --------

async function cmdSign() {
  const rl = createInterface({ input: stdin, output: stdout });
  const ask = async (q) => (await rl.question(q)).trim();
  const askYN = async (q, def) => {
    const d = def === true ? "Y/n" : "y/N";
    const a = (await ask(`${q} [${d}] `)).toLowerCase();
    if (a === "") return def;
    return a === "y" || a === "yes";
  };

  try {
    process.stdout.write(`
=== Operator Register pledge ceremony ===

This tool walks you through signing a pledge against the current Register
documents. Nothing is sent to the chain or to any server by this tool; the
final step is a JSON blob you paste into the Register's web interface.

Current Register versions you are about to pledge against:

  Rules (${CURRENT_RULES.version})
    sha256:  ${CURRENT_RULES.sha256}
    Arweave: ${CURRENT_RULES.arweave_url}
    on-chain: ${CURRENT_RULES.sas_pda}

  Oracles bundle (${CURRENT_ORACLES.version})
    sha256:  ${CURRENT_ORACLES.sha256}
    Arweave: ${CURRENT_ORACLES.arweave_url}
    on-chain: ${CURRENT_ORACLES.sas_pda}

  Pledge text (${CURRENT_PLEDGE.version})
    sha256:  ${CURRENT_PLEDGE.sha256}
    Arweave: ${CURRENT_PLEDGE.arweave_url}
    on-chain: ${CURRENT_PLEDGE.sas_pda}

  Current continuation key: ${CURRENT_INFRA_KEYS.continuation_pubkey}

Fetch each Arweave URL and run 'shasum -a 256' against the file if you want
to verify the hashes above before signing. The web interface will reject a
pledge that does not match the current Rules + Oracles hashes.

`);

    const proceed = await askYN("Ready to begin?", true);
    if (!proceed) {
      rl.close();
      process.stderr.write("Aborted.\n");
      return;
    }

    const solanaVersion = checkSolanaCli();
    process.stdout.write(`\nFound: ${solanaVersion}\n`);
    checkSolanaClusterDefault();

    // ---- Step 1: Operator keypair ----

    process.stdout.write(`
=== Step 1 of 4: Your operator key ===

The operator key is a dedicated key you create specifically for the
Register. It signs the pledge, the completeness oath, and any change to
the bound fleet. It is your name on the roll.

IMPORTANT: this is NOT your validator identity key, NOT your withdrawer
key, and NOT any other key your validator uses in daily operation. The
Rules recommend a dedicated key held offline between ceremonies.

If you don't have an operator key yet, generate one:
  solana-keygen new -o ./operator.json

You MAY instead sign with a key from validator operation (identity or
withdrawer); the Register will accept it and the risk is yours (a key
that signs votes is online). Rotation to a dedicated key is available
later per Rules §7.8.

`);
    const operatorPath = resolvePath(await ask("Path to your operator keypair file: "));
    if (!operatorPath || !existsSync(operatorPath)) {
      die(`keypair file not found: '${operatorPath}'`);
    }
    const operatorPubkey = solanaAddress(operatorPath);
    process.stdout.write(`  pubkey: ${operatorPubkey}\n`);
    const operatorOk = await askYN("Is this the right operator key?", true);
    if (!operatorOk) {
      rl.close();
      process.stderr.write("Aborted.\n");
      return;
    }

    // ---- Step 2: Continuation key (Register-held in v0) ----

    process.stdout.write(`
=== Step 2 of 4: The continuation key ===

The continuation key signs a daily "still standing" message that keeps your
pledge fresh between re-pledges. In v0, the Register holds this key in
non-extractable KMS. By signing a pledge that names it, you consent to that
key emitting daily on your behalf.

A compromised continuation key can at worst stop your clock; it cannot
re-swear or expand your pledge, so the custody risk is bounded.

Future versions will let you designate any key you choose, including one
you hold directly.

  Current continuation key: ${CURRENT_INFRA_KEYS.continuation_pubkey}

`);
    const continuationPubkey = CURRENT_INFRA_KEYS.continuation_pubkey;
    const consentCont = await askYN("Consent to this continuation key?", true);
    if (!consentCont) {
      rl.close();
      process.stderr.write("Aborted.\n");
      return;
    }

    // ---- Step 3: Vote accounts + per-node signatures ----

    process.stdout.write(`
=== Step 3 of 4: Bound vote accounts ===

List each vote account you are binding to this pledge. For each one, you
will provide the path to a keypair that controls it: either the account's
withdrawer keypair (preferred) or its validator identity keypair.

This tool fetches the vote account from mainnet-beta and auto-detects which
role your keypair plays (withdrawer or identity) by comparing the derived
pubkey against the on-chain state. If neither matches, the keypair does not
control this vote account and the ceremony aborts.

Signing is done by 'solana sign-offchain-message'; the private key never
leaves the solana CLI.

Enter vote accounts one at a time. When done, leave the input blank.

`);
    const nodes = [];
    const seen = new Set();
    let idx = 0;
    while (true) {
      idx++;
      const vote = await ask(
        `  Vote account ${idx} (base58 pubkey, blank to finish): `,
      );
      if (!vote) break;
      if (!isSolanaPubkey(vote)) {
        process.stdout.write(`    not a valid base58 pubkey; try again.\n`);
        idx--;
        continue;
      }
      if (seen.has(vote)) {
        process.stdout.write(`    already listed; try again.\n`);
        idx--;
        continue;
      }
      seen.add(vote);

      process.stdout.write(`    fetching ${vote.slice(0, 8)}... from mainnet-beta...\n`);
      const onChain = solanaVoteAccount(vote);
      process.stdout.write(`      withdrawer: ${onChain.withdrawer}\n`);
      process.stdout.write(`      identity:   ${onChain.identity}\n`);

      const kpPath = resolvePath(await ask(
        `    Path to keypair controlling ${vote.slice(0, 8)}...: `,
      ));
      if (!kpPath || !existsSync(kpPath)) {
        die(`keypair file not found: '${kpPath}'`);
      }
      const kpPubkey = solanaAddress(kpPath);
      let kpKind;
      if (kpPubkey === onChain.withdrawer) {
        kpKind = "withdrawer";
      } else if (kpPubkey === onChain.identity) {
        kpKind = "identity";
      } else {
        die(
          `keypair at '${kpPath}' derives to '${kpPubkey}',\n` +
          `  which is neither the withdrawer ('${onChain.withdrawer}')\n` +
          `  nor the identity ('${onChain.identity}') for vote account '${vote}'.\n` +
          `  This keypair does not control that vote account.`,
        );
      }
      process.stdout.write(`    detected: ${kpKind} key (${kpPubkey})\n`);

      const msg = challenge(operatorPubkey, vote);
      process.stdout.write(`    signing: ${msg}\n`);
      const sig = spawnSign(kpPath, msg);
      process.stdout.write(`    signature: ${sig.slice(0, 20)}...\n`);

      nodes.push({
        vote_account: vote,
        status: "bound",
        oath_coverage: "beneficial_interest",
        counter_sig_key_type: kpKind,
        counter_signature: sig,
      });
    }
    if (nodes.length === 0) {
      die("at least one bound vote account is required");
    }

    // ---- Step 4: Build canonical, sign root, print blob ----

    process.stdout.write(`
=== Step 4 of 4: Sign the full pledge ===

Building canonical pledge bytes and signing with your operator key...

`);
    const epoch = currentRegisterEpoch();
    const signedAtUtc = new Date().toISOString();
    const payload = {
      type: "operator-pledge.v2",
      operator_pubkey: operatorPubkey,
      continuation_pubkey: continuationPubkey,
      register_rules_hash: CURRENT_RULES.sha256,
      oracles_hash: CURRENT_ORACLES.sha256,
      pledge_template_hash: CURRENT_PLEDGE.sha256,
      covers_epochs: [epoch, epoch + 1, epoch + 2, epoch + 3],
      signed_at_slot: "0",
      signed_at_utc: signedAtUtc,
      nodes: nodes.slice().sort((a, b) =>
        a.vote_account.localeCompare(b.vote_account),
      ),
    };
    const canonical = canonicalize(payload);
    const canonicalSha = createHash("sha256")
      .update(canonical, "utf8")
      .digest("hex");

    process.stdout.write(`  canonical bytes: ${Buffer.byteLength(canonical, "utf8")}\n`);
    process.stdout.write(`  canonical sha256: ${canonicalSha}\n`);
    process.stdout.write(`  covers epochs: ${payload.covers_epochs.join(", ")}\n`);
    process.stdout.write(`  signing with operator keypair at ${operatorPath}...\n`);

    const operatorSig = spawnSign(operatorPath, canonical);
    process.stdout.write(`  operator signature: ${operatorSig.slice(0, 20)}...\n`);

    const blob = {
      canonical,
      operator_sig: operatorSig,
      operator_sig_format: "restricted-ascii",
    };

    process.stdout.write(`\n=== Done ===\n\n`);
    process.stdout.write(
      `Paste the JSON below into the Register's "Paste signed package" field.\n` +
      `Optionally save a copy; it is safe to keep (it is public once anchored).\n\n` +
      `---\n`,
    );
    rl.close();
    process.stdout.write(JSON.stringify(blob, null, 2));
    process.stdout.write("\n");
  } catch (err) {
    rl.close();
    throw err;
  }
}

// -------- Scripted subcommands (unchanged behavior) --------

function cmdEmit(args) {
  if (!args.operator) die("--operator required");
  if (!isSolanaPubkey(args.operator)) die(`invalid --operator: '${args.operator}'`);
  if (args.nodes.length === 0) die("at least one --node required");

  const nodes = args.nodes.map(parseNodeSpec);
  const bound = nodes.filter(n => n.status === "bound");
  if (bound.length === 0) die("at least one bound node required");

  process.stderr.write(`\n=== Per-node binding ceremony ===\n`);
  process.stderr.write(`Operator: ${args.operator}\n\n`);
  process.stderr.write(`For each vote account below, run the printed command with the path to\n`);
  process.stderr.write(`that account's keypair (withdrawer preferred, identity acceptable).\n`);
  process.stderr.write(`Collect the base58 signatures. You will pass them to 'assemble'.\n`);

  for (const node of bound) {
    const msg = challenge(args.operator, node.vote_account);
    process.stdout.write(`\n=== Vote account ${node.vote_account} - sign this ===\n\n`);
    process.stdout.write(`solana sign-offchain-message -k <withdrawer-or-identity-keypair>.json \\\n`);
    process.stdout.write(`  '${msg}'\n\n`);
    process.stdout.write(`(Replace <...-keypair> with the path to your keypair file. The quoted\n`);
    process.stdout.write(`string is the entire message; the quotes themselves are shell syntax,\n`);
    process.stdout.write(`not part of what gets signed.)\n`);
  }
}

function cmdAssemble(args) {
  if (!args.operator) die("--operator required");
  if (!args.continuation) die("--continuation required");
  if (!args["rules-hash"]) die("--rules-hash required");
  if (!args["oracles-hash"]) die("--oracles-hash required");
  if (!args["pledge-hash"]) die("--pledge-hash required");
  if (args.nodes.length === 0) die("at least one --node required");

  if (!isSolanaPubkey(args.operator)) die(`invalid --operator: '${args.operator}'`);
  if (!isSolanaPubkey(args.continuation)) die(`invalid --continuation: '${args.continuation}'`);
  if (!/^[0-9a-f]{64}$/i.test(args["rules-hash"])) die(`--rules-hash must be 64 hex chars`);
  if (!/^[0-9a-f]{64}$/i.test(args["oracles-hash"])) die(`--oracles-hash must be 64 hex chars`);
  if (!/^[0-9a-f]{64}$/i.test(args["pledge-hash"])) die(`--pledge-hash must be 64 hex chars`);

  const nodes = args.nodes.map(parseNodeSpec);
  const bound = nodes.filter(n => n.status === "bound");
  if (bound.length === 0) die("at least one bound node required");
  for (const n of bound) {
    if (!n.counter_signature) die(`bound node ${n.vote_account} missing counter_sig in assemble mode`);
  }

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
    type: "operator-pledge.v2",
    operator_pubkey: args.operator,
    continuation_pubkey: args.continuation,
    register_rules_hash: args["rules-hash"].toLowerCase(),
    oracles_hash: args["oracles-hash"].toLowerCase(),
    pledge_template_hash: args["pledge-hash"].toLowerCase(),
    covers_epochs: [epoch, epoch + 1, epoch + 2, epoch + 3],
    signed_at_slot: signedAtSlot,
    signed_at_utc: signedAtUtc,
    nodes: nodes.slice().sort((a, b) => a.vote_account.localeCompare(b.vote_account)),
  };

  const canonical = canonicalize(payload);
  const sha = createHash("sha256").update(canonical, "utf8").digest("hex");
  const bytes = Buffer.byteLength(canonical, "utf8");

  process.stderr.write(`\n=== Canonical pledge payload ===\n`);
  process.stderr.write(`operator:        ${args.operator}\n`);
  process.stderr.write(`continuation:    ${args.continuation}\n`);
  process.stderr.write(`register_rules:  ${payload.register_rules_hash}\n`);
  process.stderr.write(`oracles:         ${payload.oracles_hash}\n`);
  process.stderr.write(`pledge_template: ${payload.pledge_template_hash}\n`);
  process.stderr.write(`covers_epochs:   ${payload.covers_epochs.join(", ")}\n`);
  process.stderr.write(`nodes:           ${nodes.length} (${bound.length} bound)\n`);
  process.stderr.write(`signed_at_utc:   ${signedAtUtc}\n`);
  process.stderr.write(`bytes:           ${bytes}\n`);
  process.stderr.write(`sha256:          ${sha}\n\n`);
  process.stderr.write(`Save these canonical bytes to a file, then sign them with your operator key:\n\n`);
  process.stderr.write(`    node pledge-cli.mjs assemble ... > pledge.canonical\n`);
  process.stderr.write(`    solana sign-offchain-message -k <operator-keypair>.json "$(cat pledge.canonical)"\n\n`);
  process.stderr.write(`Then run 'finalize' with the resulting signature.\n\n`);

  process.stdout.write(canonical);
}

function cmdFinalize(args) {
  if (!args.from) die("--from <path> required (file written by 'assemble')");
  if (!args["operator-sig"]) die("--operator-sig required (base58 signature from solana sign-offchain-message)");
  if (!isBase58Signature(args["operator-sig"])) {
    die(`invalid --operator-sig: '${args["operator-sig"]}' (must be base58, ~86-88 chars)`);
  }
  const fmt = args["operator-sig-format"] ?? "restricted-ascii";
  if (!["restricted-ascii", "utf8"].includes(fmt)) {
    die(`--operator-sig-format must be restricted-ascii|utf8, got '${fmt}'`);
  }

  let canonical;
  const fromPath = resolvePath(args.from);
  try {
    canonical = readFileSync(fromPath, "utf8");
  } catch (err) {
    die(`cannot read --from file '${fromPath}': ${err.message}`);
  }
  if (canonical.endsWith("\n")) canonical = canonical.slice(0, -1);

  let parsed;
  try {
    parsed = JSON.parse(canonical);
  } catch (err) {
    die(`--from file is not valid JSON: ${err.message}`);
  }
  if (parsed?.type !== "operator-pledge.v2") {
    die(`--from file is not an operator-pledge.v2 payload (type='${parsed?.type}')`);
  }

  const sha = createHash("sha256").update(canonical, "utf8").digest("hex");

  const blob = {
    canonical,
    operator_sig: args["operator-sig"],
    operator_sig_format: fmt,
  };

  process.stderr.write(`\n=== Final pledge blob ===\n`);
  process.stderr.write(`canonical bytes: ${Buffer.byteLength(canonical, "utf8")}\n`);
  process.stderr.write(`canonical sha256: ${sha}\n`);
  process.stderr.write(`operator_sig_format: ${fmt}\n\n`);
  process.stderr.write(`Paste the JSON below into the Register's web interface:\n`);
  process.stderr.write(`---\n`);

  process.stdout.write(JSON.stringify(blob, null, 2));
  process.stdout.write("\n");
}

// -------- Main --------

function usage() {
  process.stderr.write(`
Operator Register pledge-building tool.

Primary command:

  node pledge-cli.mjs sign

    Interactive end-to-end ceremony. Prompts for your keypair paths, spawns
    'solana sign-offchain-message' for each signature, and prints the final
    JSON blob to paste into the Register's web interface.

Scripted-use subcommands (for integrators who want finer control):

  node pledge-cli.mjs emit --operator <base58> \\
    --node <vote_account>:bound:beneficial_interest ...

  node pledge-cli.mjs assemble --operator <base58> \\
    --continuation <base58> \\
    --rules-hash <64hex> --oracles-hash <64hex> --pledge-hash <64hex> \\
    --node <vote_account>:bound:beneficial_interest:identity:<counter_sig> ...

  node pledge-cli.mjs finalize --from <canonical.json> \\
    --operator-sig <base58> [--operator-sig-format restricted-ascii|utf8]

See README.md for the full ceremony flow.
`);
  process.exit(1);
}

async function main() {
  const argv = process.argv;
  if (argv.length < 3) usage();
  const subcmd = argv[2];
  if (subcmd === "--help" || subcmd === "-h" || subcmd === "help") usage();
  if (subcmd === "sign") {
    await cmdSign();
    return;
  }
  const args = parseArgs(argv, 3);
  if (subcmd === "emit") cmdEmit(args);
  else if (subcmd === "assemble") cmdAssemble(args);
  else if (subcmd === "finalize") cmdFinalize(args);
  else {
    process.stderr.write(`unknown subcommand: ${subcmd}\n`);
    usage();
  }
}

main().catch((err) => die(err?.stack ?? String(err)));
