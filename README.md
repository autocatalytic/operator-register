# Operator Register

Public toolkit for signing an Operator Register pledge. The Register itself is a public record of Solana validator operators who stand behind their own conduct. Its governing documents (the Rules, the Pledge, and the designated oracles) are durably stored on Arweave and anchored on Solana mainnet.


## What this is

A zero-dependency Node.js tool that walks an operator through signing a pledge against the current Register. The tool fetches your vote accounts from mainnet to auto-detect which keypair role you're using, spawns `solana sign-offchain-message` for each signature so your private keys never leave the `solana` CLI, and prints a JSON blob you paste into the Register's web interface.

## How to use

Clone the repo, then run:

```
node pledge-cli.mjs sign
```

The tool prints the current Rules, Pledge, oracles bundle, and infrastructure keys with their Arweave URLs and on-chain SAS addresses so you can verify what you're signing against. It then walks you through four steps:

1. **Your root identity keypair.** The key that signs the pledge itself. In production this is your validator identity key, held offline.
2. **Your continuation key.** In v0 this is a shared key the Register holds in secure hardware; the tool uses it by default. See `docs/infrastructure-keys-v0.md` for details.
3. **Your bound vote accounts.** For each one, the tool fetches the vote account from mainnet, auto-detects whether your keypair is the withdrawer or the identity key, and spawns `solana sign-offchain-message` to sign the per-account binding.
4. **Signing the pledge.** The tool builds the canonical pledge bytes and signs them with your root key.

At the end you get a JSON blob to paste into the Register's "Paste signed package" field.

For scripted use (CI, batch ceremonies), `emit`, `assemble`, and `finalize` subcommands remain available. See `node pledge-cli.mjs --help`.

## Prerequisites

Before you run `node pledge-cli.mjs sign`, make sure you have:

- **Node.js 20 or later.** Verify with `node --version`.
- **The Solana CLI.** The ceremony spawns `solana sign-offchain-message` and `solana vote-account` under the hood; your private keys never leave the Solana CLI. Install from https://docs.anza.xyz/cli/install.
- **Solana CLI set to mainnet-beta.** The Register runs on Solana mainnet; vote accounts, Rules, Pledge template, and Oracles bundle all live there. Set it with:

      solana config set --url mainnet-beta

  The pledge tool passes `--url mainnet-beta` explicitly on each command, but setting the default also keeps the rest of your Solana workflow (balance checks, keypair derivation) consistent.
- No `npm install`. Zero dependencies.

## Reading the Register

The Rules, Pledge, and oracles bundle live inside the Register itself. See `docs/README.md` for how to read them.

## License

Apache 2.0. See `LICENSE`.
