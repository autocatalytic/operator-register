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

## Requirements

- Node.js 20 or later (uses the built-in Ed25519 primitive via `node:crypto`)
- The `solana` CLI, for `sign-offchain-message`
- No `npm install`. Zero dependencies.

## Reading the Register

The Rules, Pledge, and oracles bundle live inside the Register itself. See `docs/README.md` for how to read them.

## License

Apache 2.0. See `LICENSE`.
