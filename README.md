# Operator Register

Public toolkit for signing an Operator Register pledge. The Register itself is a public record of Solana validator operators who stand behind their own conduct. Its governing documents (the Rules, the Pledge, and the designated oracles) are durably stored on Arweave and anchored on Solana mainnet.


## What this is

A zero-dependency Node.js tool that helps an operator produce the signed blob the Register needs to add them to the roster.

## How to use

Three steps:

1. **Emit per-node binding messages.** The tool prints one plaintext message per vote account in your fleet. These are what each vote account signs to prove you control it.

2. **Sign each message.** Use `solana sign-offchain-message -k <keypair>.json "<message>"` with each vote account's identity key or withdrawer key. Also sign the canonical pledge payload with your root identity key.

3. **Assemble the final blob.** Pass the signed challenges back to the tool along with your root signature. It prints a JSON blob you paste into the Register's web interface.

See `node pledge-cli.mjs --help` for the full flag reference, and the inline examples at the top of `pledge-cli.mjs`.

## Requirements

- Node.js 20 or later (uses the built-in Ed25519 primitive via `node:crypto`)
- The `solana` CLI, for `sign-offchain-message`
- No `npm install`. Zero dependencies.

## Reading the Register

The Rules, Pledge, and oracles bundle live inside the Register itself. See `docs/README.md` for how to read them.

## License

Apache 2.0. See `LICENSE`.
