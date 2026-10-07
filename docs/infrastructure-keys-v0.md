# Register Infrastructure Keys v0

Keys the Register holds in secure hardware (non-extractable KMS) for v0 operation. Operators consent to these when they sign a pledge that names them.

## Continuation key

Pubkey (base58): J7socF4aMnzkP9uh52STQ1hFuryvAxHh94AQmBoKWtVo
Purpose: emits daily continuation attestations per Rules §4.4.
Rotation: a new key ships as a new entry in this doc; the pledge CLI defaults to the current entry. Operators re-pledge against the new key when they next renew.

## Where this lives

This doc records which keys are currently active. What each key does is written in the Rules. Authority comes from the pledge payload itself, which names the specific key.

Readers verifying an attestation chain cite the pledge payload for the key, not this doc.
