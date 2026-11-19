# The key these tree heads are signed with

This folder holds the public key of the organization that signs the tree heads in this repository.
The file `eformogi-org-key.jwk` is the Ed25519 public key as a JWK. Its identifier is `did:web:eformogi.com#key-1`.

The same key is served at https://eformogi.com/.well-known/did.json and is built into the verifier in the `verifier` folder.
It is kept here so that a signed tree head, a receipt and its proof can be checked with nothing from eformogi.com.

To check one proof: `node verifier/verify-offline.js proof.json --jwk keys/eformogi-org-key.jwk`

This repository is written by a daily job. A file here changes only when the file it copies has changed.
