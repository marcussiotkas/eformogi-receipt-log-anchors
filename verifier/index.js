/**
 * @eformogi/verify-offline
 *
 * The programmatic face of the reference verifier for The Record
 * (protocol draft 0.1). verify-offline.js is the command line and the
 * algorithms; this file wraps its proof check in a structured result and
 * re-exports the primitives so an issuer can derive ids and check its own
 * output against the reference before publishing anything.
 *
 * Copyright 2026 Eformogi, Inc. Licensed under the Apache License,
 * Version 2.0. See the LICENSE file next to this one.
 *
 *   const { verifyProof } = require('@eformogi/verify-offline');
 *   const result = verifyProof(proofJson, { sha256: hashOfTheArtifactYouHold });
 *   // { verified, pending, steps: [{ ok, name, detail? }], notes: [string] }
 *
 * Nothing here reads the network, the environment, or the file system.
 */

'use strict';

const core = require('./verify-offline.js');
const { version } = require('./package.json');

const SPEC_DRAFT = '0.1';

/**
 * Resolve the organization key a caller handed us. Accepts a bare
 * Ed25519 public JWK ({ x }) or a whole DID document (the shape of
 * /.well-known/did.json). With a DID document, the verification method
 * whose fragment matches preferredKeyId wins, then the first usable one.
 * Throws when a DID document carries no usable key, or names no method
 * matching a preferred key id, so a caller cannot silently verify against
 * a key other than the one the tree head names.
 */
function resolvePublicJwk(input, preferredKeyId) {
  if (input === undefined || input === null) return core.ORG_PUBLIC_JWK;
  if (typeof input !== 'object') throw new Error('jwk must be an Ed25519 public JWK or a DID document');
  if (typeof input.x === 'string') return { kty: 'OKP', crv: 'Ed25519', x: input.x };
  const methods = Array.isArray(input.verificationMethod) ? input.verificationMethod : [];
  const usable = methods.filter((m) => m && m.publicKeyJwk && typeof m.publicKeyJwk.x === 'string');
  if (usable.length === 0) throw new Error('no Ed25519 public key found (expected a JWK or a DID document)');
  const fragment = String(preferredKeyId || '').split('#')[1] || '';
  if (fragment) {
    const named = usable.find((m) => String(m.id || '').split('#')[1] === fragment);
    if (!named) throw new Error(`the DID document has no verification method "#${fragment}", which is the key the tree head names`);
    return named.publicKeyJwk;
  }
  return usable[0].publicKeyJwk;
}

/**
 * Verify one receipt proof, exactly as the command line does, and return
 * every step instead of printing it.
 *
 * @param {object|string} proof  the proof document (the file behind
 *   "Download proof (JSON)" on a verify page, or /api/receipt-proof), as
 *   a parsed object or a JSON string. A string that is not valid JSON is
 *   not thrown on: it comes back as a result whose first step, "proof is
 *   a JSON object", failed, with the parse error as its detail.
 * @param {object} [options]
 * @param {object} [options.jwk]     the organization public key: an
 *   Ed25519 JWK or a DID document; defaults to the published key. This
 *   is the caller's own input, not the proof's, so an unusable value
 *   THROWS rather than failing a step: a jwk that is neither a JWK nor a
 *   DID document, a DID document with no usable Ed25519 key, or one that
 *   has no verification method matching the key the tree head names.
 * @param {string} [options.sha256]  the SHA-256 of the artifact you hold,
 *   compared with the sha256 inside the logged leaf
 * @param {object} [options.statement]  a signed statement file (chapter
 *   03, section 3.12) the holder handed you, checked against the hash
 *   the proof names. A proof that names no statement fails a step when
 *   one is passed.
 * @returns {{ verified: boolean, pending: boolean, receipt_id: string|null,
 *             steps: Array<{ ok: boolean, name: string, detail?: string }>,
 *             notes: string[] }}
 *   verified is true only when every step passed. A pending proof (no
 *   signed head covers the leaf yet) reports pending true and verified
 *   false. receipt_id is the id inside the LOGGED LEAF (null when the
 *   leaf could not be read), never the file's own top-level label, which
 *   the first step compares against it. notes are advisory and never
 *   change the verdict.
 */
function verifyProof(proof, options = {}) {
  let doc = proof;
  if (typeof proof === 'string') {
    try {
      doc = JSON.parse(proof);
    } catch (e) {
      return {
        verified: false,
        pending: false,
        receipt_id: null,
        steps: [{ ok: false, name: 'proof is a JSON object', detail: `not valid JSON: ${e.message}` }],
        notes: [],
      };
    }
  }
  const preferred = doc && typeof doc === 'object' && doc.sth && typeof doc.sth.key_id === 'string' ? doc.sth.key_id : '';
  const jwk = resolvePublicJwk(options.jwk, preferred);
  return core.verifyProofSteps(doc, jwk, options.sha256, options.statement !== undefined ? { statement: options.statement } : {});
}

/**
 * Verify one signed statement file on its own (chapter 03, section 3.12):
 * the key named inside the signed words signed exactly those words. It
 * shows nothing about whose record the words are on; a receipt's proof,
 * checked with this file, does.
 *
 * @param {object|string} file  the statement file, parsed or as JSON text
 * @returns {{ verified: boolean, sha256: string|null,
 *             steps: Array<{ ok: boolean, name: string, detail?: string }>,
 *             notes: string[] }}
 */
function verifyStatement(file) {
  let doc = file;
  if (typeof file === 'string') {
    try {
      doc = JSON.parse(file);
    } catch (e) {
      return { verified: false, sha256: null, steps: [{ ok: false, name: 'the file is a signed statement (v 1, kind credit)', detail: `not valid JSON: ${e.message}` }], notes: [] };
    }
  }
  return core.verifyStatementSteps(doc, {});
}

module.exports = {
  ...core,
  verifyProof,
  verifyStatement,
  resolvePublicJwk,
  VERSION: version,
  SPEC_DRAFT,
};
