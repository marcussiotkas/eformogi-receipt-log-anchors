#!/usr/bin/env node
/**
 * spec/verifier/verify-offline.js
 *
 * The reference offline verifier for the Record (Draft 0.1).
 * Single file, no dependencies beyond node:crypto and node:fs, no network.
 *
 * Copyright 2026 Eformogi, Inc. Licensed under the Apache License,
 * Version 2.0. See the LICENSE file next to this one, or
 * https://eformogi.com/spec/verifier/LICENSE-Apache-2.0.txt
 *
 * Derived from scripts/verify-receipt-offline.js (copied, not moved) and
 * widened to cover every check the specification makes normative:
 * canonical JSON, receipt-id derivation per prefix, the kb_ key binding,
 * family and organization Ed25519 signatures under their context prefixes,
 * the RFC 6962 Merkle log (leaf and node domains, inclusion proofs, signed
 * tree heads), the four-step inclusion-proof algorithm of chapter 06, and
 * the eddsa-jcs-2022 credential proof of chapter 07.
 *
 * Two modes, chosen from the file you hand it (a conformance vector
 * carries `check`; a receipt proof carries leaf bytes or a tree head):
 *
 *   node verify-offline.js <vector.json>
 *     Conformance mode. Runs the vector's check against its input, prints
 *     each step, and exits 0 only when the computed verdict matches the
 *     vector's expected verdict (and expected values, where the vector
 *     carries them). A vector that EXPECTS a failure passes when the
 *     verifier correctly refuses.
 *
 *   node verify-offline.js <proof.json> [--jwk pub.jwk|did.json] [--sha256 <hex>]
 *     Receiver mode. Verifies a real /api/receipt-proof response (the file
 *     behind "Download proof (JSON)" on any verify page): leaf hash,
 *     inclusion, the signed tree head, and the family signature when the
 *     proof carries one. Exit 0 iff every step passes. `--proof <file>`
 *     forces this mode.
 *
 *   node verify-offline.js <statement.json>
 *   node verify-offline.js <proof.json> --statement <statement.json>
 *     A statement a signer wrote and signed with their own key (chapter
 *     03, section 3.12). The first form checks the file alone: the key
 *     named inside the signed words signed exactly those words. The
 *     second also checks that the words are the ones the receipt in the
 *     proof was signed from.
 *
 * Node 18 or newer (Ed25519 in node:crypto). The published organization key
 * is embedded below; pass --jwk to pin a key you fetched yourself.
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

// ─── Published organization key (did:web:eformogi.com#key-1) ───────
const ORG_PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'Oo09J95ausJIDH4nnNNy6wfKgveRbGgDsX9V3Y0xyMQ',
};

// ─── Context prefixes (chapter 02, 03, 04, 05). Frozen. ────────────
const SIG_CONTEXT = 'eformogi-receipt-sig-v1:';
// A signer's own signature on an attestation (chapter 03; added Nov 18 2026).
const ATT_SIG_CONTEXT = 'eformogi-attestation-sig-v1:';
// A statement a signer wrote and signed with their own key (chapter 03,
// section 3.12; added Nov 18 2026).
const CREDIT_SIG_CONTEXT = 'eformogi-credit-sig-v1:';
const COUNTERSIG_CONTEXT = 'eformogi-witness-countersig-v1:';
const STH_CONTEXT = 'eformogi-sth-v1:';

// Receipt kinds eligible for the public log. ecr_ (institutional) and
// tl_ (private timeline) are deliberately absent.
const RECEIPT_PREFIXES = ['tr', 'cr', 'ws', 'wn', 'wl', 'att', 'kb'];

// ─── Canonical JSON (chapter 02) ───────────────────────────────────
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

function assertJcsSafe(obj, path = '$') {
  if (obj === null) return;
  const t = typeof obj;
  if (t === 'number') {
    if (!Number.isInteger(obj)) throw new Error(`non-integer number at ${path}`);
    return;
  }
  if (t === 'string' || t === 'boolean') return;
  if (t === 'undefined') throw new Error(`undefined at ${path}`);
  if (Array.isArray(obj)) { obj.forEach((v, i) => assertJcsSafe(v, `${path}[${i}]`)); return; }
  if (t === 'object') { for (const k of Object.keys(obj)) assertJcsSafe(obj[k], `${path}.${k}`); return; }
  throw new Error(`unsupported value type "${t}" at ${path}`);
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function idFromCanonical(prefix, canonicalStr) {
  const sha256 = sha256Hex(canonicalStr);
  return { id: prefix + '_' + sha256.slice(0, 12), sha256 };
}

// ─── Leaf payload (chapter 02 §leaf grammar) ───────────────────────
function buildLeafPayload({ receipt_id, prefix, sha256, issued_at }) {
  if (!RECEIPT_PREFIXES.includes(prefix)) throw new Error(`invalid prefix "${prefix}"`);
  if (typeof receipt_id !== 'string' || !receipt_id.trim()) throw new Error('receipt_id required');
  const sha = String(sha256 || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(sha)) throw new Error('invalid sha256 (expected 64 hex chars)');
  const d = new Date(issued_at);
  if (isNaN(d.getTime())) throw new Error(`invalid issued_at "${issued_at}"`);
  const leaf = { receipt_id: receipt_id.toLowerCase(), prefix, sha256: sha, issued_at: d.toISOString() };
  assertJcsSafe(leaf);
  return canonicalize(leaf);
}

// ─── Per-prefix hash domains (chapter 02 §derivations) ─────────────
function clip(v, max) {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (!t) return null;
  return t.length > max ? t.slice(0, max) : t;
}

function deriveTr(payload) {
  // The whole issuance payload is the hash domain (chapter 02, tr_).
  return idFromCanonical('tr', canonicalize(payload));
}

function deriveCr(course) {
  const student_name = clip(course.student_name, 200);
  const course_title = clip(course.course_title, 300);
  const term = clip(course.term, 100);
  const grade = clip(course.grade, 32);
  if (!student_name || !course_title || !term || !grade) throw new Error('cr_: student_name, course_title, term, grade required');
  const credits = course.credits == null || course.credits === '' ? null : String(course.credits);
  const payload = { kind: 'course', student_name, course_title, term, grade, credits };
  return idFromCanonical('cr', canonicalize(payload));
}

function deriveAtt(a) {
  const signer_name = clip(a.signer_name, 120);
  const signer_role = clip(a.signer_role, 120);
  if (!signer_name || !signer_role) throw new Error('att_: signer_name and signer_role required');
  const signer_organization = clip(a.signer_organization, 200);
  const statement = clip(a.statement, 1000);
  const hasWs = !!a.ws_receipt_id;
  const hasCr = !!a.cr_receipt_id;
  if (hasWs === hasCr) throw new Error('att_: exactly one of ws_receipt_id or cr_receipt_id');
  const publicPayload = hasWs
    ? {
        ws_receipt_id: a.ws_receipt_id,
        signer: { name: signer_name, role: signer_role, organization: signer_organization || null },
        statement: statement || null,
      }
    : {
        cr_receipt_id: a.cr_receipt_id,
        signer: {
          name: signer_name,
          role: signer_role,
          organization: signer_organization || null,
          relationship: clip(a.signer_relationship, 200),
        },
        // A null grade is a Portrait evidence signature (chapter 03 section
        // 3.4, chapter 08 section 8.7): the witness signed what they saw
        // on the course row and not the grade. The field stays in the
        // domain as null, exactly as organization and statement can be.
        signed_grade: clip(a.signed_grade, 32) || null,
        statement: statement || null,
      };
  if (hasCr && !publicPayload.signer.relationship) {
    throw new Error('att_: signer_relationship required for cr_ targets');
  }
  const email_raw = clip(a.signer_email, 320);
  const hashInput = { ...publicPayload, email_hash_input: (email_raw || '').toLowerCase() };
  return idFromCanonical('att', canonicalize(hashInput));
}

function deriveWs(w) {
  const e = w.entry || {};
  const useV2 = Boolean(e.evidence_sha256) && !e.evidence_url;
  const payload = useV2
    ? {
        v: 2,
        entry: { kind: e.kind, title: e.title, detail: e.detail || null, evidence_sha256: e.evidence_sha256, at: e.at },
        issuer: (w.issuer || 'Family Records Office').trim(),
        person_id: w.person_id || null,
        source_entry_id: w.source_entry_id,
      }
    : {
        entry: { kind: e.kind, title: e.title, detail: e.detail || null, evidence_url: e.evidence_url || null, at: e.at },
        issuer: (w.issuer || 'Family Records Office').trim(),
        person_id: w.person_id || null,
        source_entry_id: w.source_entry_id,
      };
  return idFromCanonical('ws', canonicalize(payload));
}

function deriveWn(n) {
  const body = typeof n.body === 'string' ? n.body.trim() : '';
  if (!body) throw new Error('wn_: empty body');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(n.week_of || '')) throw new Error('wn_: week_of must be YYYY-MM-DD');
  const payload = { kind: 'weekly_note', author: 'kid', week_of: n.week_of, body };
  return idFromCanonical('wn', canonicalize(payload));
}

function deriveWl(w) {
  const payload = { kind: 'wall', curator: w.curator, person_id: w.person_id || null, created_at: w.created_at };
  const out = idFromCanonical('wl', canonicalize(payload));
  // The wall's mutable snapshot hash is sha256 of the JSON array of pinned ids, in order.
  if (Array.isArray(w.pinned_ids)) out.snapshot_sha256 = sha256Hex(JSON.stringify(w.pinned_ids));
  return out;
}

// ─── base58btc ─────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58btcEncode(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) { carry += digits[j] * 256; digits[j] = carry % 58; carry = Math.floor(carry / 58); }
    while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}
function base58btcDecode(str) {
  if (typeof str !== 'string') throw new Error('base58btcDecode expects a string');
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = [];
  for (let i = zeros; i < str.length; i++) {
    const v = B58.indexOf(str[i]);
    if (v === -1) throw new Error(`invalid base58 character "${str[i]}"`);
    let carry = v;
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes.reverse())]);
}

// ─── Ed25519 ───────────────────────────────────────────────────────
function verifyBytes(bytes, signature, publicJwk) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x }, format: 'jwk' });
    return crypto.verify(null, bytes, key, signature);
  } catch { return false; }
}
function verifyContextSig(context, multibaseSig, messageStr, publicJwk) {
  try {
    if (typeof multibaseSig !== 'string' || multibaseSig[0] !== 'z') return false;
    return verifyBytes(Buffer.from(context + messageStr, 'utf8'), base58btcDecode(multibaseSig.slice(1)), publicJwk);
  } catch { return false; }
}

// did:key for an Ed25519 public key: multicodec ed25519-pub (0xed 0x01) || raw key, base58btc, multibase 'z'.
function didKeyFromPublicJwk(publicJwk) {
  const pub = Buffer.from(publicJwk.x, 'base64url');
  if (pub.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return 'did:key:z' + base58btcEncode(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
}

// kb_ key-binding payload (chapter 04). Frozen.
function buildKbPayload({ key_id, public_jwk, established_at }) {
  if (typeof key_id !== 'string' || !key_id.startsWith('did:key:z')) throw new Error('key_id must be a did:key');
  const d = new Date(established_at);
  if (isNaN(d.getTime())) throw new Error('invalid established_at');
  const payload = { established_at: d.toISOString(), key_id, public_jwk: { crv: 'Ed25519', kty: 'OKP', x: String(public_jwk.x) } };
  assertJcsSafe(payload);
  return canonicalize(payload);
}

// ─── Merkle log (chapter 05) ───────────────────────────────────────
function hexTo32(hex, what) {
  if (typeof hex !== 'string' || !/^[a-f0-9]{64}$/i.test(hex)) throw new Error(`${what} must be 64 hex chars`);
  return Buffer.from(hex, 'hex');
}
function leafHash(payloadUtf8) {
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(payloadUtf8, 'utf8')])).digest('hex');
}
function nodeHash(leftHex, rightHex) {
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), hexTo32(leftHex, 'left'), hexTo32(rightHex, 'right')])).digest('hex');
}
function chainHash(prevHex, leafHashHex) {
  return crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x02]), hexTo32(prevHex, 'prev'), hexTo32(leafHashHex, 'leaf')])).digest('hex');
}
const GENESIS_CHAIN = '0'.repeat(64);
function largestPowerOfTwoBelow(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }
function merkleRoot(leafHashesHex) {
  const n = leafHashesHex.length;
  if (n === 0) return crypto.createHash('sha256').update('').digest('hex');
  if (n === 1) return leafHashesHex[0].toLowerCase();
  const k = largestPowerOfTwoBelow(n);
  return nodeHash(merkleRoot(leafHashesHex.slice(0, k)), merkleRoot(leafHashesHex.slice(k)));
}
function verifyInclusion({ leafHashHex, leafIndex, treeSize, auditPath, rootHex }) {
  try {
    if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return false;
    if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;
    if (!Array.isArray(auditPath)) return false;
    let fn = leafIndex;
    let sn = treeSize - 1;
    let r = leafHashHex.toLowerCase();
    for (const p of auditPath) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = nodeHash(p, r);
        if (fn % 2 === 0) {
          while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
        }
      } else {
        r = nodeHash(r, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && r === rootHex.toLowerCase();
  } catch { return false; }
}
const STH_SIGNED_FIELDS = ['version', 'log_id', 'tree_size', 'root_hash', 'chain_hash', 'timestamp', 'key_id'];
function verifySth(sth, publicJwk) {
  try {
    if (!sth || typeof sth !== 'object') return false;
    if (typeof sth.signature !== 'string' || !sth.signature.startsWith('z')) return false;
    const body = {};
    for (const k of STH_SIGNED_FIELDS) if (k in sth) body[k] = sth[k];
    assertJcsSafe(body);
    return verifyBytes(Buffer.from(STH_CONTEXT + canonicalize(body), 'utf8'), base58btcDecode(sth.signature.slice(1)), publicJwk);
  } catch { return false; }
}

// ─── eddsa-jcs-2022 credential proof (chapter 07) ──────────────────
function verifyCredentialProof(credential, publicJwk) {
  try {
    if (!credential || !credential.proof) return { verified: false, error: 'No proof found on credential' };
    const { proof, ...C } = credential;
    if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') {
      return { verified: false, error: 'Unsupported proof' };
    }
    if (typeof proof.proofValue !== 'string' || !proof.proofValue.startsWith('z')) {
      return { verified: false, error: 'proofValue must be multibase base58btc' };
    }
    const { proofValue, ...P } = proof;
    const h = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest();
    const signInput = Buffer.concat([h(canonicalize(P)), h(canonicalize(C))]);
    const ok = verifyBytes(signInput, base58btcDecode(proofValue.slice(1)), publicJwk);
    return ok ? { verified: true } : { verified: false, error: 'Signature verification failed' };
  } catch (e) { return { verified: false, error: e.message }; }
}

// ─── Step reporter ─────────────────────────────────────────────────
const results = [];
function step(okBool, name, detail) {
  console.log(`${okBool ? '✓' : '✗'} ${name}${detail ? ` (${detail})` : ''}`);
  results.push(okBool);
  return okBool;
}
function safe(fn) { try { return fn(); } catch (e) { return { __error: e.message }; } }

// ─── A statement a signer wrote (chapter 03, section 3.12) ─────────
//
// statementSteps is the whole check of a signed statement file. It needs
// nothing but the file: the key's id is inside the signed words, and a
// did:key id is the public key. `s` records a step and `note` a note, so
// the same checks run alone and inside a proof. Returns the statement's
// hash, or null when the file is not a statement at all.
function statementSteps(file, s, note) {
  const st = file && typeof file === 'object' && !Array.isArray(file) ? file.statement : null;
  const shaped = !!st && typeof st === 'object' && !Array.isArray(st) && st.v === 1 && st.kind === 'credit'
    && typeof st.key_id === 'string' && typeof file.sig === 'string';
  s(shaped, 'the file is a signed statement (v 1, kind credit)');
  if (!shaped) return null;

  // The hash is over the canonical form of the statement exactly as it
  // is in the file. Nothing is trimmed, reordered by meaning, or
  // repaired: a statement with one character changed is another
  // statement, and its signature does not verify.
  const sha = crypto.createHash('sha256').update(canonicalize(st), 'utf8').digest('hex');
  if (file.sha256 !== undefined) {
    s(file.sha256 === sha, 'sha256 is the hash of the statement as written', file.sha256 === sha ? sha.slice(0, 16) + '...' : `computed ${sha}`);
  }
  const derived = safe(() => didKeyFromPublicJwk(file.public_jwk || {}));
  s(derived === st.key_id, 'the key named inside the signed words is the public key in this file',
    derived === st.key_id ? st.key_id : `derived ${JSON.stringify(derived)}`);
  const keyOk = derived === st.key_id;
  const sigOk = s(verifyContextSig(CREDIT_SIG_CONTEXT, file.sig, JSON.stringify({ sha256: sha }), file.public_jwk) === true,
    'that key signed these exact words');

  // The words are printed either way, and the line above them says
  // whether they were shown to be signed.
  const who = st.signer && typeof st.signer === 'object' ? st.signer : {};
  note(keyOk && sigOk ? '· the words that were signed:' : '· the words in this file, which were NOT shown to be signed:');
  note(`    for:      ${st.for_name}`);
  note(`    what:     ${st.what}`);
  note(`    when:     ${st.when}`);
  if (st.hours !== undefined) note(`    hours:    ${st.hours}`);
  note(`    by:       ${[who.name, who.role, who.organization].filter(Boolean).join(', ')}`);
  note(`    written:  ${st.written_at}`);
  note('· note: a key shows the same signer each time, not who the signer is. The name, the role and the organization are what the signer wrote about themselves.');
  return sha;
}

// ─── The four-step proof algorithm (chapter 06) ────────────────────
//
// verifyProofSteps is the algorithm; it collects every step and note and
// returns them, printing nothing on its own. verifyProof below is the
// CLI's view of it (prints each step, returns the boolean verdict), and
// index.js exposes the structured result to programs. Same checks, same
// order, one implementation.
function verifyProofSteps(proof, jwk = ORG_PUBLIC_JWK, artifactSha256, hooks = {}) {
  const steps = [];
  const notes = [];
  const onStep = typeof hooks.onStep === 'function' ? hooks.onStep : null;
  const onNote = typeof hooks.onNote === 'function' ? hooks.onNote : null;
  const s = (ok, name, detail) => {
    const okBool = ok === true;
    steps.push(detail ? { ok: okBool, name, detail } : { ok: okBool, name });
    if (onStep) onStep(okBool, name, detail);
    return okBool;
  };
  const note = (text) => { notes.push(text); if (onNote) onNote(text); };
  // The receipt this proof is about is whatever the LOGGED LEAF says,
  // never the file's own label. The result carries it so a caller (and
  // the CLI's last line) names the leaf's id, not a label anyone could
  // have typed.
  const isObject = !!proof && typeof proof === 'object' && !Array.isArray(proof);
  const leafObj = isObject ? safe(() => JSON.parse(proof.leaf_payload)) : null;
  const loggedId = leafObj && typeof leafObj === 'object' && !leafObj.__error && typeof leafObj.receipt_id === 'string'
    ? leafObj.receipt_id
    : null;
  const done = (pending) => ({
    verified: !pending && steps.length > 0 && steps.every((x) => x.ok),
    pending: !!pending,
    receipt_id: loggedId,
    steps,
    notes,
  });

  if (!isObject) {
    s(false, 'proof is a JSON object');
    return done(false);
  }
  if (proof.status === 'pending') {
    s(false, 'proof is pending: no signed tree head covers this leaf yet');
    return done(true);
  }

  // The proof's own labels must agree with what was actually logged and
  // signed. Without this, a genuine proof for one receipt could be
  // relabeled with the id of another and the final line would name the
  // wrong receipt as verified (vector v23). The leaf and the head are
  // the facts; the top-level fields are a summary of them. A label that
  // is PRESENT runs the check whatever its type, and a value that is not
  // a string (or, for tree_size, not an integer) fails it (vector v24):
  // only an absent field skips a check, and a skipped check is not a pass.
  if (proof.receipt_id !== undefined) {
    if (typeof proof.receipt_id !== 'string') {
      s(false, 'receipt_id is the id inside the logged leaf',
        `receipt_id must be a string, got ${JSON.stringify(proof.receipt_id)}`);
    } else {
      const claimed = proof.receipt_id.trim().toLowerCase();
      const same = loggedId !== null && claimed === loggedId;
      s(same, 'receipt_id is the id inside the logged leaf',
        same ? loggedId : `proof says ${JSON.stringify(proof.receipt_id)}, leaf says ${JSON.stringify(loggedId)}`);
    }
  }
  if (proof.tree_size !== undefined) {
    const headSize = proof.sth && proof.sth.tree_size;
    const same = Number.isInteger(proof.tree_size) && proof.tree_size === headSize;
    s(same, 'tree_size equals the signed head',
      same ? String(headSize) : `proof says ${JSON.stringify(proof.tree_size)}, head says ${JSON.stringify(headSize)}`);
  }

  if (artifactSha256) {
    const claimed = leafObj && typeof leafObj === 'object' ? leafObj.sha256 : undefined;
    const provided = String(artifactSha256).toLowerCase();
    s(claimed === provided, 'artifact sha256 matches the logged leaf', claimed === provided ? provided : `leaf has ${claimed}`);
  }
  s(safe(() => leafHash(proof.leaf_payload) === String(proof.leaf_hash || '').toLowerCase()) === true,
    'leaf_hash = SHA256(0x00 || leaf_payload)');
  s(verifyInclusion({
    leafHashHex: String(proof.leaf_hash || ''), leafIndex: proof.leaf_index,
    treeSize: proof.sth && proof.sth.tree_size, auditPath: proof.audit_path,
    rootHex: String((proof.sth && proof.sth.root_hash) || ''),
  }) === true, `inclusion proof verifies (leaf ${proof.leaf_index} of ${proof.sth && proof.sth.tree_size})`);
  s(verifySth(proof.sth, jwk) === true, `STH Ed25519 signature verifies (${(proof.sth && proof.sth.key_id) || 'no key_id'})`);

  // Family signature over the SAME leaf bytes the log anchored. Present
  // on the proof only for receipts the family signed; absence is not a
  // failure (chapter 06, step 4: "verifies by integrity alone").
  const fam = proof.issuer_signature;
  if (fam && fam.sig && fam.public_jwk) {
    s(verifyContextSig(SIG_CONTEXT, fam.sig, proof.leaf_payload, fam.public_jwk) === true,
      `family signature verifies over the logged leaf (${fam.key_id || 'no key_id'})`);
    if (typeof fam.key_id === 'string' && fam.key_id.startsWith('did:key:')) {
      const derived = safe(() => didKeyFromPublicJwk(fam.public_jwk));
      s(derived === fam.key_id, 'family key_id is the did:key of the public key it ships with',
        derived === fam.key_id ? undefined : `derived ${JSON.stringify(derived)}`);
    }
    // ADVISORY, never fatal. issued_at is the moment the FAMILY sealed the
    // record, which legitimately precedes the key: a guest issues offline
    // and republishes on sign-up with the original issued_at, and every
    // family's first signed receipt is stamped before the signing key is
    // minted. The ordering is worth showing a receiver and worth nothing
    // as a verdict, so it prints as a note and stays out of the failure
    // set. Do not turn it into a tolerance window; the gap is weeks.
    if (fam.key_established_at) {
      const established = new Date(fam.key_established_at).getTime();
      const issued = safe(() => new Date(JSON.parse(proof.leaf_payload).issued_at).getTime());
      const ordered = Number.isFinite(established) && Number.isFinite(issued) && established <= issued;
      note(ordered
        ? `· note: the family key was established before this receipt was issued (${fam.key_established_at})`
        : `· note: this receipt was issued before its family key was established (key ${fam.key_established_at}). Normal for a record sealed before the family had an account, or for a family's first signed receipt. Not a verification failure.`);
    }
  }
  // The signer's own signature on an attestation (chapter 03). Present
  // only when the adult who signed holds a key and used it. It is over
  // the attestation's id and hash, both of which are in the leaf, so it
  // binds the key to exactly what was attested. Absence is not a
  // failure: a signature by a typed name verifies by integrity alone.
  const own = proof.signer_signature;
  if (own && own.sig && own.public_jwk) {
    const leaf = safe(() => JSON.parse(proof.leaf_payload));
    const attId = leaf && typeof leaf.receipt_id === 'string' ? leaf.receipt_id : '';
    const attSha = leaf && typeof leaf.sha256 === 'string' ? leaf.sha256 : '';
    s(/^att_[a-f0-9]{12}$/.test(attId) && attId === 'att_' + attSha.slice(0, 12),
      'the signed attestation id is the one its hash implies');
    s(verifyContextSig(ATT_SIG_CONTEXT, own.sig, JSON.stringify({ att_id: attId, sha256: attSha }), own.public_jwk) === true,
      `the signer's own key signed this attestation (${own.key_id || 'no key_id'})`);
    if (typeof own.key_id === 'string' && own.key_id.startsWith('did:key:')) {
      const derived = safe(() => didKeyFromPublicJwk(own.public_jwk));
      s(derived === own.key_id, 'the signer key_id is the did:key of the public key it ships with',
        derived === own.key_id ? undefined : `derived ${JSON.stringify(derived)}`);
    }
    // ADVISORY, never fatal: a key shows it is the same signer each time,
    // and when the key began. It does not show who the signer is.
    if (own.key_established_at) {
      note(`· note: the signer's key was established ${own.key_established_at}; a key shows the same signer each time, not who the signer is`);
    }
  }
  // A statement the signer wrote and signed with their own key, from
  // which this attestation was made (chapter 03, section 3.12). The
  // proof carries the statement's hash, the signature over that hash and
  // the public key. It carries no words: the statement names the
  // student, and a proof holds no personal data. The student holds the
  // statement and hands it to whom they choose. Given it, the words are
  // checked against the hash this proof names.
  const stmt = proof.signer_statement;
  const stmtFile = hooks.statement;
  if (stmt && stmt.sig && stmt.public_jwk) {
    const sha = typeof stmt.sha256 === 'string' ? stmt.sha256 : '';
    s(/^[a-f0-9]{64}$/.test(sha), 'the written statement is named by its hash');
    s(verifyContextSig(CREDIT_SIG_CONTEXT, stmt.sig, JSON.stringify({ sha256: sha }), stmt.public_jwk) === true,
      `the signer's own key signed a statement they wrote (${stmt.key_id || 'no key_id'})`);
    if (typeof stmt.key_id === 'string' && stmt.key_id.startsWith('did:key:')) {
      const derived = safe(() => didKeyFromPublicJwk(stmt.public_jwk));
      s(derived === stmt.key_id, 'the statement key_id is the did:key of the public key it ships with',
        derived === stmt.key_id ? undefined : `derived ${JSON.stringify(derived)}`);
    }
    if (stmtFile !== undefined) {
      const got = statementSteps(stmtFile, s, note);
      s(got !== null && got === sha, 'the statement file holds the words this receipt was signed from',
        got === sha ? undefined : `the proof names ${sha.slice(0, 16)}..., the file is ${String(got).slice(0, 16)}...`);
      const fileKey = stmtFile && stmtFile.statement && stmtFile.statement.key_id;
      s(fileKey === stmt.key_id, 'the statement and the proof name the same key');
    } else {
      note('· note: the words are in the statement file the student holds. To check them, run: node verify-offline.js proof.json --statement statement.json');
    }
    if (stmt.key_established_at) {
      note(`· note: the signer's key was established ${stmt.key_established_at}; a key shows the same signer each time, not who the signer is`);
    }
  } else if (stmtFile !== undefined) {
    // A statement was handed over and this proof names none. Its own
    // signature may be good, and it is still not shown to belong here.
    statementSteps(stmtFile, s, note);
    s(false, 'this proof names a written statement', 'it carries no signer_statement, so nothing ties the statement file to this receipt');
  }
  return done(false);
}

// The CLI's view: print every step through the reporter, return the verdict.
function verifyProof(proof, jwk, artifactSha256, statement) {
  return verifyProofSteps(proof, jwk, artifactSha256, {
    onStep: step,
    onNote: (text) => console.log(text),
    ...(statement !== undefined ? { statement } : {}),
  }).verified;
}

// A signed statement file on its own: every step and note, and a verdict.
function verifyStatementSteps(file, hooks = {}) {
  const steps = [];
  const notes = [];
  const s = (ok, name, detail) => {
    const okBool = ok === true;
    steps.push(detail ? { ok: okBool, name, detail } : { ok: okBool, name });
    if (typeof hooks.onStep === 'function') hooks.onStep(okBool, name, detail);
    return okBool;
  };
  const note = (text) => { notes.push(text); if (typeof hooks.onNote === 'function') hooks.onNote(text); };
  const sha256 = statementSteps(file, s, note);
  return { verified: steps.length > 0 && steps.every((x) => x.ok), sha256, steps, notes };
}

// ─── Conformance vector dispatch (chapter 10) ──────────────────────
function runVector(v) {
  const input = v.input || {};
  const expect = v.expect || {};
  const wantPass = (expect.verdict || 'pass') === 'pass';
  let computedPass = false;
  let valuesMatch = true;
  const cmp = (got, want, label) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    step(ok, `${label} matches expected`, ok ? undefined : `got ${JSON.stringify(got)}`);
    if (!ok) valuesMatch = false;
  };

  switch (v.check) {
    case 'canonicalize': {
      const got = safe(() => canonicalize(input.value));
      computedPass = typeof got === 'string';
      if (computedPass) cmp(got, expect.canonical, 'canonical string');
      break;
    }
    case 'leaf_payload': {
      const got = safe(() => buildLeafPayload(input.leaf));
      computedPass = typeof got === 'string';
      step(computedPass, 'leaf payload builds', computedPass ? undefined : got.__error);
      if (computedPass && expect.canonical !== undefined) cmp(got, expect.canonical, 'leaf payload');
      break;
    }
    case 'receipt_id': {
      const fn = { tr: () => deriveTr(input.payload), cr: () => deriveCr(input.course), att: () => deriveAtt(input.attestation),
        ws: () => deriveWs(input.worksample), wn: () => deriveWn(input.note), wl: () => deriveWl(input.wall) }[input.kind];
      const got = fn ? safe(fn) : { __error: `unknown kind ${input.kind}` };
      computedPass = !!got && !got.__error;
      step(computedPass, `${input.kind}_ derivation runs`, computedPass ? got.id : got.__error);
      if (computedPass) {
        if (expect.id !== undefined) cmp(got.id, expect.id, 'receipt id');
        if (expect.sha256 !== undefined) cmp(got.sha256, expect.sha256, 'sha256');
        if (expect.snapshot_sha256 !== undefined) cmp(got.snapshot_sha256, expect.snapshot_sha256, 'snapshot_sha256');
      }
      break;
    }
    case 'kb_binding': {
      const did = safe(() => didKeyFromPublicJwk(input.public_jwk));
      const didOk = did === input.key_id;
      step(didOk, 'key_id equals did:key derived from public_jwk.x', didOk ? did : `derived ${JSON.stringify(did)}`);
      const canon = safe(() => buildKbPayload(input));
      computedPass = didOk && typeof canon === 'string';
      if (typeof canon === 'string') {
        if (expect.canonical !== undefined) cmp(canon, expect.canonical, 'kb_ canonical payload');
        const { id, sha256 } = idFromCanonical('kb', canon);
        if (expect.id !== undefined) cmp(id, expect.id, 'kb_ id');
        if (expect.sha256 !== undefined) cmp(sha256, expect.sha256, 'kb_ sha256');
      }
      break;
    }
    case 'family_sig': {
      computedPass = verifyContextSig(SIG_CONTEXT, input.sig, input.leaf_payload, input.public_jwk);
      step(computedPass, `family signature verifies under '${SIG_CONTEXT}'`);
      break;
    }
    case 'countersig': {
      computedPass = verifyContextSig(COUNTERSIG_CONTEXT, input.org_countersig, input.leaf_payload, input.public_jwk);
      step(computedPass, `organization countersignature verifies under '${COUNTERSIG_CONTEXT}'`);
      break;
    }
    case 'merkle_root': {
      const leaves = (input.leaf_payloads || []).map(leafHash);
      computedPass = true;
      for (const n of Object.keys(expect.roots || {})) {
        const got = merkleRoot(leaves.slice(0, Number(n)));
        const ok = got === expect.roots[n];
        step(ok, `Merkle root over ${n} leaves`, ok ? got.slice(0, 16) + '...' : `got ${got}`);
        if (!ok) computedPass = false;
      }
      if (expect.empty_root !== undefined) {
        const ok = merkleRoot([]) === expect.empty_root;
        step(ok, 'empty-tree root equals SHA256 of the empty string');
        if (!ok) computedPass = false;
      }
      break;
    }
    case 'inclusion': {
      computedPass = verifyInclusion({
        leafHashHex: input.leaf_hash, leafIndex: input.leaf_index, treeSize: input.tree_size,
        auditPath: input.audit_path, rootHex: input.root_hash,
      });
      step(computedPass, `inclusion proof (leaf ${input.leaf_index} of ${input.tree_size})`);
      break;
    }
    case 'sth': {
      computedPass = verifySth(input.sth, input.public_jwk);
      step(computedPass, `STH signature verifies under '${STH_CONTEXT}'`);
      break;
    }
    case 'proof': {
      computedPass = verifyProof(input.proof, input.public_jwk || ORG_PUBLIC_JWK, input.sha256, input.statement);
      break;
    }
    case 'signed_statement': {
      const r = verifyStatementSteps(input.file, { onStep: step, onNote: (text) => console.log(text) });
      computedPass = r.verified;
      if (computedPass && expect.sha256 !== undefined) cmp(r.sha256, expect.sha256, 'statement sha256');
      break;
    }
    case 'vc_proof': {
      const r = verifyCredentialProof(input.credential, input.public_jwk);
      computedPass = r.verified === true;
      step(computedPass, 'eddsa-jcs-2022 DataIntegrityProof verifies', r.error);
      break;
    }
    default:
      step(false, `unknown check kind "${v.check}"`);
      return false;
  }

  const verdict = computedPass && valuesMatch ? 'pass' : 'fail';
  const match = wantPass ? verdict === 'pass' : verdict === 'fail';
  console.log(`\nverdict: ${verdict} (expected ${wantPass ? 'pass' : 'fail'}) ${match ? 'OK' : 'MISMATCH'}`);
  return match;
}

// ─── CLI ───────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { positional: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--proof') args.proof = argv[++i];
    else if (argv[i] === '--jwk') args.jwk = argv[++i];
    else if (argv[i] === '--sha256') args.sha256 = argv[++i];
    else if (argv[i] === '--statement') args.statement = argv[++i];
    else if (argv[i].startsWith('--')) { console.error(`unknown argument: ${argv[i]}`); args.bad = true; }
    else args.positional.push(argv[i]);
  }
  return args;
}

function readJson(p, what) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error(`✗ could not read ${what}: ${e.message}`); process.exit(2); }
}

// --jwk accepts either a bare Ed25519 JWK or a whole DID document, so a
// receiver can pin the key straight from `curl .../.well-known/did.json`.
// A DID document may carry several verification methods; prefer the one
// the tree head actually names, and only then fall back to the first.
function readPublicJwk(p, preferredKeyId) {
  const doc = readJson(p, 'JWK file');
  if (doc && typeof doc.x === 'string') return doc;
  const vm = Array.isArray(doc && doc.verificationMethod) ? doc.verificationMethod : [];
  const usable = vm.filter((m) => m && m.publicKeyJwk && typeof m.publicKeyJwk.x === 'string');
  if (usable.length === 0) {
    console.error('✗ no Ed25519 public key found in that file (expected a JWK or a DID document)');
    process.exit(2);
  }
  const wantFragment = String(preferredKeyId || '').split('#')[1] || '';
  const named = wantFragment
    ? usable.find((m) => String(m.id || '').split('#')[1] === wantFragment)
    : null;
  if (wantFragment && !named) {
    console.error(`✗ that DID document has no verification method "#${wantFragment}", which is the key this tree head names`);
    process.exit(2);
  }
  return (named || usable[0]).publicKeyJwk;
}

function looksLikeProof(doc) {
  return !!doc && typeof doc === 'object' && !doc.check &&
    (typeof doc.leaf_payload === 'string' || !!doc.sth || doc.status === 'pending');
}

// A signed statement carries the statement and its signature, and no
// leaf bytes or tree head.
function looksLikeStatement(doc) {
  return !!doc && typeof doc === 'object' && !doc.check && !looksLikeProof(doc) &&
    !!doc.statement && typeof doc.statement === 'object' && typeof doc.sig === 'string';
}

function runStatement(file) {
  const result = verifyStatementSteps(file, { onStep: step, onNote: (text) => console.log(text) });
  console.log(result.verified
    ? '\nVERIFIED: the key named in this statement signed these exact words. This file alone does not show the words are on anyone\'s record; the proof for the receipt does (pass both: <proof.json> --statement <statement.json>).'
    : '\nFAILED: this statement does not verify. Do not rely on its words on the basis of this file.');
  return result.verified;
}

function runProof(proof, args) {
  const jwk = args.jwk ? readPublicJwk(args.jwk, proof && proof.sth && proof.sth.key_id) : ORG_PUBLIC_JWK;
  const result = verifyProofSteps(proof, jwk, args.sha256, {
    onStep: step,
    onNote: (text) => console.log(text),
    ...(args.statement ? { statement: readJson(args.statement, 'statement file') } : {}),
  });
  // The last line names the receipt the LOGGED LEAF is about, never the
  // file's own label (which the label check above may just have refused).
  console.log(result.verified
    ? `\nVERIFIED: ${result.receipt_id || 'receipt'} is in the signed receipt log (tree_size ${proof.sth && proof.sth.tree_size}); check the head against the anchor repository yourself.`
    : '\nFAILED: this proof does not verify. Do not trust the receipt on the basis of this file.');
  return result.verified;
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  if (args.bad || (!args.proof && args.positional.length !== 1)) {
    console.error('usage: node verify-offline.js <proof.json>   (a proof downloaded from a /verify page)');
    console.error('       node verify-offline.js <vector.json>  (a conformance vector)');
    console.error('       node verify-offline.js <statement.json>  (a statement a signer wrote and signed)');
    console.error('       optional: --jwk <pub.jwk or did.json> --sha256 <hash of the artifact you hold>');
    console.error('       optional: --statement <statement.json> with a proof, to check the words it was signed from');
    console.error('       --proof <proof.json> still works and forces proof mode.');
    process.exit(2);
  }
  if (args.proof) process.exit(runProof(readJson(args.proof, 'proof file'), args) ? 0 : 1);

  // One positional file: a conformance vector carries `check`, a proof
  // carries leaf bytes or a tree head. Decide from the file, not a flag.
  const doc = readJson(args.positional[0], 'input file');
  if (looksLikeProof(doc)) process.exit(runProof(doc, args) ? 0 : 1);
  if (looksLikeStatement(doc)) process.exit(runStatement(doc) ? 0 : 1);
  if (!doc || typeof doc.check !== 'string') {
    console.error('✗ that file is not a conformance vector (no "check"), a receipt proof (no leaf bytes), or a signed statement (no statement and signature).');
    process.exit(2);
  }
  console.log(`[${doc.id || args.positional[0]}] chapter ${doc.chapter || '?'}: ${doc.title || ''}`);
  process.exit(runVector(doc) ? 0 : 1);
}

module.exports = {
  canonicalize, assertJcsSafe, buildLeafPayload, RECEIPT_PREFIXES,
  deriveTr, deriveCr, deriveAtt, deriveWs, deriveWn, deriveWl,
  base58btcEncode, base58btcDecode, verifyBytes, verifyContextSig, didKeyFromPublicJwk, buildKbPayload,
  leafHash, nodeHash, chainHash, GENESIS_CHAIN, merkleRoot, verifyInclusion, verifySth,
  verifyCredentialProof, verifyProofSteps, verifyProof, verifyStatementSteps, runVector,
  SIG_CONTEXT, ATT_SIG_CONTEXT, CREDIT_SIG_CONTEXT, COUNTERSIG_CONTEXT, STH_CONTEXT, ORG_PUBLIC_JWK,
};
