// Encrypted, authenticated links between nodes, post-quantum end to end.
//
// Handshake (one HTTP round trip, POST /p2p/handshake):
//   initiator -> { v, chainId, genesisHash, from: <its ML-DSA identity key>, kem: <fresh ML-KEM-768
//                  public key>, nonce, ts }, signed with the identity key
//   responder -> { v, sid, from: <its identity key>, ct: <ML-KEM-768 ciphertext>, init: <hash of the
//                  initiator's message> }, signed with its identity key
// Both sides then hold the same 32-byte ML-KEM shared secret (FIPS 203), and (version 2) an X25519
// shared secret from fresh keys on both sides: the session keys come from BOTH, so an attacker must
// break ML-KEM (a lattice problem) and X25519 (an elliptic curve) to read the traffic. A quantum
// computer breaks only the second; a classical breakthrough against lattices only the first. Two AES-256-GCM keys, one
// per direction, are derived from it with HKDF-SHA256 over the whole transcript. The ML-KEM key pair
// is used once and thrown away, so recording traffic today and breaking one key later reveals no
// other session (forward secrecy), and no quantum computer can recover the session from the
// recorded handshake. The identity signatures (ML-DSA, FIPS 204) stop anyone in the middle from
// posing as either node.
//
// Messages (POST /p2p): { sid, seq, ct } where ct = AES-256-GCM(JSON request). The nonce is the
// direction and the sequence number, never reused under a key; the receiver rejects repeated or
// stale sequence numbers (replays). Responses come back encrypted under the other direction's key.
import crypto from 'node:crypto';
import { canonical, sha256, sign, verify, isPublicKey, keyTypeOf, PQ_KEY_TYPES } from './crypto.js';

export const P2P_VERSION = 2; // 2 = hybrid ML-KEM-768 + X25519
const HANDSHAKE_MAX_SKEW_MS = 60_000;
export const SESSION_MAX_AGE_MS = 10 * 60_000; // initiators start a fresh session (fresh keys) every 10 minutes
const SESSION_MAX_MESSAGES = 1_000_000;
const REPLAY_WINDOW = 4096;

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => Buffer.from(String(s), 'base64');

function deriveKeys(sharedKey, init, resp) {
  const salt = Buffer.from(sha256(`cyvber-p2p:v2|${canonical(init)}|${canonical(resp)}`), 'hex');
  const okm = Buffer.from(crypto.hkdfSync('sha256', sharedKey, salt, Buffer.from('cyvber-p2p hybrid session keys'), 64));
  return { i2r: crypto.createSecretKey(okm.subarray(0, 32)), r2i: crypto.createSecretKey(okm.subarray(32, 64)) }; // key objects, built once per session
}

const x25519Public = (der) => {
  const key = crypto.createPublicKey({ key: unb64(der), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'x25519') throw new Error('handshake key must be X25519');
  return key;
};
const exportPublic = (key) => b64(key.export({ type: 'spki', format: 'der' }));
// The two secrets combined: ML-KEM first, then X25519; HKDF needs both to produce the keys.
const hybridSecret = (kemSecret, ecdhSecret) => Buffer.concat([Buffer.from(kemSecret), Buffer.from(ecdhSecret)]);

const signed = (body, privateKey) => ({ ...body, sig: sign(canonical(body), privateKey) });
const unsigned = ({ sig, ...body }) => body;

function checkIdentity(key) {
  return isPublicKey(key) && PQ_KEY_TYPES.includes(keyTypeOf(key));
}

// One end of a session: encrypts what it sends, decrypts and replay-checks what it receives.
export class Session {
  constructor({ sid, sendKey, recvKey, sendDir, peerKey, initiator }) {
    this.sid = sid;
    this.sendKey = sendKey;
    this.recvKey = recvKey;
    this.sendDir = sendDir; // 'i' (initiator -> responder) or 'r'
    this.recvDir = sendDir === 'i' ? 'r' : 'i';
    this.peerKey = peerKey;
    this.initiator = initiator;
    this.createdAt = Date.now();
    this.lastUsed = this.createdAt;
    this.sent = 0;
    this.maxSeen = -1;
    this.seen = new Set();
  }

  get expired() {
    return Date.now() - this.createdAt > SESSION_MAX_AGE_MS || this.sent >= SESSION_MAX_MESSAGES;
  }

  static #iv(dir, seq) {
    const iv = Buffer.alloc(12);
    iv.write(dir === 'i' ? 'ini>' : 'res>', 0, 'latin1');
    iv.writeBigUInt64BE(BigInt(seq), 4);
    return iv;
  }

  #aad(dir, seq) {
    return Buffer.from(`${this.sid}|${dir}|${seq}`);
  }

  #seal(key, dir, seq, value) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, Session.#iv(dir, seq));
    cipher.setAAD(this.#aad(dir, seq));
    const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    return b64(ct);
  }

  #open(key, dir, seq, ct) {
    const data = unb64(ct);
    if (data.length < 16) throw new Error('message too short');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Session.#iv(dir, seq));
    decipher.setAAD(this.#aad(dir, seq));
    decipher.setAuthTag(data.subarray(data.length - 16));
    try {
      return JSON.parse(Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString('utf8'));
    } catch {
      throw new Error('message failed authentication (tampered, or wrong session)');
    }
  }

  // Requests go out under our direction; the reply to request `seq` comes back under the other.
  encryptRequest(value) {
    const seq = this.sent++;
    this.lastUsed = Date.now();
    return { sid: this.sid, seq, ct: this.#seal(this.sendKey, this.sendDir, seq, value) };
  }

  decryptReply(seq, ct) {
    return this.#open(this.recvKey, this.recvDir, seq, ct);
  }

  decryptRequest({ seq, ct }) {
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('bad sequence number');
    if (seq <= this.maxSeen - REPLAY_WINDOW || this.seen.has(seq)) throw new Error('replayed message');
    const value = this.#open(this.recvKey, this.recvDir, seq, ct); // only authentic messages update the window
    this.seen.add(seq);
    if (seq > this.maxSeen) {
      this.maxSeen = seq;
      for (const s of this.seen) if (s <= seq - REPLAY_WINDOW) this.seen.delete(s);
    }
    this.lastUsed = Date.now();
    return value;
  }

  encryptReply(seq, value) {
    return { ct: this.#seal(this.sendKey, this.sendDir, seq, value) };
  }
}

// Initiator side, step 1: a fresh ML-KEM-768 key pair and the signed hello.
export function createHello({ chainId, genesisHash, identityKey, identityPublicKey }) {
  const kem = crypto.generateKeyPairSync('ml-kem-768');
  const ecdh = crypto.generateKeyPairSync('x25519');
  const hello = signed({
    v: P2P_VERSION, chainId, genesisHash, from: identityPublicKey,
    kem: exportPublic(kem.publicKey), x: exportPublic(ecdh.publicKey),
    nonce: crypto.randomBytes(32).toString('hex'), ts: Date.now(),
  }, identityKey);
  return { hello, kemPrivateKey: { kem: kem.privateKey, x25519: ecdh.privateKey } };
}

// Responder side: checks the hello, encapsulates a shared secret to it, signs the answer.
// `seenNonces` (a Set) rejects a replayed hello. `admit(identityKey)`, when given, is the stealth gate:
// an identity it refuses gets a StealthRefusal before any signature check or key exchange, so the
// node spends nothing on strangers and can answer as if the route did not exist.
export class StealthRefusal extends Error {}
export function acceptHello(hello, { chainId, genesisHash, identityKey, identityPublicKey, seenNonces, admit = null }) {
  if (admit && !(hello && typeof hello === 'object' && typeof hello.from === 'string' && admit(hello.from))) throw new StealthRefusal('not admitted');
  if (!hello || typeof hello !== 'object' || hello.v !== P2P_VERSION) throw new Error('unsupported handshake version');
  if (hello.chainId !== chainId || hello.genesisHash !== genesisHash) throw new Error('different chain');
  if (!checkIdentity(hello.from)) throw new Error('identity must be a post-quantum public key');
  if (!Number.isSafeInteger(hello.ts) || Math.abs(Date.now() - hello.ts) > HANDSHAKE_MAX_SKEW_MS) throw new Error('handshake too old or clock skew too large');
  if (typeof hello.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(hello.nonce) || seenNonces?.has(hello.nonce)) throw new Error('replayed handshake');
  if (!verify(canonical(unsigned(hello)), hello.sig, hello.from)) throw new Error('handshake signature invalid');
  let kemKey;
  try {
    kemKey = crypto.createPublicKey({ key: unb64(hello.kem), format: 'der', type: 'spki' });
  } catch {
    throw new Error('bad ML-KEM key');
  }
  if (kemKey.asymmetricKeyType !== 'ml-kem-768') throw new Error('handshake key must be ML-KEM-768');
  let theirX;
  try {
    theirX = x25519Public(hello.x);
  } catch {
    throw new Error('bad X25519 key');
  }
  seenNonces?.add(hello.nonce);
  const { sharedKey, ciphertext } = crypto.encapsulate(kemKey);
  const ours = crypto.generateKeyPairSync('x25519');
  const ecdh = crypto.diffieHellman({ privateKey: ours.privateKey, publicKey: theirX });
  const reply = signed({ v: P2P_VERSION, sid: crypto.randomBytes(16).toString('hex'), from: identityPublicKey, ct: b64(ciphertext), x: exportPublic(ours.publicKey), init: sha256(canonical(hello)) }, identityKey);
  const keys = deriveKeys(hybridSecret(sharedKey, ecdh), hello, reply);
  const session = new Session({ sid: reply.sid, sendKey: keys.r2i, recvKey: keys.i2r, sendDir: 'r', peerKey: hello.from, initiator: false });
  return { reply, session };
}

// Initiator side, step 2: checks the reply and opens the session.
export function completeHello(hello, kemPrivateKey, reply, { expectedPeerKey = null } = {}) {
  if (!reply || reply.v !== P2P_VERSION || typeof reply.sid !== 'string' || !/^[0-9a-f]{32}$/.test(reply.sid)) throw new Error('bad handshake reply');
  if (!checkIdentity(reply.from)) throw new Error('peer identity must be a post-quantum public key');
  if (expectedPeerKey && reply.from !== expectedPeerKey) throw new Error('peer identity changed (possible impersonation)');
  if (reply.init !== sha256(canonical(hello))) throw new Error('handshake reply is for a different hello');
  if (!verify(canonical(unsigned(reply)), reply.sig, reply.from)) throw new Error('handshake reply signature invalid');
  const sharedKey = crypto.decapsulate(kemPrivateKey.kem, unb64(reply.ct));
  let theirX;
  try {
    theirX = x25519Public(reply.x);
  } catch {
    throw new Error('bad X25519 key in reply');
  }
  const ecdh = crypto.diffieHellman({ privateKey: kemPrivateKey.x25519, publicKey: theirX });
  const keys = deriveKeys(hybridSecret(sharedKey, ecdh), hello, reply);
  return new Session({ sid: reply.sid, sendKey: keys.i2r, recvKey: keys.r2i, sendDir: 'i', peerKey: reply.from, initiator: true });
}
