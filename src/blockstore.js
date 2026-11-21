// Compact block files. A block as it travels is ~100 KB, mostly post-quantum material repeated in
// every vote: each precommit carries the validator's full public key (2,592 bytes for ML-DSA-87, as
// hex) and a signature (4,627 bytes, as hex), twice per block (lastCommit + commit). On disk:
//   - validator keys in votes and the header's proposer become numbers into a per-node key list
//     (keys.json, append-only), so each key is stored once instead of in every block;
//   - signatures are stored as base64 instead of hex;
//   - the result is Brotli-compressed into <height>.cb.
// Encoding is checked by decoding it again: a block that would not come back byte-identical is
// stored as plain <height>.json instead, so this file format can never change what a block is.
// Plain .json files (the older format) are still read.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { canonical } from './crypto.js';

const HEX = /^[0-9a-f]+$/;
const isHexSig = (s) => typeof s === 'string' && s.length % 2 === 0 && s.length > 0 && HEX.test(s);
const pad = (h) => String(h).padStart(10, '0');

export class BlockStore {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.keysFile = path.join(path.dirname(dir), 'keys.json');
    this.keys = fs.existsSync(this.keysFile) ? JSON.parse(fs.readFileSync(this.keysFile, 'utf8')) : [];
    this.index = new Map(this.keys.map((k, i) => [k, i]));
  }

  #keyId(key) {
    let i = this.index.get(key);
    if (i === undefined) {
      i = this.keys.length;
      this.keys.push(key);
      this.index.set(key, i);
      const tmp = `${this.keysFile}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.keys));
      fs.renameSync(tmp, this.keysFile); // the key list is saved before any block that uses it
    }
    return i;
  }

  #packVotes(commit) {
    if (!commit || !Array.isArray(commit.precommits)) return commit;
    return { ...commit, precommits: commit.precommits.map((v) => {
      if (!v || typeof v.validator !== 'string' || !isHexSig(v.signature)) return { raw: v };
      const { validator, signature, ...rest } = v;
      return { ...rest, k: this.#keyId(validator), s: Buffer.from(signature, 'hex').toString('base64') };
    }) };
  }

  #unpackVotes(commit) {
    if (!commit || !Array.isArray(commit.precommits)) return commit;
    return { ...commit, precommits: commit.precommits.map((v) => {
      if (v.raw !== undefined) return v.raw;
      const { k, s, ...rest } = v;
      return { ...rest, validator: this.keys[k], signature: Buffer.from(s, 'base64').toString('hex') };
    }) };
  }

  encode(block) {
    const { header, ...body } = block;
    const packed = {
      v: 1,
      ...body,
      header: { ...header, proposer: this.#keyId(header.proposer) },
      lastCommit: this.#packVotes(block.lastCommit),
      commit: this.#packVotes(block.commit),
    };
    return zlib.brotliCompressSync(Buffer.from(JSON.stringify(packed)), { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } });
  }

  decode(buf) {
    const packed = JSON.parse(zlib.brotliDecompressSync(buf).toString('utf8'));
    if (packed.v !== 1) throw new Error(`unknown block file version ${packed.v}`);
    const { v, ...rest } = packed;
    const block = { ...rest, header: { ...packed.header, proposer: this.keys[packed.header.proposer] } };
    if ('lastCommit' in packed) block.lastCommit = this.#unpackVotes(packed.lastCommit);
    if ('commit' in packed) block.commit = this.#unpackVotes(packed.commit);
    return block;
  }

  write(block) {
    const height = block.header.height;
    let file = path.join(this.dir, `${pad(height)}.cb`);
    let data;
    try {
      data = this.encode(block);
      if (canonical(this.decode(data)) !== canonical(block)) throw new Error('round trip differs');
    } catch {
      file = path.join(this.dir, `${pad(height)}.json`);
      data = JSON.stringify(block);
    }
    fs.writeFileSync(file, data);
  }

  read(height) {
    const cb = path.join(this.dir, `${pad(height)}.cb`);
    if (fs.existsSync(cb)) return this.decode(fs.readFileSync(cb));
    const js = path.join(this.dir, `${pad(height)}.json`);
    return fs.existsSync(js) ? JSON.parse(fs.readFileSync(js, 'utf8')) : null;
  }

  // Heights stored, in order (either format).
  heights() {
    const set = new Set();
    for (const f of fs.readdirSync(this.dir)) {
      const m = /^(\d{10})\.(cb|json)$/.exec(f);
      if (m) set.add(Number(m[1]));
    }
    return [...set].sort((a, b) => a - b);
  }

  // Rewrites plain .json files in the compact format (after checking each one round-trips).
  compact({ log = () => {} } = {}) {
    let done = 0, before = 0, after = 0;
    for (const h of this.heights()) {
      const js = path.join(this.dir, `${pad(h)}.json`);
      if (!fs.existsSync(js)) continue;
      const text = fs.readFileSync(js, 'utf8');
      const block = JSON.parse(text);
      this.write(block);
      const cb = path.join(this.dir, `${pad(h)}.cb`);
      if (fs.existsSync(cb)) {
        before += text.length; after += fs.statSync(cb).size;
        fs.unlinkSync(js);
        done++;
      }
    }
    log(`compacted ${done} block files: ${(before / 1e6).toFixed(1)} MB -> ${(after / 1e6).toFixed(1)} MB`);
    return { done, before, after };
  }
}
