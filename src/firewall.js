// The node's firewall: five layers in front of the API and the encrypted peer channel.
//
//   1. Connection   banned addresses are dropped before a byte is read; open connections per
//                   address are capped; slow senders time out (see the server timeouts in node.js).
//   2. Rate         token buckets per address and per kind of request. The post-quantum handshake
//                   (an ML-KEM decapsulation and ML-DSA signature per call) has its own tight budget.
//   3. Size         a body limit per route: transactions are small, only the peer channel carries
//                   whole blocks.
//   4. Behaviour    every request that fails a check costs points (malformed JSON, invalid
//                   transactions, refused handshakes, tampered peer messages, probing unknown routes).
//                   Too many points in a short time bans the address; each repeat ban lasts twice as
//                   long (1 minute up to 24 hours).
//   5. Peer identity  a peer that sends invalid consensus messages or blocks over the encrypted
//                   channel is scored by its ML-DSA identity, not its address, so it can't escape by
//                   changing IP; at the threshold its identity is refused at the handshake.
//
// Never banned: loopback (local tools, a reverse proxy, a devnet on one machine) unless exemptLocal
// is off, the addresses in `allow`, and trusted peer identities: the peers in the node's own config
// file and the active validators (a misbehaving one is reported, not cut off, so a bug can't split the
// validator set; consensus slashing deals with real faults). IPv6 clients are grouped by /64, the block one subscriber usually gets.

export const FIREWALL_DEFAULTS = {
  enabled: true,
  exemptLocal: true,
  allow: [],
  maxConnectionsPerIp: 32,
  // Requests per minute per address (token buckets, so short bursts up to the same size pass).
  rates: { read: 600, tx: 120, handshake: 30, p2p: 6000, faucet: 10, other: 120 },
  // Body limits per kind of request, in bytes.
  bodyLimits: { tx: 1_000_000, handshake: 64_000, p2p: 16_000_000, faucet: 4_000, other: 64_000 },
  banThreshold: 100, // points
  pointsDecayPerMinute: 20,
  banBaseMs: 60_000,
  banMaxMs: 24 * 3_600_000,
  maxTracked: 100_000, // addresses kept in memory; the quietest are forgotten first
};

// Points per kind of misbehaviour.
export const PENALTIES = {
  'bad-json': 10,
  'too-large': 25,
  'not-found': 2,
  'bad-method': 5,
  'invalid-tx': 2,
  'bad-signature': 10,
  'bad-handshake': 10,
  'tampered': 50, // a peer message that fails AES-GCM authentication
  'unknown-session': 1, // normal after a restart, so cheap
  'invalid-consensus': 10,
  'invalid-block': 25,
  'rate-limited': 1, // ignoring a 429 and carrying on
};

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

export function addressKey(ip) {
  const raw = String(ip ?? '').replace(/^::ffff:/, '');
  if (!raw.includes(':')) return raw;
  const halves = raw.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const groups = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

export class Firewall {
  constructor(options = {}, { now = () => Date.now(), log = () => {}, trustedPeer = () => false } = {}) {
    const o = { ...FIREWALL_DEFAULTS, ...options };
    this.options = { ...o, rates: { ...FIREWALL_DEFAULTS.rates, ...options.rates }, bodyLimits: { ...FIREWALL_DEFAULTS.bodyLimits, ...options.bodyLimits } };
    this.now = now;
    this.log = log;
    this.allow = new Set(this.options.allow.map(addressKey));
    this.trustedPeer = trustedPeer;
    this.hosts = new Map(); // address key -> { buckets, points, pointsAt, strikes, bannedUntil, lastSeen, reasons }
    this.peers = new Map(); // peer identity -> { points, pointsAt, strikes, bannedUntil, reasons }
    this.connections = new Map(); // address key -> open connections
    this.stats = { droppedConnections: 0, refusedRequests: 0, bans: 0, peerBans: 0, penalties: 0 };
  }

  exempt(ip) {
    return !this.options.enabled || (this.options.exemptLocal && LOOPBACK.has(ip)) || this.allow.has(addressKey(ip));
  }

  #host(key) {
    let h = this.hosts.get(key);
    if (!h) {
      if (this.hosts.size >= this.options.maxTracked) this.#forgetQuietest();
      h = { buckets: {}, points: 0, pointsAt: this.now(), strikes: 0, bannedUntil: 0, lastSeen: this.now(), reasons: {} };
      this.hosts.set(key, h);
    }
    h.lastSeen = this.now();
    return h;
  }

  #forgetQuietest() {
    const now = this.now();
    const quiet = [...this.hosts].filter(([, h]) => h.bannedUntil <= now).sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    for (const [key] of quiet.slice(0, Math.max(1, Math.floor(this.options.maxTracked / 10)))) this.hosts.delete(key);
  }

  // Milliseconds left on a ban, or 0.
  bannedFor(ip) {
    if (this.exempt(ip)) return 0;
    const h = this.hosts.get(addressKey(ip));
    return h && h.bannedUntil > this.now() ? h.bannedUntil - this.now() : 0;
  }

  // Layer 1. Call when a TCP connection opens; false = drop it. Pair with connectionClosed().
  connectionOpened(ip) {
    if (this.exempt(ip)) return true;
    const key = addressKey(ip);
    const open = this.connections.get(key) ?? 0;
    if (this.bannedFor(ip) || open >= this.options.maxConnectionsPerIp) {
      this.stats.droppedConnections++;
      return false;
    }
    this.connections.set(key, open + 1);
    return true;
  }

  connectionClosed(ip) {
    if (this.exempt(ip)) return;
    const key = addressKey(ip);
    const open = (this.connections.get(key) ?? 1) - 1;
    if (open > 0) this.connections.set(key, open);
    else this.connections.delete(key);
  }

  // Layer 2. Returns null if the request may go ahead, else { status, retryAfterMs, error }.
  checkRequest(ip, kind) {
    if (!ip || this.exempt(ip)) return null;
    const banned = this.bannedFor(ip);
    if (banned) {
      this.stats.refusedRequests++;
      return { status: 403, retryAfterMs: banned, error: 'this address is temporarily blocked by the node firewall' };
    }
    const perMinute = this.options.rates[kind] ?? this.options.rates.other;
    if (!perMinute) return null;
    const h = this.#host(addressKey(ip));
    const now = this.now();
    const b = h.buckets[kind] ?? (h.buckets[kind] = { tokens: perMinute, at: now });
    b.tokens = Math.min(perMinute, b.tokens + ((now - b.at) * perMinute) / 60_000);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return null;
    }
    this.stats.refusedRequests++;
    this.penalize(ip, 'rate-limited');
    return { status: 429, retryAfterMs: Math.ceil(((1 - b.tokens) * 60_000) / perMinute), error: `too many ${kind} requests from your address` };
  }

  bodyLimit(kind) {
    return this.options.bodyLimits[kind] ?? this.options.bodyLimits.other;
  }

  #score(entry, reason) {
    const now = this.now();
    const decay = ((now - entry.pointsAt) * this.options.pointsDecayPerMinute) / 60_000;
    entry.points = Math.max(0, entry.points - decay) + (PENALTIES[reason] ?? 5);
    entry.pointsAt = now;
    entry.reasons[reason] = (entry.reasons[reason] ?? 0) + 1;
    this.stats.penalties++;
    if (entry.points < this.options.banThreshold || entry.bannedUntil > now) return 0;
    const ms = Math.min(this.options.banMaxMs, this.options.banBaseMs * 2 ** entry.strikes);
    entry.strikes++;
    entry.bannedUntil = now + ms;
    entry.points = 0;
    return ms;
  }

  // Layer 4. Records misbehaviour by an address; returns the ban length in ms if this caused a ban.
  penalize(ip, reason) {
    if (!ip || this.exempt(ip)) return 0; // no address: a request relayed inside the encrypted peer channel
    const key = addressKey(ip);
    const ms = this.#score(this.#host(key), reason);
    if (ms) {
      this.stats.bans++;
      this.log(`firewall: blocked ${key} for ${Math.round(ms / 1000)} s (${reason})`);
    }
    return ms;
  }

  // Layer 5. Misbehaviour by an authenticated peer identity (its ML-DSA public key).
  penalizePeer(peerKey, reason) {
    if (!peerKey) return 0;
    let p = this.peers.get(peerKey);
    if (!p) this.peers.set(peerKey, (p = { points: 0, pointsAt: this.now(), strikes: 0, bannedUntil: 0, reasons: {} }));
    if (this.trustedPeer(peerKey)) {
      p.reasons[reason] = (p.reasons[reason] ?? 0) + 1; // reported, never cut off
      return 0;
    }
    const ms = this.#score(p, reason);
    if (ms) {
      this.stats.peerBans++;
      this.log(`firewall: refusing peer identity ${peerKey.slice(0, 24)}… for ${Math.round(ms / 1000)} s (${reason})`);
    }
    return ms;
  }

  peerBannedFor(peerKey) {
    const p = this.peers.get(peerKey);
    return p && p.bannedUntil > this.now() ? p.bannedUntil - this.now() : 0;
  }

  prune() {
    const now = this.now();
    const idle = 30 * 60_000;
    for (const [key, h] of this.hosts) if (h.bannedUntil <= now && now - h.lastSeen > idle) this.hosts.delete(key);
    for (const [key, p] of this.peers) if (p.bannedUntil <= now && now - p.pointsAt > idle) this.peers.delete(key);
  }

  // `detail` adds the blocked addresses and identities (for the node's own operator only).
  status({ detail = false } = {}) {
    const now = this.now();
    const bannedHosts = [...this.hosts].filter(([, h]) => h.bannedUntil > now);
    const bannedPeers = [...this.peers].filter(([, p]) => p.bannedUntil > now);
    const { enabled, exemptLocal, maxConnectionsPerIp, rates, bodyLimits, banThreshold, banBaseMs, banMaxMs } = this.options;
    return {
      enabled,
      layers: ['connection', 'rate', 'size', 'behaviour', 'peer-identity'],
      rules: { exemptLocal, maxConnectionsPerIp, requestsPerMinute: rates, bodyLimitBytes: bodyLimits, banThresholdPoints: banThreshold, banMinutes: [banBaseMs / 60_000, banMaxMs / 60_000], penalties: PENALTIES },
      stats: { ...this.stats, trackedAddresses: this.hosts.size, openConnections: [...this.connections.values()].reduce((a, b) => a + b, 0) },
      blocked: { addresses: bannedHosts.length, peerIdentities: bannedPeers.length },
      ...(detail ? {
        blockedAddresses: bannedHosts.map(([key, h]) => ({ address: key, untilMs: h.bannedUntil - now, strikes: h.strikes, reasons: h.reasons })),
        blockedPeers: bannedPeers.map(([key, p]) => ({ identity: key.slice(0, 40), untilMs: p.bannedUntil - now, strikes: p.strikes, reasons: p.reasons })),
      } : {}),
    };
  }
}
