# Putting the Argeni testnet online

This puts the website at **argeni.io**, the explorer at **explorer.argeni.io**, and the network's
API at **rpc.argeni.io**, all on one DigitalOcean server with automatic HTTPS. It takes about
45 minutes, most of it waiting.

What you'll have afterwards: a public **testnet** with 4 post-quantum validators on one server.
Test ARGENI has no value. One server means one operator, so it is **not decentralized yet**;
adding validators on other servers is the next step.

---

## Part 1 · On your Mac (once)

**1. Create the treasury vault key. It never goes on the server.**

Follow [FOUNDER-VAULT.md](FOUNDER-VAULT.md): the same steps make the treasury vault, an encrypted,
hash-based (SLH-DSA-256s) key kept offline with 3 backups. In short:

```bash
mkdir -p ~/argeni-vault && chmod 700 ~/argeni-vault
cd ~/Documents/argeni-chain
node src/cli.js keygen --out ~/argeni-vault/treasury.json --type slh-dsa-256s --encrypt
node src/cli.js check-key --key ~/argeni-vault/treasury.json
```

Copy the `address ag…` line it prints. You'll need it in step 8. Never upload the key file or the
passphrase anywhere.

**2. Create an SSH key** (lets you log in to the server securely, without a password):

```bash
ssh-keygen -t ed25519 -C "argeni-server"
cat ~/.ssh/id_ed25519.pub
```

Press Enter to accept the default file, choose a passphrase you'll remember, then copy the line
that `cat` prints (it starts with `ssh-ed25519`).

## Part 2 · DigitalOcean

**3. Create the server** (DigitalOcean calls it a Droplet): **Create → Droplets**

| Setting | Choose |
|---|---|
| Region | **Singapore** |
| Image | **Ubuntu 24.04 (LTS)** |
| Size | Basic → Regular → **2 vCPU / 4 GB** |
| Authentication | **SSH Key** → New SSH Key → paste the line from step 2 |
| Hostname | `argeni-testnet-1` |
| Backups | Optional, recommended |

Click **Create Droplet** and copy its **IPv4 address** (for example `203.0.113.25`).

## Part 3 · GoDaddy DNS

**4.** In GoDaddy: **My Products → argeni.io → DNS**. Add these records, all pointing at the
server's IP:

| Type | Name | Value | TTL |
|---|---|---|---|
| A | `@` | *your server IP* | 1/2 hour |
| A | `www` | *your server IP* | 1/2 hour |
| A | `explorer` | *your server IP* | 1/2 hour |
| A | `rpc` | *your server IP* | 1/2 hour |
| A | `faucet` | *your server IP* | 1/2 hour |

- If there is already an **A record for `@`** (often "Parked"), edit it to your IP instead of adding a second one.
- If argeni.io has **Forwarding** turned on, turn it off.
- If there is a **CNAME for `www`**, delete it before adding the A record.
- Don't touch **MX** records if you use email on argeni.io.

Wait 10–30 minutes, then check on [dnschecker.org](https://dnschecker.org) that `explorer.argeni.io`
shows your IP.

## Part 4 · Install

**5. Build the package** on your Mac:

```bash
cd ~/Documents/argeni-chain
bash deploy/make-bundle.sh
```

**6. Upload it** (replace the IP):

```bash
scp argeni-bundle.tar.gz root@203.0.113.25:/root/
```

**7. Log in to the server:**

```bash
ssh root@203.0.113.25
```

**8. Install everything** (replace the address with your treasury address from step 1, and the
key with your Anthropic API key for the website's AI assistant, from
[console.anthropic.com](https://console.anthropic.com/) → API Keys):

```bash
tar xzf argeni-bundle.tar.gz
TREASURY=ag…your-treasury-address ANTHROPIC_API_KEY=sk-ant-… bash argeni-bundle/chain/deploy/setup-server.sh
```

Leave out `ANTHROPIC_API_KEY=…` to install without the AI assistant; you can add it later by
running the same command again with the key. The key is stored only on the server, in
`/etc/argeni/assistant.env`. Each visitor question is a paid Claude API call (a few cents at
most; the site's content is cached), and each visitor is limited to 20 questions per 10 minutes.
Set a monthly spend limit in the Anthropic Console.

This takes 3–5 minutes. It installs Node.js and Caddy, creates the testnet with post-quantum
keys, starts 4 validators, turns on HTTPS and the firewall, and prints the network's status at
the end.

**9. Open** https://argeni.io and https://explorer.argeni.io. If HTTPS isn't ready yet, wait a
minute: the certificates are requested the first time.

**10. Back up the server's keys** (run this on your Mac):

```bash
scp -r root@203.0.113.25:/opt/argeni/testnet/keys ~/Documents/argeni-testnet-keys-backup
```

Keep the backup private. These are the 4 validator keys and the faucet key.

---

## Later

**Update the code or website:** repeat steps 5–7, then on the server:

```bash
tar xzf argeni-bundle.tar.gz
bash argeni-bundle/chain/deploy/setup-server.sh
```

The chain, its data and its keys are kept; only the code and website are replaced.

**See what a node is doing:**

```bash
systemctl status argeni-node@1        # running?
journalctl -u argeni-node@1 -f        # live log (Ctrl+C to stop)
systemctl restart argeni-node@1       # restart one node
journalctl -u argeni-assistant -f     # the AI assistant's log (one line per question)
```

## Before you announce it

- File the **ARGENI trademark** at IPOPHL (the name becomes public the day this goes live).
- Get the **logo similarity check** done.
- Fill in the **"to confirm"** items on the website (contact, repository link, figures).
- Keep saying clearly that **test ARGENI has no value**, and don't promise it will become real ARGENI.
