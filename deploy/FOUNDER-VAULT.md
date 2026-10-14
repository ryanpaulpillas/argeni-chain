# Founder and treasury vault keys

How to create and keep the keys that will hold large ARGENI allocations: the founders' 8%
(40,000,000 ARGENI) and the treasury. The same steps work for the testnet treasury today.

## The setup

| Choice | Decision | Why |
|---|---|---|
| Key type | **SLH-DSA-256s** (`--type slh-dsa-256s`) | Hash-based post-quantum signatures (NIST FIPS 205) at the highest security level (category 5). They rest only on hash functions, so a future breakthrough against lattice cryptography wouldn't affect them. Signing takes about half a second, which is fine for a vault. |
| Encryption | **Passphrase-encrypted file** (`--encrypt`) | The file alone is useless to a thief. The passphrase is stretched with scrypt and the key sealed with AES-256-GCM. |
| One key per founder | Yes | Each founder controls their own share. |
| Where it lives | **Offline**, never on a server | Only the vault's *address* goes into the chain's genesis and onto servers. |
| Backups | **3 copies**, in 3 places | Losing the key means losing the tokens: nobody, including Argeni, can recover them. |

## Create a vault (once per founder)

1. **Use a folder that isn't synced to iCloud or any cloud.** On a Mac, `~/Documents` and
   `~/Desktop` are often synced; use a folder in your home directory instead:

   ```bash
   mkdir -p ~/argeni-vault && chmod 700 ~/argeni-vault
   ```

2. **Go offline.** Turn off Wi-Fi while creating the key.

3. **Choose a long passphrase**: at least 5 random words (for example from a dice word list) or 20+
   characters. Write it on paper. Don't save it on the computer or in a phone note.

4. **Create the encrypted vault key:**

   ```bash
   cd ~/Documents/argeni-chain
   node src/cli.js keygen --out ~/argeni-vault/founder-ryan.json --type slh-dsa-256s --encrypt
   ```

   It asks for the passphrase twice and prints the vault's **address** (`ag…`, 64 characters).

5. **Test that it opens** (this is how you'll test every backup too):

   ```bash
   node src/cli.js check-key --key ~/argeni-vault/founder-ryan.json
   ```

   It should print `OK: … opens and controls ag… (slh-dsa-256s, encrypted)`.

## Back it up: 3 copies, 3 places

| Copy | Where | Notes |
|---|---|---|
| 1 | Encrypted USB drive at home, in a safe | Copy `founder-ryan.json` onto it |
| 2 | Encrypted USB drive somewhere else (a bank safe deposit box, a trusted family member) | Same file |
| 3 | Paper | Print the file's contents, or keep a third USB drive, in a separate place |

Keep the **passphrase separate from the key files**, for example the paper in a different safe from
the USB drive. Someone who finds one shouldn't find the other.

After making the copies, run `check-key` against each copy to make sure it opens. Then delete the
key from the computer if you don't need it there.

## What goes where

- **Into the chain's genesis:** only the vault's address, with its allocation and lock-up.
- **To servers, GitHub, email, chat, AI assistants:** never the key file and never the passphrase.

## Using the vault later

The command-line wallet asks for the passphrase whenever the vault signs, for example:

```bash
node src/cli.js send --key ~/argeni-vault/founder-ryan.json --to ag… --amount 1000
```

Founder tokens are locked for the first year after mainnet anyway. Before relying on the vault,
do one small test transfer from it on the testnet.

## If something happens

- **Lost one copy:** you still have two. Make a new third copy from a working one.
- **Passphrase may have leaked:** move the funds to a brand-new vault (create one as above and send
  everything to it, or use `migrate`).
- **Key may be compromised and you made a commitment:** if you ran `pq-commit` to a backup vault in
  advance, only that backup can receive the funds, even from an attacker holding the old key.

## Option: a 2-of-3 multisig vault

For the treasury, or a vault shared by several people, use a **multisig**: any 2 of 3 keys must sign
before funds move. One lost or stolen key is then not enough to lose or steal anything.

1. Each member creates their own encrypted key on their own computer (steps above), for example
   `member-ryan.json`, and shares **only the public part**. The `publicKey` and `address` lines of
   the file are public. Sharing the whole file is safe only if it is encrypted, because the
   encrypted file never contains the private key in readable form.
2. One person builds the vault from the members' files:

   ```bash
   node src/cli.js multisig create --threshold 2 --keys member-ryan.json,member-b.json,member-c.json --out treasury-vault.json
   ```

   It prints the vault's address. Put that address in genesis (or send funds to it).
3. To spend, one person prepares the transaction, then two members sign it, each on their own
   computer (the file can travel by USB or email; it holds no secrets), and anyone submits it:

   ```bash
   node src/cli.js multisig propose --vault treasury-vault.json --to ag… --amount 1000 --out spend.json
   node src/cli.js multisig sign --tx spend.json --key ~/argeni-vault/member-ryan.json
   node src/cli.js multisig sign --tx spend.json --key member-b.json     # on member B's computer
   node src/cli.js multisig submit --tx spend.json
   ```

`sign` shows what is being signed (amount, recipient) before signing. Check it every time.

## Lock-ups are enforced by the chain

Founder, team and partner allocations go into genesis as **vesting grants** (for founders:
12-month lock, then 24 monthly unlocks). Until a part unlocks, the chain refuses to move it, from
any key, including after a key migration. The explorer shows each address's locked amount and
when it becomes free.
