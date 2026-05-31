# Security Policy & Threat Model

FolderLocker is a free, open-source hobby project. It uses strong, standard
cryptography, but it has **not** been independently audited. This document
explains — honestly — what it protects against and what it does not, so you can
make an informed decision before trusting it with your data.

If you only read one line: **FolderLocker protects your files at rest. It is not
a defense against malware or an attacker who controls your account while a
folder is unlocked.**

---

## How it works (in brief)

FolderLocker uses **envelope encryption**, the same pattern as BitLocker,
VeraCrypt, and FileVault:

- A random 256-bit **master key** is generated once per folder and is what
  actually encrypts your files. It never changes and is never derived from your
  password.
- Your **password** is run through **Argon2id** (memory-hard key derivation) to
  produce a wrapping key, which encrypts (wraps) the master key.
- A one-time **recovery key** independently wraps the same master key, so you
  can reset a forgotten password.
- Files are encrypted with **AES-256-GCM** in streaming 4 MB chunks, each chunk
  authenticated to detect tampering or truncation.

### Cryptographic parameters

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-GCM (authenticated) |
| Nonce | 96-bit, per-chunk derived from a random base nonce |
| Password KDF | Argon2id — 32 MB memory, 2 iterations, parallelism 2, 256-bit output |
| Recovery key | 128-bit random, PBKDF2-SHA256 (1,000 iterations) |
| Master key | 256-bit, from the OS CSPRNG (`os.urandom`) |

> Note: the Argon2id parameters (32 MB / 2 iterations) favor responsiveness on
> typical hardware. They are reasonable but lighter than maximum-hardness
> settings; a very well-resourced attacker targeting a weak password is the
> relevant risk — use a strong password.

---

## What it protects against ✅

- **Theft of a powered-off device.** A stolen laptop or a hard drive pulled and
  read on another machine yields only AES-256 ciphertext.
- **Booting another OS** (e.g. a Linux USB) to bypass Windows — the files are
  still encrypted.
- **Other non-administrator users** on the same PC — they're denied access and
  the files are encrypted anyway.
- **Casual snooping** — "show hidden files", browsing, copying the folder
  elsewhere all yield encrypted data.
- **Offline password guessing** — Argon2id makes brute-forcing a decent
  password slow and expensive even with GPUs.

---

## What it does NOT protect against ❌

Please take these seriously.

1. **An administrator on the machine.** The access block uses an `icacls /deny`
   rule, which an Administrator can reset. Your files remain *encrypted*, but the
   access barrier itself is not absolute against admin rights.

2. **Anything running as you while a folder is UNLOCKED.** While a folder is
   unlocked, the master key is stored **in plaintext** in
   `%APPDATA%\FolderLocker\vaults.json` so the background helper can re-encrypt
   the folder when you lock your screen. During that window, malware or a person
   at your unlocked session can read the key and the files. The key is cleared
   when the folder re-locks.

3. **Malware / a compromised account.** A keylogger captures your password; code
   running as you can read unlocked data. FolderLocker is not anti-malware.

4. **A targeted "evil maid" attacker** with repeated physical access who can
   modify the tool or the OS between your uses.

5. **Forgetting your credentials.** If you lose **both** your password and your
   recovery key, the data is permanently unrecoverable. This is by design — there
   is no backdoor, master key, or reset.

6. **RAM / swap / hibernation capture.** While files are being processed, plaintext
   exists in memory and could be written to the page file or a hibernation file.

7. **Filename and size metadata.** FolderLocker encrypts file *contents*. File
   names, folder structure, and file sizes are not hidden (beyond the optional
   "hide" attribute, which is cosmetic, not cryptographic).

---

## Comparison with full-disk / container encryption

| | FolderLocker | BitLocker / VeraCrypt |
|---|---|---|
| Protects data at rest | ✅ | ✅ |
| Hides file names & sizes | ❌ | ✅ |
| Key never written to disk in plaintext | ❌ (while unlocked) | ✅ |
| Protects against admin on live system | ❌ | ✅ (pre-boot) |
| Audited | ❌ | ✅ |
| Per-folder, no setup | ✅ | ❌ |

**Use FolderLocker** for convenient per-folder protection against device theft
and casual access. **Use BitLocker or VeraCrypt** for whole-disk protection or
genuinely high-stakes secrets.

---

## Recommendations for users

- Use a **strong, unique password** — Argon2id only helps so much against a weak one.
- **Save your recovery key** in a password manager. It's your only spare key.
- **Lock your screen** when you step away; don't leave vaults unlocked.
- Consider running FolderLocker **on top of** BitLocker (full-disk) rather than instead of it.
- Don't lock folders inside **OneDrive / Dropbox / Google Drive** (the tool warns you).

---

## Reporting a vulnerability

This is a small hobby project maintained on a best-effort basis.

- Please open an issue at https://github.com/XMrNooBX/locker/issues for general
  bugs.
- For a **security-sensitive** report you'd prefer not to disclose publicly,
  open a GitHub issue asking for a private contact channel, or use GitHub's
  "Report a vulnerability" feature if enabled on the repository.

There is no bug-bounty program and no guaranteed response time, but security
reports are taken seriously and credited.

---

## No warranty

FolderLocker is licensed under GPL-3.0 and is provided **"as is", without
warranty of any kind**. The authors are not liable for data loss or damages.
You are solely responsible for your password, your recovery key, and your data.
