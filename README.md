# FolderLocker 🔒

**Lock any folder on Windows with a password — right from the right-click menu.**

FolderLocker encrypts a folder's contents with AES-256 so that, without your password, the files are unreadable. Lock a folder, optionally hide it, and it stays encrypted — including if your powered-off laptop is stolen, the drive is pulled, or someone boots another operating system. It re-locks automatically when you lock your screen or shut down.

Download it, run it once, and it adds itself to your right-click menu.

> **Heads-up:** This is a free, open-source hobby project — strong encryption, but **not** an audited security product. Please read [Why it's reasonably safe](#why-its-reasonably-safe--and-where-it-isnt) and [SECURITY.md](SECURITY.md) before trusting it with anything important. **No warranty — use at your own risk.**

---

## ⚠️ Read this first — there is no backdoor

FolderLocker is built so that **only you** can open your folders. That strength comes with one rule you must respect:

> **If you forget your password AND lose your recovery key, your files are gone forever.**
>
> Nobody can get them back — not you, not us, not a hacker, not a technician. There is no "reset" email, no master key, no override. That is exactly what makes it secure.

When you first lock a folder you're shown a one-time **recovery key**. Save it somewhere safe (a password manager, a note, a photo). It's your only spare key. **Use this tool at your own risk** — if you're not comfortable being fully responsible for your password and recovery key, don't lock anything important until you are.

---

## Why it's reasonably safe — and where it isn't

FolderLocker uses strong, standard cryptography, but it is **a hobby project, not an audited security product.** Be honest with yourself about what it does and doesn't protect against before trusting it with anything critical.

**What's genuinely strong:**
- **AES-256-GCM encryption** — a widely trusted, standard algorithm. The encryption itself has no known practical break.
- **Argon2id key derivation** — deliberately slow and memory-heavy, so guessing your password is expensive even with a fast GPU.
- **Your password is the only secret.** The source code being public doesn't weaken anything — that's how real cryptography is supposed to work.
- **Protects data at rest.** If your powered-off laptop is stolen, the drive is pulled, or someone boots a Linux USB, locked files are unreadable ciphertext.

**What it does NOT protect against — read this:**
- **A determined Administrator on your PC.** The "blocked" permission can be reset by an admin. Your files stay encrypted, but the *access block* is not a hard wall.
- **Malware or anyone active on your account while a folder is unlocked.** While unlocked, the key sits in `vaults.json` so the tool can auto-relock — anyone reading your profile in that window can grab it.
- **A targeted attacker with repeated access to your machine** (so-called "evil maid" situations).
- **You losing your password and recovery key.** Nothing and no one can recover the data then.

It has **not** been independently security-audited. Treat it as "much better than a hidden folder or a ZIP password, not a replacement for BitLocker or VeraCrypt for life-or-death secrets."

👉 **See [SECURITY.md](SECURITY.md) for the full threat model.**

| If someone tries to… | Protected? |
|----------------------|------------|
| Open the folder as another **non-admin** Windows user | ✅ Yes |
| Turn on "show hidden files" in Explorer | ✅ Yes — files are still encrypted |
| Steal your powered-off laptop / pull the drive | ✅ Yes — encrypted at rest |
| Boot from a Linux USB stick | ✅ Yes — encrypted at rest |
| Guess your password with software | ✅ Slow and expensive by design |
| **Admin** account resets folder permissions | ⚠️ Access block bypassed, but files stay encrypted |
| Read your account **while the folder is unlocked** | ❌ Key is briefly accessible — not protected |
| Malware running as you | ❌ Not protected |

---

## Install

### The easy way (most people)

1. Go to the [Releases](https://github.com/XMrNooBX/locker/releases) page and download `locker.exe`.
2. (Recommended) Verify it — see [Verifying your download](#verifying-your-download) below.
3. Double-click it. It asks **"Install FolderLocker now?"** — click **Yes**.
4. Done. Right-click any folder and use the **Locker** menu.

No administrator rights needed. To update later, download the newer `locker.exe` and run it once again.

To remove it: **Settings → Apps → Installed apps → FolderLocker → Uninstall**, or run `locker.exe --uninstall`.

> **About the security warning:** FolderLocker is not code-signed (signing certificates are expensive for a free project), so Windows SmartScreen may say *"Windows protected your PC"* and some antivirus tools may flag it. This is a common **false positive** for unsigned binaries — the code is fully open and the exe is built by GitHub Actions straight from the tagged source. If you'd like a second opinion, upload it to [VirusTotal](https://www.virustotal.com/); if you'd rather not run an unsigned exe at all, use the **run from source** option below.

### Verifying your download

Each release attaches a **SHA-256 checksum** (`locker.exe.sha256`). To check the file matches:

```powershell
Get-FileHash .\locker.exe -Algorithm SHA256
```

Compare the output to the checksum on the release page. If they differ, don't run it.

### Running from source (for developers / the cautious)

Needs Windows 10/11 and Python 3.10+:

```bat
pip install cryptography argon2-cffi psutil
python locker.py --install      :: add the right-click menu
python locker.py --uninstall    :: remove it
```

---

## How to use it

Right-click any folder → **Locker** →

| Choose | What happens |
|--------|--------------|
| **Lock** | Encrypts the folder and blocks access. The folder stays where it is, with its normal name. |
| **Lock & Hide** | Same as Lock, but also hides the folder so it vanishes from view. |
| **Unlock** | Asks for your password and opens the folder back up. It will auto-relock later. |
| **Fully Unlock** | Unlocks it permanently and removes it from FolderLocker — back to a totally normal folder. |

When you lock a folder for the first time, you'll set a password and be shown your **recovery key** — save it.

> **Lock vs Lock & Hide:** both encrypt your files with AES-256 — the contents are equally protected either way. "Lock & Hide" *also* conceals the folder from Explorer; it's not stronger encryption, just less visible. Hidden folders are reached through the Manager (below).
>
> All four items always show in the menu. If one doesn't apply (e.g. unlocking a folder that isn't locked), FolderLocker just tells you instead of doing nothing.

### Finding hidden folders — the Manager

A folder you chose **Lock & Hide** for disappears from Explorer, so you can't right-click it. To get it back, open the **Manager**:

- Press the **Windows key**, type **FolderLocker**, and open **FolderLocker Manager**, or
- Run `locker manage`.

The Manager lists every folder you've locked. Pick one and you can:

- **Unlock** it (temporarily open it),
- **Fully Unlock** it (make it normal again),
- **🔑 Reset password** (if you forgot the password but still have the recovery key),
- **🗑 Delete** it (permanently erase a folder you can no longer open — see below).

---

## Forgot your password?

**If you still have your recovery key**, you're fine:

1. Open the **Manager**.
2. Select the folder → **🔑 Reset password**.
3. Paste your recovery key and set a new password.

That's instant, no matter how big the folder is. You'll get a fresh recovery key afterward — save the new one.

**If you've lost both the password and the recovery key**, the files cannot be opened by anyone, ever. Your only option is to delete the folder to free up the space:

- In the Manager, select it → **🗑 Delete** → confirm twice. This permanently erases the encrypted folder.

---

## Password rules

A password needs at least **6 characters** with an uppercase letter, a lowercase letter, a number, and a symbol (like `!@#$%`).

---

## Where things are stored

| Location | What it is |
|----------|------------|
| `%APPDATA%\FolderLocker\vaults.json` | The list of folders you've locked |
| `%LOCALAPPDATA%\FolderLocker\locker.exe` | The installed copy the menu uses |
| Start Menu → FolderLocker Manager | Shortcut to the Manager |

---

## For maintainers — building the .exe

The release `locker.exe` is built with **Nuitka** (compiles Python to C, which
triggers fewer antivirus false-positives than a PyInstaller bundle). The easiest
way is the bundled script:

```bat
build.bat
```

Or manually:

```bat
pip install nuitka cryptography argon2-cffi psutil
python -m nuitka --onefile --windows-console-mode=disable --enable-plugin=tk-inter ^
    --windows-icon-from-ico=locker.ico --include-data-files=locker.ico=locker.ico ^
    --assume-yes-for-downloads --output-filename=locker.exe --output-dir=dist locker.py
```

Nuitka needs a C compiler; on Windows it uses MSVC if present, otherwise it
offers to download MinGW automatically. Builds take a few minutes. Run the test
suite with:

```bat
python test_context_menu.py
```

> Note: Nuitka does **not** remove the SmartScreen warning — only code signing
> does. It just reduces antivirus false-positives.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Windows SmartScreen blocked it | Click **More info → Run anyway** (it's unsigned — see [Install](#install)), or run from source |
| Antivirus flagged it | Possible false positive for an unsigned binary — check the release's VirusTotal link, or run from source |
| No right-click menu | Run `locker.exe --install` once |
| A black console window flickered before | Reinstall — newer versions launch silently |
| Can't find a hidden folder | Open the Manager (Start menu → FolderLocker) |
| Forgot password | Manager → Reset password (needs your recovery key) |
| Lost password **and** recovery key | The files can't be recovered — only deleted |
| Auto-relock not happening | Check `%APPDATA%\FolderLocker\daemon.log` |

---

## Privacy & license

- **No telemetry.** FolderLocker makes **no network connections** of any kind. It never phones home, collects analytics, or sends your data anywhere. Everything stays on your machine.
- **License:** GPL-3.0. It comes with **no warranty** — see the [LICENSE](LICENSE) and the disclaimer below.
- **Cloud folders:** Avoid locking folders inside OneDrive, Dropbox, or Google Drive. The tool warns you if it detects one — locking syncs encrypted data to the cloud and can cause conflicts.
- **Export note:** This is published open-source encryption software. You are responsible for complying with any encryption import/export/use laws in your country.

> **Disclaimer:** FolderLocker is provided "as is", without warranty of any kind. The authors are not liable for any data loss or damages. You are solely responsible for your password, your recovery key, and the safety of your files.
