# Changelog

All notable changes to FolderLocker are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [1.0.0] — Unreleased

First public release.

### Added
- Right-click **Locker** submenu on folders: **Lock**, **Lock & Hide**,
  **Unlock**, **Fully Unlock**.
- Self-installer: `--install` / `--uninstall` register a per-user context menu
  (no admin), copy the exe to `%LOCALAPPDATA%`, and add a Start Menu shortcut.
- Registers in **Settings → Apps → Installed apps** with a working Uninstall
  button.
- **AES-256-GCM** streaming encryption with **Argon2id** key wrapping and
  envelope encryption (random master key wrapped by password + recovery key).
- One-time **recovery key** and password reset (`recover`) that never touches
  file data.
- **Manager** window (Start Menu / `manage`) to view, unlock, fully unlock,
  reset the password of, or permanently delete vaults — including hidden ones.
- Modern dark-themed GUI dialogs (password entry with strength meter, recovery
  key, progress, messages).
- Automatic re-lock on screen lock, shutdown, restart, and logoff via a hidden
  background helper.
- Visible **Lock** vs **Lock & Hide** distinction (encrypt-in-place vs
  rename + hide).
- **Cloud-sync warning** when locking a folder inside OneDrive / Dropbox /
  Google Drive.
- **Locked-vault warning** on uninstall so encrypted folders aren't stranded.
- Adaptive I/O throttling to keep the PC responsive during large operations.
- `locker.ico` application icon.
- Headless test suite (`test_context_menu.py`).
- `SECURITY.md` threat model and an honest README security section.

### Security
- No telemetry; the app makes no network connections.
- Documented threat model: protects data at rest; does **not** protect against
  an admin/malware on a live account while a folder is unlocked.

[1.0.0]: https://github.com/XMrNooBX/locker/releases
