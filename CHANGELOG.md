# Changelog

All notable changes to FolderLocker are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [1.0.3] — Unreleased

Bug-fix release: smooths out the GUI so it never looks frozen or scary.

### Fixed
- **A console window flashed on every action; unlocking sometimes showed an
  `icacls.exe — Application Error (0xc0000142)` dialog.** The filesystem helpers
  (`icacls`, `attrib`, `takeown`) now run hidden (`CREATE_NO_WINDOW` + hidden
  `STARTUPINFO`, no inherited handles) and transient `0xc0000142`
  (`STATUS_DLL_INIT_FAILED`) failures are retried, so no console flickers and the
  spurious error dialog is gone.
- **The Manager froze ("Not Responding") with no feedback after clicking
  Unlock / Lock / Reset / Delete.** The heavy steps — Argon2id key derivation
  and the recursive ACL/attribute changes — used to run on the UI thread. They
  now run on a background thread behind an animated "working…" window, so the
  app stays responsive and always shows what it is doing.

## [1.0.2]

Bug-fix release: makes the packaged (Nuitka) build actually work end-to-end.

### Fixed
- **Right-click menu actions did nothing after installing the packaged exe.**
  Nuitka does not set `sys.frozen`, so install never copied the exe and the menu
  pointed at a temporary extraction folder that is deleted on exit. Packaging is
  now detected for both Nuitka and PyInstaller, and the menu/daemon use the
  stable installed copy.
- **Password and other dialogs flashed and vanished in the packaged exe.**
  One-shot GUI commands now run a real event loop instead of relying on
  `wait_window()`, which was unreliable as the first window in a windowed exe.
- **Double-clicking the exe to install showed a dialog that flashed away.**
  First-run now opens a proper install window.

## [1.0.1]

Bug-fix release focused on the GUI Manager and uninstall flow.

### Fixed
- Manager dialogs (Unlock / Fully Unlock / Reset / Delete) no longer flash and
  vanish — all windows now share one Tk root and dialogs stay above the Manager.
- Uninstalling from Settings → Apps no longer crashes with "lost sys.stdin"
  (the uninstall command now runs in GUI mode).
- Manager action buttons are always visible regardless of vault-list length.

### Changed
- The released `locker.exe` is now built with **Nuitka** (compiled to C) instead
  of PyInstaller, which reduces antivirus false-positives.
- Console output is forced to UTF-8 so it never crashes on a legacy code page.

## [1.0.0]

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

[1.0.3]: https://github.com/XMrNooBX/locker/releases/tag/v1.0.3
[1.0.2]: https://github.com/XMrNooBX/locker/releases/tag/v1.0.2
[1.0.1]: https://github.com/XMrNooBX/locker/releases/tag/v1.0.1
[1.0.0]: https://github.com/XMrNooBX/locker/releases/tag/v1.0.0
