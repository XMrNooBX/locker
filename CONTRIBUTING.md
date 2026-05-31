# Contributing to FolderLocker

Thanks for your interest in improving FolderLocker! This is a small,
security-sensitive project, so a few guidelines keep things safe and tidy.

## Ground rules

- **Be honest about security.** Don't add claims the code can't back up. If a
  change affects the threat model, update `SECURITY.md` in the same PR.
- **Never weaken the crypto** (algorithms, key sizes, KDF parameters) without a
  clear, discussed reason.
- **No telemetry / network calls.** The tool must keep working fully offline and
  send nothing anywhere.
- **Windows-only** for now. Keep `tkinter`, `winreg`, and `ctypes` usage behind
  the existing lazy-import / platform guards.

## Project layout

| File | Purpose |
|------|---------|
| `locker.py` | The entire tool — crypto, CLI, GUI, installer, daemon |
| `test_context_menu.py` | Headless test suite |
| `make_icon.py` | Regenerates `locker.ico` |
| `README.md` / `SECURITY.md` | User docs and threat model |

## Development setup

```bat
pip install cryptography argon2-cffi psutil
python locker.py --help
```

To exercise the GUI without installing, run a command with `--gui`, e.g.:

```bat
python locker.py manage --gui
```

## Before you open a PR

1. **Run the tests** and make sure they pass:
   ```bat
   python test_context_menu.py
   ```
   The suite mocks the OS-level ACL/attribute calls so it runs without admin in
   a sandbox. If you change locking behavior, add or update a test.

2. **Manually verify** anything the tests can't cover (the suite mocks
   `icacls`/`attrib`). At minimum, on a real folder:
   - Lock → confirm access is denied and files are encrypted.
   - Unlock → confirm the original files come back.
   - Lock & Hide → confirm the folder is renamed/hidden and the Manager can
     unlock it.

3. **Keep `--install` / `--uninstall` symmetric** — anything install creates,
   uninstall must remove (registry keys, shortcut, installed copy, Settings
   entry).

4. **Update `CHANGELOG.md`** under an "Unreleased" section.

5. Keep changes focused; match the existing code style (standard library +
   `cryptography`/`argon2`/`psutil`, no new runtime dependencies without
   discussion).

## Reporting security issues

Please see [SECURITY.md](SECURITY.md) — don't post exploit details in a public
issue before maintainers have a chance to respond.

## Coding notes

- The GUI is intentionally dependency-free (`tkinter` only). The `_button`
  helper uses `tk.Button` because the `clam` ttk theme renders custom button
  colors unreliably on Windows.
- All paths that re-invoke the tool (daemon, registry commands, shortcut) go
  through `_self_invocation()` / the install logic so they work both frozen
  (exe) and from source.
