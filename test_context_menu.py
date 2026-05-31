"""
Headless tests for the explorer-context-menu feature additions to locker.py.

Run:  python test_context_menu.py
These avoid Tk and real Explorer; they exercise the pure logic, the registry
install/uninstall against a throwaway HKCU key, and a full visible-lock +
unlock cycle on a temp folder using the ConsoleUx path.
"""
import os
import sys
import tempfile
import winreg
from pathlib import Path

import locker


PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name)


# ── 1. _self_invocation: frozen vs source ─────────────────────────────────────
def test_self_invocation():
    orig_frozen = getattr(sys, "frozen", False)
    try:
        if hasattr(sys, "frozen"):
            del sys.frozen
        inv = locker._self_invocation()
        check("self_invocation source = [python, script]",
              len(inv) == 2 and inv[0] == sys.executable and inv[1].endswith("locker.py"))

        sys.frozen = True
        inv2 = locker._self_invocation()
        check("self_invocation frozen = [exe]",
              len(inv2) == 1 and inv2[0] == sys.executable)
    finally:
        if orig_frozen:
            sys.frozen = True
        elif hasattr(sys, "frozen"):
            del sys.frozen


# ── 2. menu command builder ───────────────────────────────────────────────────
def test_menu_commands():
    if hasattr(sys, "frozen"):
        del sys.frozen
    cmds = locker._menu_commands()
    check("four menu commands", set(cmds) ==
          {"01lock", "02lockhide", "03unlock", "04fullunlock"})
    check("lock cmd has --gui and quoted %1",
          "--gui" in cmds["01lock"] and '"%1"' in cmds["01lock"]
          and " lock " in cmds["01lock"])
    check("lockhide cmd uses lock-hide subcommand",
          "lock-hide --gui" in cmds["02lockhide"])
    check("unlock-f cmd uses unlock-f subcommand",
          "unlock-f --gui" in cmds["04fullunlock"])
    check("source prefix invokes python + script",
          cmds["01lock"].startswith('"') and "locker.py" in cmds["01lock"]
          and ("python" in cmds["01lock"].lower()))
    # The menu must use pythonw.exe (windowless) in source mode so no console
    # window pops up when a menu item is clicked — unless pythonw is missing.
    import pathlib as _pl
    _pyw = _pl.Path(sys.executable).with_name("pythonw.exe")
    if _pyw.exists():
        check("source menu uses pythonw (no console window)",
              "pythonw" in cmds["01lock"].lower())


# ── 3. hidden marker migration ────────────────────────────────────────────────
def test_hidden_marker():
    check("legacy record (no marker) -> hidden True",
          locker._vault_hidden({}) is True)
    check("hidden False respected", locker._vault_hidden({"hidden": False}) is False)
    check("hidden True respected", locker._vault_hidden({"hidden": True}) is True)


# ── 4. password helpers ───────────────────────────────────────────────────────
def test_password():
    check("weak password reports errors", len(locker.password_errors("abc")) > 0)
    check("strong password passes", locker.password_errors("MyP@ss1!") == [])
    score, label = locker.password_strength("MyP@ss1!")
    check("strong password high score", score >= 4)
    check("empty password score 0", locker.password_strength("")[0] == 0)


# ── 5. registry install / uninstall against a throwaway root ──────────────────
def test_install_uninstall(monkeypatch_root=r"Software\Classes\Directory\shell\__LockerTest"):
    # Redirect the menu root to a test location so we don't touch the real menu.
    orig_root = locker.REG_MENU_ROOT
    orig_shortcut = locker.SHORTCUT_PATH
    orig_install_dir = locker.INSTALL_DIR
    orig_install_exe = locker.INSTALL_EXE
    orig_uninstall = locker.REG_UNINSTALL
    tmp = Path(tempfile.mkdtemp())
    locker.REG_MENU_ROOT = monkeypatch_root
    locker.SHORTCUT_PATH = tmp / "mgr.lnk"
    locker.INSTALL_DIR = tmp / "inst"
    locker.INSTALL_EXE = tmp / "inst" / "locker.exe"
    locker.REG_UNINSTALL = r"Software\__LockerTestUninstall\FolderLocker"
    if hasattr(sys, "frozen"):
        del sys.frozen   # source mode → no exe copy, no shortcut requirement

    def _uninstall_entry_exists():
        try:
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, locker.REG_UNINSTALL).Close()
            return True
        except FileNotFoundError:
            return False

    ux = locker.ConsoleUx()
    try:
        check("not installed initially", locker._menu_installed() is False)

        try:
            locker.do_install(ux)
        except locker.AbortAction:
            pass
        check("installed after do_install", locker._menu_installed() is True)
        check("Settings uninstall entry created", _uninstall_entry_exists() is True)

        # The uninstall entry must carry a usable UninstallString.
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, locker.REG_UNINSTALL) as k:
                us, _ = winreg.QueryValueEx(k, "UninstallString")
                dn, _ = winreg.QueryValueEx(k, "DisplayName")
            check("uninstall entry has --uninstall string", "--uninstall" in us)
            check("uninstall entry display name set", dn == "FolderLocker")
        except Exception:
            check("uninstall entry has --uninstall string", False)
            check("uninstall entry display name set", False)

        # Verify the four command subkeys exist with the expected content.
        ok_cmds = True
        for key in ("01lock", "02lockhide", "03unlock", "04fullunlock"):
            try:
                p = monkeypatch_root + r"\shell" + "\\" + key + r"\command"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, p) as k:
                    val, _ = winreg.QueryValueEx(k, None)
                    if "--gui" not in val:
                        ok_cmds = False
            except FileNotFoundError:
                ok_cmds = False
        check("all four command keys written with --gui", ok_cmds)

        # Idempotent re-install.
        try:
            locker.do_install(ux)
        except locker.AbortAction:
            pass
        check("still installed after re-install", locker._menu_installed() is True)

        # Uninstall.
        try:
            locker.do_uninstall(ux)
        except locker.AbortAction:
            pass
        check("uninstalled after do_uninstall", locker._menu_installed() is False)
        check("Settings uninstall entry removed", _uninstall_entry_exists() is False)

        # Uninstall when nothing present → no crash, stays uninstalled.
        try:
            locker.do_uninstall(ux)
        except locker.AbortAction:
            pass
        check("uninstall-when-absent is a no-op", locker._menu_installed() is False)
    finally:
        # Cleanup test keys if anything is left.
        locker._reg_delete_tree(winreg.HKEY_CURRENT_USER, monkeypatch_root)
        locker._reg_delete_tree(winreg.HKEY_CURRENT_USER, r"Software\__LockerTestUninstall")
        locker.REG_MENU_ROOT = orig_root
        locker.SHORTCUT_PATH = orig_shortcut
        locker.INSTALL_DIR = orig_install_dir
        locker.INSTALL_EXE = orig_install_exe
        locker.REG_UNINSTALL = orig_uninstall


# ── 6. full visible lock + unlock cycle on a temp folder ──────────────────────
def test_visible_lock_cycle():
    # Redirect the vault registry to a temp file so we don't touch the real one.
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"

    # Disable the daemon spawn during the test.
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None

    # Mock the OS-level ACL/attribute calls.  These are the existing, unchanged
    # locking primitives; their real behaviour is environment-sensitive (a deny
    # ACE under %TEMP% can't be reset by a non-elevated sandbox user).  We test
    # the NEW orchestration + the REAL encryption round-trip here; the ACL
    # mechanism itself is verified manually on a real desktop.
    orig_deny = locker.icacls_deny
    orig_restore = locker.icacls_restore
    orig_hide = locker.attrib_hide
    orig_show = locker.attrib_show
    locker.icacls_deny = lambda p: None
    locker.icacls_restore = lambda p: None
    locker.attrib_hide = lambda p: None
    locker.attrib_show = lambda p: None

    secret = tmp / "Secret"
    secret.mkdir(parents=True)
    plaintext = b"hello world, this is a test file" * 1000
    (secret / "a.txt").write_bytes(plaintext)
    (secret / "sub").mkdir()
    (secret / "sub" / "b.bin").write_bytes(os.urandom(50_000))

    ux = locker.ConsoleUx()
    try:
        # Lock (visible): no rename, files encrypted.
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)
        check("visible lock keeps original folder name", secret.exists())
        check("file genuinely encrypted (magic header present)",
              (secret / "a.txt").read_bytes()[:5] == locker.MAGIC_V2)

        state = locker.load_state()
        _, vault = locker.find_vault(state, secret)
        check("vault recorded hidden=False", vault and vault.get("hidden") is False)
        check("locked_path == original_path for visible lock",
              vault and vault["locked_path"] == str(secret))
        check("vault status locked after lock", vault and vault["status"] == "locked")

        # Unlock: restores plaintext (the round-trip proves real encryption).
        locker.cmd_unlock(str(secret), "MyP@ss1!", ux)
        check("file decrypted back to original plaintext",
              (secret / "a.txt").read_bytes() == plaintext)
        check("subfolder file restored", (secret / "sub" / "b.bin").exists())
        state = locker.load_state()
        _, vault = locker.find_vault(state, secret)
        check("vault status unlocked after unlock", vault and vault["status"] == "unlocked")
    finally:
        locker.icacls_deny = orig_deny
        locker.icacls_restore = orig_restore
        locker.attrib_hide = orig_hide
        locker.attrib_show = orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 6b. hidden lock renames to .~vlt_ and back ────────────────────────────────
def test_hidden_lock_cycle():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None

    secret = tmp / "Secret"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"top secret" * 200)

    ux = locker.ConsoleUx()
    try:
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=True)
        hidden = secret.parent / (locker.LOCK_PREFIX + "Secret")
        check("hidden lock renames to .~vlt_ prefix", hidden.exists())
        check("hidden lock removes original name", not secret.exists())
        state = locker.load_state()
        _, vault = locker.find_vault(state, secret)
        check("vault recorded hidden=True", vault and vault.get("hidden") is True)

        locker.cmd_unlock(str(secret), "MyP@ss1!", ux)
        check("unlock restores original folder name", secret.exists())
        check("unlock removes .~vlt_ folder", not hidden.exists())
        check("hidden vault decrypts correctly",
              (secret / "a.txt").read_bytes() == b"top secret" * 200)
    finally:
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 6c. state guards leave the folder untouched ───────────────────────────────
def test_state_guards():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None

    secret = tmp / "Secret"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"data" * 100)
    ux = locker.ConsoleUx()
    try:
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)

        # Lock again on an already-locked vault → abort, no change.
        raised = False
        try:
            locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)
        except locker.AbortAction:
            raised = True
        check("locking an already-locked vault aborts", raised)

        # Unlock an unregistered folder → abort.
        other = tmp / "Other"
        other.mkdir()
        raised = False
        try:
            locker.cmd_unlock(str(other), "MyP@ss1!", ux)
        except locker.AbortAction:
            raised = True
        check("unlocking an unregistered folder aborts", raised)
    finally:
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 7. wrong password leaves vault locked ─────────────────────────────────────
def test_wrong_password():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None

    secret = tmp / "Secret2"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"data" * 500)

    ux = locker.ConsoleUx()
    try:
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)
        raised = False
        try:
            locker.cmd_unlock(str(secret), "WrongP@ss9!", ux)
        except locker.AbortAction:
            raised = True
        check("wrong password aborts", raised)
        check("file still encrypted after wrong password",
              (secret / "a.txt").read_bytes()[:5] == locker.MAGIC_V2)
        state = locker.load_state()
        _, vault = locker.find_vault(state, secret)
        check("vault still locked after wrong password",
              vault and vault["status"] == "locked")
        # Correct password still works afterwards.
        locker.cmd_unlock(str(secret), "MyP@ss1!", ux)
        check("correct password unlocks after a failed attempt",
              (secret / "a.txt").read_bytes() == b"data" * 500)
    finally:
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 8. recover (password reset) round-trip ────────────────────────────────────
def test_recover_cycle():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None

    # Capture the recovery code that cmd_lock emits via show_recovery.
    captured = {}

    class CapUx(locker.ConsoleUx):
        def show_recovery(self, code):
            captured["code"] = code

    secret = tmp / "Secret3"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"recover me" * 100)

    ux = CapUx()
    try:
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)
        code = captured.get("code")
        check("recovery code captured at lock", bool(code))

        # Reset the password using the recovery code.
        locker.cmd_recover(str(secret), code, "NewP@ss2!", ux)

        # Old password must now fail.
        raised = False
        try:
            locker.cmd_unlock(str(secret), "MyP@ss1!", ux)
        except locker.AbortAction:
            raised = True
        check("old password rejected after reset", raised)

        # New password must work.
        locker.cmd_unlock(str(secret), "NewP@ss2!", ux)
        check("new password unlocks after reset",
              (secret / "a.txt").read_bytes() == b"recover me" * 100)
    finally:
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 9. forget + delete a locked vault (lost-everything path) ──────────────────
def test_forget_delete():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    orig_ensure = locker.ensure_daemon
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None

    secret = tmp / "Gone"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"bye" * 100)

    ux = locker.ConsoleUx()
    try:
        locker.cmd_lock(str(secret), "MyP@ss1!", ux, hide=False)
        check("vault exists before forget",
              locker.find_vault(locker.load_state(), secret)[1] is not None)

        # Forget WITH delete (lost password + recovery key scenario).
        locker.cmd_forget(str(secret), ux, delete_files=True)

        check("folder deleted from disk", not secret.exists())
        check("vault removed from registry",
              locker.find_vault(locker.load_state(), secret)[1] is None)
    finally:
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir


# ── 10. cloud-sync folder detection ───────────────────────────────────────────
def test_cloud_sync_detection():
    # A plain temp path should not be flagged.
    plain = Path(tempfile.mkdtemp()) / "Normal"
    plain.mkdir()
    check("plain folder not flagged as synced",
          locker._cloud_sync_warning(plain) is None)

    # Paths containing provider names should be flagged.
    base = Path(tempfile.mkdtemp())
    od = base / "OneDrive" / "Secret"
    od.mkdir(parents=True)
    check("OneDrive path flagged", locker._cloud_sync_warning(od) == "OneDrive")

    db = base / "Dropbox" / "Secret"
    db.mkdir(parents=True)
    check("Dropbox path flagged", locker._cloud_sync_warning(db) == "Dropbox")

    gd = base / "My Google Drive" / "Secret"
    gd.mkdir(parents=True)
    check("Google Drive path flagged",
          locker._cloud_sync_warning(gd) == "Google Drive")


# ── 11. uninstall warns when a vault is still locked ──────────────────────────
def test_uninstall_locked_warning():
    tmp = Path(tempfile.mkdtemp())
    orig_state = locker.STATE_FILE
    orig_appdir = locker.APP_DIR
    orig_root = locker.REG_MENU_ROOT
    orig_uninstall = locker.REG_UNINSTALL
    orig_shortcut = locker.SHORTCUT_PATH
    orig_install_exe = locker.INSTALL_EXE
    orig_ensure = locker.ensure_daemon
    locker.APP_DIR = tmp / "app"
    locker.STATE_FILE = locker.APP_DIR / "vaults.json"
    locker.REG_MENU_ROOT = r"Software\Classes\Directory\shell\__LockerTest2"
    locker.REG_UNINSTALL = r"Software\__LockerTest2Uninstall\FolderLocker"
    locker.SHORTCUT_PATH = tmp / "mgr.lnk"
    locker.INSTALL_EXE = tmp / "inst" / "locker.exe"
    locker.ensure_daemon = lambda: None
    orig_deny, orig_restore = locker.icacls_deny, locker.icacls_restore
    orig_hide, orig_show = locker.attrib_hide, locker.attrib_show
    locker.icacls_deny = locker.icacls_restore = lambda p: None
    locker.attrib_hide = locker.attrib_show = lambda p: None
    if hasattr(sys, "frozen"):
        del sys.frozen

    # A UX that records confirm() prompts and always says "no".
    class DeclineUx(locker.ConsoleUx):
        prompted = False
        def confirm(self, title, message):
            DeclineUx.prompted = True
            return False

    secret = tmp / "StillLocked"
    secret.mkdir(parents=True)
    (secret / "a.txt").write_bytes(b"data" * 100)

    try:
        # Register the menu + a locked vault.
        locker.do_install(locker.ConsoleUx())
        locker.cmd_lock(str(secret), "MyP@ss1!", locker.ConsoleUx(), hide=False)

        ux = DeclineUx()
        try:
            locker.do_uninstall(ux)
        except locker.AbortAction:
            pass
        check("uninstall warns about locked vaults", DeclineUx.prompted is True)
        check("declining the warning keeps the menu installed",
              locker._menu_installed() is True)
    finally:
        locker._reg_delete_tree(winreg.HKEY_CURRENT_USER, locker.REG_MENU_ROOT)
        locker._reg_delete_tree(winreg.HKEY_CURRENT_USER,
                                r"Software\__LockerTest2Uninstall")
        locker.icacls_deny, locker.icacls_restore = orig_deny, orig_restore
        locker.attrib_hide, locker.attrib_show = orig_hide, orig_show
        locker.ensure_daemon = orig_ensure
        locker.STATE_FILE = orig_state
        locker.APP_DIR = orig_appdir
        locker.REG_MENU_ROOT = orig_root
        locker.REG_UNINSTALL = orig_uninstall
        locker.SHORTCUT_PATH = orig_shortcut
        locker.INSTALL_EXE = orig_install_exe


if __name__ == "__main__":
    print("Running headless context-menu tests...\n")
    test_self_invocation()
    test_menu_commands()
    test_hidden_marker()
    test_password()
    test_install_uninstall()
    test_visible_lock_cycle()
    test_hidden_lock_cycle()
    test_state_guards()
    test_wrong_password()
    test_recover_cycle()
    test_forget_delete()
    test_cloud_sync_detection()
    test_uninstall_locked_warning()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed.")
    if FAIL:
        print("FAILED:", ", ".join(FAIL))
        sys.exit(1)
