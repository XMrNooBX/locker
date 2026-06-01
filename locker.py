"""
locker.py — FolderLocker for Windows
======================================
Commands:
  locker lock     <folder> <password>            Encrypt & lock a folder
  locker unlock   <folder> <password>            Decrypt (auto-relocks on lock/shutdown)
  locker unlock-f <folder> <password>            Fully unlock, remove from registry
  locker recover  <folder> <code> <new-password> Reset password via recovery code
  locker show                                    List all vaults

── Encryption model ──────────────────────────────────────────────────────────
  Envelope encryption (same principle as VeraCrypt, FileVault, BitLocker):

    master_key  = random 32 bytes, generated ONCE at first lock — never changes.
    pw_key      = Argon2id(password, pw_salt)
    wrapped_pw  = AES-256-GCM(pw_key, master_key)   ← tiny blob in vaults.json
    rec_key     = PBKDF2-SHA256(recovery_code, rec_salt)
    wrapped_rec = AES-256-GCM(rec_key, master_key)  ← tiny blob in vaults.json

  Password reset  → unwrap master_key with recovery key, re-wrap with new
                    password key.  Files are NEVER touched again.  O(1).

  File encryption : AES-256-GCM, streaming 4 MB chunks, parallel workers.
                    Each chunk uses a nonce derived from base_nonce XOR chunk_idx.
                    Handles files of any size without loading them into RAM.

  Key derivation  : Argon2id (32 MB, 2 iterations) — OWASP-compliant.

Security notice
───────────────
This source code is intentionally public (Kerckhoffs's Principle).
Your PASSWORD is the only secret — AES-256 and Argon2id are public standards.
"""

import argparse
import concurrent.futures
import ctypes
import ctypes.wintypes as W
import getpass
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import NoReturn, Optional

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from argon2 import PasswordHasher as _PH_cls
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import psutil
except ImportError:
    print("\n  [ERROR] Missing dependencies. Run:\n")
    print("    pip install cryptography argon2-cffi psutil\n")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────

LOCK_PREFIX = ".~vlt_"
APP_DIR     = Path(os.environ.get("APPDATA", Path.home())) / "FolderLocker"
STATE_FILE  = APP_DIR / "vaults.json"
PID_FILE    = APP_DIR / "daemon.pid"
LOG_FILE    = APP_DIR / "daemon.log"

# ── Self-install locations (per-user, no admin) ───────────────────────────────
# The executable is copied here on --install so the context menu points to a
# stable path even if the user moves or deletes the original download.
INSTALL_DIR    = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "FolderLocker"
INSTALL_EXE    = INSTALL_DIR / "locker.exe"
# Start Menu shortcut that launches the Vault Manager.
START_MENU_DIR = (
    Path(os.environ.get("APPDATA", Path.home()))
    / "Microsoft" / "Windows" / "Start Menu" / "Programs"
)
SHORTCUT_PATH  = START_MENU_DIR / "FolderLocker Manager.lnk"

# Registry: per-user cascading context menu on folders.
#   HKCU\Software\Classes\Directory\shell\Locker  (ExtendedSubCommandsKey cascade)
REG_MENU_ROOT  = r"Software\Classes\Directory\shell\Locker"
REG_MENU_LABEL = "Locker"

# Registry: Windows "Installed apps" / "Apps & features" uninstall entry, so the
# tool appears in Settings → Apps with a working Uninstall button (per-user, no
# admin).  HKCU\…\Uninstall\FolderLocker
REG_UNINSTALL  = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FolderLocker"
APP_VERSION    = "1.0.3"

# Argon2id — OWASP-compliant, lighter than v1 params (~2× faster)
ARGON2_TIME_COST   = 2
ARGON2_MEMORY_COST = 32_768   # 32 MB
ARGON2_PARALLELISM = 2
ARGON2_KEY_LEN     = 32       # 256-bit

NONCE_LEN   = 12              # 96-bit GCM nonce (standard)
VAULT_VER   = 2
REC_BYTES   = 16              # 128-bit recovery code entropy

# Streaming chunk size — 4 MB avoids loading entire files into RAM
# (fixes OSError on large video files) and gives smooth progress updates.
CHUNK_SIZE = 4 * 1024 * 1024

# Adaptive I/O: the throttle uses ~55 % of measured disk speed at startup
# and adjusts dynamically based on CPU / RAM / disk pressure from other
# processes.  See _AdaptiveThrottle for the full feedback loop.

# File format magic — 5 bytes prepended to every encrypted file (v2+).
# Probability of random v1-nonce matching: ~1 / 256^5 ≈ 10^-12 (negligible).
MAGIC_V2   = b'LKRV\x02'
TMP_SUFFIX = ".~tmp"          # temp suffix during encryption; filtered from file scans

# WinAPI
WM_WTSSESSION_CHANGE    = 0x02B1
WTS_SESSION_LOCK        = 0x7
WM_DESTROY              = 0x0002
WM_QUERYENDSESSION      = 0x0011
WM_ENDSESSION           = 0x0016
NOTIFY_FOR_THIS_SESSION = 0
_k32                    = ctypes.windll.kernel32
FILE_ATTRIBUTE_HIDDEN   = 0x2
FILE_ATTRIBUTE_SYSTEM   = 0x4
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

# Spawn console helpers (icacls/attrib/takeown/cmd) with no visible window.
# Without this, every helper call briefly flashes a console window — and from a
# windowed (no-console) GUI exe it can intermittently fail to initialise with
# 0xC0000142 (STATUS_DLL_INIT_FAILED), surfacing the scary
# "application was unable to start correctly" dialog.
CREATE_NO_WINDOW        = 0x08000000
STATUS_DLL_INIT_FAILED  = 0xC0000142

# ── ANSI colours ──────────────────────────────────────────────────────────────

_R  = "\033[0m"
_B  = "\033[1m"
_D  = "\033[2m"
_CY = "\033[96m"
_GR = "\033[92m"
_YL = "\033[93m"
_RD = "\033[91m"
_MG = "\033[95m"

# ── Adaptive I/O controller ───────────────────────────────────────────────
#
# Background I/O priority (SetThreadPriority) only helps when another process
# actively competes for the disk.  When nothing else is running, Windows still
# drains our queue at full speed, keeping active-time at 100 % and making the
# system feel sluggish.  A user-space rate limiter (token bucket) fixes this.
#
# Design:
#   1. calibrate(raw_mbps)  — sets initial rate to 55 % of measured disk speed
#      and starts a daemon thread that samples psutil metrics every 400 ms.
#   2. _adjust()            — feedback loop:
#        • CPU pressure    (0 at ≤15 %, 1 at ≥75 %)
#        • Memory pressure (0 at ≤70 % used, 1 at ≥92 % used)
#        • Disk pressure   (other processes' I/O rate measured as
#                           system_total_io − our_process_io)
#        pressure = max of the three signals
#        • pressure > 0.65  → back off 20 %   (fast response)
#        • 0.35 – 0.65      → ease off 5 %    (gentle)
#        • pressure < 0.35  → speed up 12 %   (reclaim headroom when idle)
#   3. consume(nbytes)      — token-bucket sleep; lock released before sleep
#      so multiple workers don't block each other.
#   4. stop()               — signals the monitor thread to pause.

class _AdaptiveThrottle:
    """
    Token-bucket rate limiter with a real-time psutil feedback loop.
    Adapts to any hardware tier and responds to competing system load.
    """
    POLL          = 0.40    # seconds between metric samples
    SPEED_UP      = 1.12    # rate multiplier when system is idle
    EASE          = 0.95    # rate multiplier when moderately loaded
    BACK_OFF      = 0.80    # rate multiplier under heavy load
    MIN_BPS       = 15.0 * 1_048_576   # 15 MB/s floor (very slow HDD)
    MAX_UTIL      = 0.85    # never claim more than 85 % of disk speed

    def __init__(self) -> None:
        self._bps     = float("inf")    # unlimited until calibrate() is called
        self._max_bps = float("inf")
        self._budget  = 0.0
        self._last_tk = time.monotonic()
        self._lock    = threading.Lock()
        # Monitor thread runs forever; pauses between operations
        self._active  = threading.Event()   # set = operation in progress
        self._proc    = psutil.Process()
        self._last_sys_io  = None
        self._last_proc_io = None
        self._last_io_t    = None
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        # Prime cpu_percent so first real call returns valid data
        psutil.cpu_percent()
        self._proc.cpu_percent()

    # ── public API ────────────────────────────────────────────────────────────

    def calibrate(self, raw_mbps: float) -> None:
        """
        Set the starting rate to 55 % of raw_mbps and start the feedback loop.
        Call once at the beginning of an encrypt/decrypt operation.
        """
        target = raw_mbps * 0.55
        with self._lock:
            self._max_bps = raw_mbps * self.MAX_UTIL * 1_048_576
            self._bps     = target * 1_048_576
            self._budget  = self._bps
            self._last_tk = time.monotonic()
        # Reset I/O baseline so delta calculation starts fresh
        try:
            self._last_sys_io  = psutil.disk_io_counters()
            self._last_proc_io = self._proc.io_counters()
            self._last_io_t    = time.monotonic()
        except Exception:
            self._last_sys_io = self._last_proc_io = self._last_io_t = None
        self._active.set()

    def stop(self) -> None:
        """Pause the feedback loop (operation complete)."""
        self._active.clear()
        with self._lock:
            self._bps = float("inf")    # no limit between operations

    def consume(self, nbytes: int) -> None:
        """Block until consuming nbytes is within the rate limit."""
        with self._lock:
            if self._bps == float("inf"):
                return
            now           = time.monotonic()
            elapsed       = now - self._last_tk
            self._last_tk = now
            self._budget  = min(self._bps, self._budget + elapsed * self._bps)
            self._budget -= nbytes
            sleep_for     = (-self._budget / self._bps) if self._budget < 0 else 0.0
            if self._budget < 0:
                self._budget = 0
        if sleep_for > 0:
            time.sleep(sleep_for)   # sleep outside the lock

    # ── feedback loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Background daemon thread: wait for activity then poll and adjust."""
        while True:
            self._active.wait()         # block until an operation starts
            time.sleep(self.POLL)
            if self._active.is_set():
                try:
                    self._adjust()
                except Exception:
                    pass

    def _adjust(self) -> None:
        """Sample psutil metrics and adjust _bps accordingly."""
        # ── 1. CPU pressure ─────────────────────────────────────────
        cpu = psutil.cpu_percent()
        # 0.0 when CPU ≤ 15 %, 1.0 when CPU ≥ 75 %
        cpu_p = max(0.0, min(1.0, (cpu - 15) / 60))

        # ── 2. Memory pressure ──────────────────────────────────
        mem = psutil.virtual_memory().percent
        # 0.0 when RAM ≤ 70 % used, 1.0 when RAM ≥ 92 % used
        mem_p = max(0.0, min(1.0, (mem - 70) / 22))

        # ── 3. Disk pressure from OTHER processes ────────────────────
        disk_p = 0.0
        now = time.monotonic()
        try:
            sys_io  = psutil.disk_io_counters()
            proc_io = self._proc.io_counters()
            if (
                self._last_sys_io  is not None
                and self._last_proc_io is not None
                and self._last_io_t    is not None
            ):
                dt = max(now - self._last_io_t, 0.001)
                sys_bps  = (
                    sys_io.read_bytes  + sys_io.write_bytes
                    - self._last_sys_io.read_bytes - self._last_sys_io.write_bytes
                ) / dt
                proc_bps = (
                    proc_io.read_bytes + proc_io.write_bytes
                    - self._last_proc_io.read_bytes - self._last_proc_io.write_bytes
                ) / dt
                other_mbps = max(0.0, sys_bps - proc_bps) / 1_048_576
                # 0.0 when other processes use < 20 MB/s,
                # 1.0 when they use > 150 MB/s
                disk_p = max(0.0, min(1.0, (other_mbps - 20) / 130))
            self._last_sys_io  = sys_io
            self._last_proc_io = proc_io
            self._last_io_t    = now
        except Exception:
            pass

        # ── 4. Combine and adjust rate ─────────────────────────────
        pressure = max(cpu_p, mem_p, disk_p)
        with self._lock:
            if pressure > 0.65:
                self._bps = max(self.MIN_BPS, self._bps * self.BACK_OFF)
            elif pressure > 0.35:
                self._bps = max(self.MIN_BPS, self._bps * self.EASE)
            else:
                self._bps = min(self._max_bps, self._bps * self.SPEED_UP)
            # Don't let stored budget exceed the new rate
            self._budget = min(self._budget, self._bps)


_throttle = _AdaptiveThrottle()


def _enable_ansi() -> None:
    try:
        ENABLE_VT = 0x0004
        h = ctypes.windll.kernel32.GetStdHandle(-11)
        m = ctypes.c_ulong()
        if ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(m)):
            ctypes.windll.kernel32.SetConsoleMode(h, m.value | ENABLE_VT)
    except Exception:
        pass


def _force_utf8_stdio() -> None:
    """
    Reconfigure stdout/stderr to UTF-8 so the Unicode UI (✓, box-drawing,
    emoji) never crashes with UnicodeEncodeError on consoles that default to a
    legacy code page (e.g. cp1252 on plain cmd or CI runners).  errors='replace'
    is a belt-and-braces fallback so a print can never abort the program.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

_force_utf8_stdio()
_enable_ansi()

# ── Output helpers ────────────────────────────────────────────────────────────

class AbortAction(Exception):
    """
    Raised to stop the current action cleanly.

    Replaces scattered sys.exit(1) calls inside the command functions so the
    GUI front-end can show a modal and unwind the Tk loop without abruptly
    terminating the process.  main() catches it and sets exit status 1.
    The console front-end maps it to the same "die" semantics.
    """
    pass


def die(msg: str) -> NoReturn:
    print(f"\n{_RD}  [✗] {msg}{_R}\n", file=sys.stderr)
    sys.exit(1)

def info(msg: str) -> None:
    print(f"{_CY}  [·] {msg}{_R}")

def ok(msg: str) -> None:
    print(f"{_GR}  [✓] {msg}{_R}")

def warn(msg: str) -> None:
    print(f"{_YL}  [!] {msg}{_R}")

# ── Animated progress bar ─────────────────────────────────────────────────────
#
# Key design choices:
#   • Redraws at ~12 fps from its own background thread — alive even during a
#     single slow large file (unlike per-file-completion updates).
#   • Fill % is driven by BYTES processed, not files — smooth for multi-GB files.
#   • bar.tick(n) is called per 4 MB chunk inside encrypt_file / decrypt_file —
#     so even one file moving through gives continuous animation.
#
#   ⣾ Encrypting  ████████████▌░░░░░░░░  52%  │  6/13 files  │  127 MB/s  │  1:04

_SPIN = "⣾⣽⣻⢿⡿⣟⣯⣷"
_EDGE = "▏▎▍▌▋▊▉"
_BW   = 26   # bar width in characters

class _Bar:
    """Byte-aware animated progress bar driven from a background thread."""

    def __init__(self, total_files: int, total_bytes: int,
                 label: str, colour: str = _CY) -> None:
        self.total_files = total_files
        self.total_bytes = max(total_bytes, 1)
        self._fdone  = 0
        self._bdone  = 0
        self._idx    = 0
        self._lock   = threading.Lock()
        self._start  = time.monotonic()
        self._stop   = threading.Event()
        self._label  = label
        self._colour = colour
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def tick(self, nbytes: int) -> None:
        """Called per chunk — drives the smooth byte-level fill."""
        with self._lock:
            self._bdone += nbytes

    def file_done(self) -> None:
        """Called when a whole file finishes."""
        with self._lock:
            self._fdone += 1

    def pump(self) -> None:
        """No-op for the console bar (it redraws from its own thread).
        The GUI progress bar overrides this to process UI events."""
        pass

    def _snap(self) -> tuple[int, int]:
        with self._lock:
            return self._fdone, self._bdone

    def _loop(self) -> None:
        while not self._stop.wait(0.08):   # ~12.5 fps
            self._draw()

    def _draw(self, final: bool = False) -> None:
        fdone, bdone = self._snap()
        elapsed = time.monotonic() - self._start

        spin  = _SPIN[self._idx % len(_SPIN)]
        self._idx += 1

        pct    = min(100, int(bdone / self.total_bytes * 100))
        filled = min(_BW, int(bdone / self.total_bytes * _BW))

        if final or bdone >= self.total_bytes:
            bar_s = f"{_GR}{'█' * _BW}{_R}"
            col   = _GR
        else:
            edge  = _EDGE[self._idx % len(_EDGE)]
            rest  = max(0, _BW - filled - 1)
            bar_s = f"{self._colour}{'█' * filled}{edge}{'░' * rest}{_R}"
            col   = self._colour

        spd  = bdone / max(elapsed, 0.01) / 1_048_576   # MB/s
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        print(
            f"\r  {_CY}{spin}{_R} "
            f"{_B}{self._label:<12}{_R}"
            f"{bar_s} "
            f"{col}{_B}{pct:>3}%{_R}  "
            f"{_D}│  {fdone}/{self.total_files} files  "
            f"│  {spd:>5.0f} MB/s  "
            f"│  {mins}:{secs:02d}{_R}",
            end="", flush=True,
        )

    def finish(self) -> None:
        self._stop.set()
        self._thread.join(timeout=0.3)
        with self._lock:             # force final 100% draw
            self._fdone = self.total_files
            self._bdone = self.total_bytes
        self._draw(final=True)
        print()


def _set_background_io() -> None:
    """
    Thread pool initializer — sets each worker thread to Windows background
    I/O priority so the OS can preempt our disk I/O for any other process.
    Combined with the rate limiter this keeps the PC fully responsive.
    """
    try:
        ctypes.windll.kernel32.SetThreadPriority(
            ctypes.windll.kernel32.GetCurrentThread(), 0x00010000
        )
    except Exception:
        pass


def _probe_disk_speed(hint_dir: Path) -> float:
    """
    Measure the actual disk write+read speed (MB/s) by timing a 4 MB I/O round-trip.
    Probes on the same drive as hint_dir so multi-drive systems are measured correctly.
    Falls back to a conservative 60 MB/s on any error (safe for old HDDs).
    """
    probe = hint_dir / ".locker_probe~"
    data  = os.urandom(CHUNK_SIZE)
    try:
        hint_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.monotonic()
        probe.write_bytes(data)
        probe.read_bytes()
        elapsed = max(time.monotonic() - t0, 0.001)
        mbps = (CHUNK_SIZE * 2) / elapsed / 1_048_576   # write + read = 2×
        return max(30.0, min(2_000.0, mbps))             # clamp to sane range
    except Exception:
        return 60.0
    finally:
        try:
            probe.unlink(missing_ok=True)
        except Exception:
            pass


def _optimal_workers(files: list[Path]) -> int:
    """
    Choose worker count based on the folder's file-size profile.

    Large files (avg > 64 MB):
        Sequential I/O is optimal — NVMe sequential >> NVMe random.
        1 worker reads each file start-to-finish without head-of-line blocking.

    Small files (avg ≤ 64 MB, e.g. photos, documents):
        AES overhead per file is tiny; file-system overhead dominates.
        Parallel workers overlap I/O waits and CPU work.
        Cap at min(cores/2, 4) so we never over-subscribe the I/O bus.
    """
    if not files:
        return 1
    sizes  = [f.stat().st_size for f in files]
    avg_mb = sum(sizes) / len(sizes) / 1_048_576
    if avg_mb > 64:
        return 1
    cores = os.cpu_count() or 2
    return max(1, min(cores // 2, 4, len(files)))


def _process_files(
    files: list[Path],
    key: bytes,
    op_fn,
    label: str,
    colour: str,
    silent: bool = False,
    workers: int = 1,
    progress_factory=None,
) -> None:
    """
    Process files with op_fn in a thread pool with background I/O priority.
    silent=True skips the progress bar (used by the background daemon).

    progress_factory(total_files, total_bytes, label, colour) -> bar is used to
    create the progress display.  It defaults to the console _Bar; the GUI passes
    a factory that returns a ProgressDialog exposing the same
    .tick / .file_done / .finish interface.
    """
    if not files:
        return

    if silent:
        for f in files:
            try:
                op_fn(f, key, None)
            except Exception:
                pass   # daemon: best-effort, don't crash on one file
        return

    if progress_factory is None:
        progress_factory = _Bar

    total_bytes = sum(f.stat().st_size for f in files)
    bar = progress_factory(len(files), total_bytes, label, colour)
    errors: list[tuple[Path, Exception]] = []

    def _worker(path: Path) -> None:
        op_fn(path, key, bar)
        bar.file_done()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(workers, len(files)),
            initializer=_set_background_io,
        ) as ex:
            futs = {ex.submit(_worker, f): f for f in files}
            pending = set(futs)
            # Poll with a short timeout so the main thread can pump the GUI
            # progress bar (bar.pump() is a no-op for the console _Bar).
            while pending:
                done, pending = concurrent.futures.wait(
                    pending, timeout=0.05,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for fut in done:
                    try:
                        fut.result()
                    except Exception as exc:
                        errors.append((futs[fut], exc))
                bar.pump()
    finally:
        bar.finish()

    if errors:
        names = ", ".join(p.name for p, _ in errors[:5])
        suffix = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        die(f"{len(errors)} file(s) failed: {names}{suffix}\n"
            f"  First error: {errors[0][1]}")

# ── Password policy ───────────────────────────────────────────────────────────

_POLICY = (
    "Minimum 6 characters including:\n"
    "   · one UPPERCASE  (A–Z)\n"
    "   · one lowercase  (a–z)\n"
    "   · one digit      (0–9)\n"
    "   · one special    (!@#$%^&* …)"
)

def password_errors(pw: str) -> list[str]:
    """Return a list of unmet password-policy requirements (empty = valid)."""
    errs = []
    if len(pw) < 6:                         errs.append("at least 6 characters")
    if not re.search(r"[A-Z]", pw):         errs.append("an uppercase letter")
    if not re.search(r"[a-z]", pw):         errs.append("a lowercase letter")
    if not re.search(r"\d",    pw):         errs.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw): errs.append("a special character")
    return errs

def enforce_password(pw: str) -> None:
    errs = password_errors(pw)
    if errs:
        die(f"Password too weak — missing {', '.join(errs)}.\n\n  {_POLICY}")

def password_strength(pw: str) -> tuple[int, str]:
    """
    Score a password 0–5 for the GUI strength meter.
    Returns (score, label).  Score counts satisfied policy rules plus a
    length bonus, capped at 5.
    """
    if not pw:
        return 0, ""
    satisfied = 5 - len(password_errors(pw))
    score = max(0, satisfied)
    if len(pw) >= 12 and score >= 5:
        score = 5
    labels = {0: "Very weak", 1: "Very weak", 2: "Weak",
              3: "Fair", 4: "Good", 5: "Strong"}
    return score, labels.get(score, "")

# ── Recovery code ─────────────────────────────────────────────────────────────

def gen_recovery_code() -> str:
    """128-bit random code as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX."""
    raw = secrets.token_hex(REC_BYTES)
    return "-".join(raw[i:i+4] for i in range(0, len(raw), 4))

def _norm_code(code: str) -> bytes:
    return code.replace("-", "").lower().encode()

# ── Key material ──────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Argon2id: password → 256-bit wrapping key. Memory-hard, GPU-resistant."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_KEY_LEN,
        type=Argon2Type.ID,
    )

def derive_rec_key(code: str, salt: bytes) -> bytes:
    """
    PBKDF2-SHA256: recovery code → 256-bit key.
    Recovery codes have 128-bit entropy so PBKDF2 is sufficient
    (no memory-hardness needed) and keeps recovery instant.
    """
    return hashlib.pbkdf2_hmac("sha256", _norm_code(code), salt, 1_000, dklen=32)

def wrap_key(master: bytes, wrapping: bytes) -> bytes:
    """Encrypt master key with wrapping key → nonce(12) + ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(wrapping).encrypt(nonce, master, None)

def unwrap_key(blob: bytes, wrapping: bytes) -> bytes:
    """Decrypt wrapped master key. Raises ValueError on wrong key."""
    try:
        return AESGCM(wrapping).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)
    except Exception:
        raise ValueError("Bad wrapping key or corrupted blob.")


class BadPassword(ValueError):
    """Raised by _derive_master_key when the password/recovery code is wrong."""


def _derive_master_key(vault: dict, password: str) -> bytes:
    """
    Verify the password and return the vault's master key.

    Pure computation (no UI, no global Tk) so it can run on a worker thread via
    ux.run_blocking().  Raises BadPassword on an incorrect password.  Handles
    both v2 (key-wrapping) and legacy v1 (argon2_hash) vaults.
    """
    if _is_v2(vault):
        pw_key = derive_key(password, bytes.fromhex(vault["pw_salt"]))
        try:
            return unwrap_key(bytes.fromhex(vault["wrapped_pw"]), pw_key)
        except ValueError:
            raise BadPassword("Incorrect password.")
    # Legacy v1 vault (argon2_hash + enc_salt format)
    _ph = _PH_cls(time_cost=3, memory_cost=65536, parallelism=4)
    try:
        _ph.verify(vault["argon2_hash"], password)
    except Exception:
        raise BadPassword("Incorrect password.")
    return hash_secret_raw(
        secret=password.encode(), salt=bytes.fromhex(vault["enc_salt"]),
        time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
        type=Argon2Type.ID,
    )

# ── Streaming AES-256-GCM ─────────────────────────────────────────────────────
#
# V2 on-disk file format:
#   [5 bytes: MAGIC_V2 = b'LKRV\x02']
#   [12 bytes: base_nonce]
#   [repeated chunks]:
#     [4 bytes big-endian: ciphertext length]
#     [N bytes: AES-GCM(chunk_nonce, plaintext_chunk) + 16-byte auth tag]
#
# chunk_nonce = base_nonce XOR chunk_index_as_12_bytes
#
# Each chunk is independently authenticated — corruption or truncation is
# detected immediately.  Chunks never exceed CHUNK_SIZE bytes of plaintext.
#
# V1 legacy format (old single-pass):
#   [12 bytes: nonce] [full AES-GCM ciphertext]
# Detected by absence of MAGIC_V2 at offset 0.

def _chunk_nonce(base: bytes, idx: int) -> bytes:
    """Derive a per-chunk nonce: base_nonce XOR big-endian chunk index."""
    return bytes(a ^ b for a, b in zip(base, idx.to_bytes(NONCE_LEN, "big")))


def encrypt_file(path: Path, key: bytes, progress=None) -> None:
    """
    Encrypt a file in 4 MB chunks (streaming).
    Writes to a .~tmp file then atomically replaces the original.

    IDEMPOTENT: if the file already carries the LKRV\x02 magic header
    (i.e. it was encrypted in a previous interrupted run), it is skipped.
    This prevents double-encryption after a power-loss or Ctrl-C.
    """
    # ── Guard: skip files already encrypted ──────────────────────────────────
    try:
        with open(path, "rb") as _chk:
            already = _chk.read(len(MAGIC_V2))
        if already == MAGIC_V2:
            # Already encrypted — skip.  Don't tick the progress bar here:
            # total_bytes was computed from pre-encryption sizes, and this
            # file's on-disk size is now larger (ciphertext overhead).
            # The bar's finish() forces 100 % at the end anyway.
            return
    except Exception:
        pass   # unreadable file — let the main open() fail with a useful error

    tmp  = path.with_name(path.name + TMP_SUFFIX)
    base = os.urandom(NONCE_LEN)
    gcm  = AESGCM(key)
    try:
        with open(path, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(MAGIC_V2)
            fout.write(base)
            cidx = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = gcm.encrypt(_chunk_nonce(base, cidx), chunk, None)
                fout.write(len(ct).to_bytes(4, "big"))
                fout.write(ct)
                cidx += 1
                _throttle.consume(len(chunk))
                if progress is not None:
                    progress.tick(len(chunk))
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def decrypt_file(path: Path, key: bytes, progress=None) -> None:
    """
    Decrypt a v2 (chunked) or v1 (legacy single-pass) encrypted file.
    Writes to a .~tmp file then atomically replaces the original.
    progress.tick(n) is called after each chunk with the plaintext byte count.

    IDEMPOTENT: if the file does NOT start with MAGIC_V2 and is too small
    to be a valid v1 encrypted file, it is assumed to already be plaintext
    and is skipped.  This prevents garbage output after an interrupted
    decrypt run where some files were already restored.
    """
    # ── Guard: skip files that are clearly already decrypted ─────────────────
    try:
        with open(path, "rb") as _chk:
            head = _chk.read(len(MAGIC_V2))
        if head != MAGIC_V2:
            # Not V2.  For V1 legacy, the minimum valid file is
            # nonce(12) + tag(16) = 28 bytes.  Anything smaller cannot
            # be a valid encrypted file.
            if path.stat().st_size < 28:
                if progress is not None:
                    progress.tick(path.stat().st_size)
                return
    except Exception:
        pass

    tmp = path.with_name(path.name + TMP_SUFFIX)
    gcm = AESGCM(key)
    try:
        with open(path, "rb") as fin, open(tmp, "wb") as fout:
            header = fin.read(len(MAGIC_V2))
            if header == MAGIC_V2:
                # ── V2 chunked format ──
                base = fin.read(NONCE_LEN)
                cidx = 0
                while True:
                    lb = fin.read(4)
                    if not lb:
                        break
                    ct_len = int.from_bytes(lb, "big")
                    ct     = fin.read(ct_len)
                    if len(ct) != ct_len:
                        raise ValueError(f"Truncated encrypted file: {path}")
                    chunk = gcm.decrypt(_chunk_nonce(base, cidx), ct, None)
                    fout.write(chunk)
                    cidx += 1
                    _throttle.consume(len(chunk))   # rate-limit to keep disk responsive
                    if progress is not None:
                        progress.tick(len(chunk))
            else:
                # ── V1 legacy: 12-byte nonce + full ciphertext ──
                fin.seek(0)
                nonce = fin.read(NONCE_LEN)
                data  = fin.read()
                pt    = gcm.decrypt(nonce, data, None)
                fout.write(pt)
                if progress is not None:
                    progress.tick(len(pt))
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _list_files(folder: Path) -> list[Path]:
    """All real files in folder, excluding .~tmp temporaries and probe files."""
    return [
        f for f in folder.rglob("*")
        if f.is_file()
        and not f.name.endswith(TMP_SUFFIX)
        and f.name != ".locker_probe~"
    ]


def _cleanup_tmp(folder: Path) -> None:
    """Remove any orphaned .~tmp files left by a previously interrupted run."""
    for f in folder.rglob("*"):
        if f.is_file() and f.name.endswith(TMP_SUFFIX):
            try:
                f.unlink()
            except Exception:
                pass


def encrypt_folder(folder: Path, key: bytes, silent: bool = False,
                   progress_factory=None) -> None:
    _cleanup_tmp(folder)
    files = _list_files(folder)
    if not silent:
        raw_mbps = _probe_disk_speed(folder.parent)
        workers  = _optimal_workers(files)
        _throttle.calibrate(raw_mbps)
    else:
        workers = 1
    try:
        _process_files(files, key, encrypt_file, "Encrypting", _MG, silent, workers,
                       progress_factory)
    finally:
        if not silent:
            _throttle.stop()


def decrypt_folder(folder: Path, key: bytes, silent: bool = False,
                   progress_factory=None) -> None:
    _cleanup_tmp(folder)
    files = _list_files(folder)
    if not silent:
        raw_mbps = _probe_disk_speed(folder.parent)
        workers  = _optimal_workers(files)
        _throttle.calibrate(raw_mbps)
    else:
        workers = 1
    try:
        _process_files(files, key, decrypt_file, "Decrypting", _CY, silent, workers,
                       progress_factory)
    finally:
        if not silent:
            _throttle.stop()


# ── State (JSON) ──────────────────────────────────────────────────────────────
#
# Version 2 vault record fields:
#   version      : 2
#   original_path: str  — path before first lock
#   locked_path  : str  — path with .~vlt_ prefix (while locked)
#   pw_salt      : hex  — 32-byte Argon2id salt  →  pw_key
#   wrapped_pw   : hex  — nonce(12) + AES-GCM(pw_key,  master_key)
#   rec_salt     : hex  — 32-byte PBKDF2 salt    →  rec_key
#   wrapped_rec  : hex  — nonce(12) + AES-GCM(rec_key, master_key)
#   status       : "locked" | "unlocked"
#   unlock_key   : null | hex(32)  — master_key cached while unlocked

def load_state() -> dict:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    for path in (STATE_FILE, STATE_FILE.with_suffix(".tmp")):
        if path.exists():
            try:
                data = json.loads(path.read_text("utf-8"))
                if "vaults" in data:
                    return data
            except Exception:
                continue
    return {"vaults": {}}

def save_state(state: dict) -> None:
    """Atomic write: tmp file + rename so a crash never truncates vaults.json."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_FILE)

def find_vault(state: dict, target: Path):
    """Look up a vault by original_path (exact or resolved) or locked_path."""
    key = str(target)
    if key in state["vaults"]:
        return key, state["vaults"][key]
    resolved = target.resolve()
    for k, v in state["vaults"].items():
        if Path(v["original_path"]).resolve() == resolved:
            return k, v
        if Path(v["locked_path"]).resolve() == resolved:
            return k, v
    return None, None

def _is_v2(vault: dict) -> bool:
    return vault.get("version", 1) >= 2

def _cloud_sync_warning(p: Path) -> Optional[str]:
    """
    Return a warning string if the folder appears to live inside a cloud-sync
    location (OneDrive, Dropbox, Google Drive, iCloud).  Locking such a folder
    uploads ciphertext to the cloud, can cause sync conflicts, and may fill
    version history.  Returns None if no sync provider is detected.
    """
    try:
        parts_lower = [seg.lower() for seg in p.resolve().parts]
    except Exception:
        parts_lower = [seg.lower() for seg in p.parts]
    full = "\\".join(parts_lower)

    providers = {
        "OneDrive":     "onedrive",
        "Dropbox":      "dropbox",
        "Google Drive": "google drive",
        "iCloud Drive": "iclouddrive",
    }
    # Also catch env-var-based OneDrive roots.
    onedrive_roots = [
        os.environ.get("OneDrive", ""),
        os.environ.get("OneDriveConsumer", ""),
        os.environ.get("OneDriveCommercial", ""),
    ]
    try:
        rp = str(p.resolve()).lower()
    except Exception:
        rp = str(p).lower()
    for root in onedrive_roots:
        if root and rp.startswith(root.lower()):
            return "OneDrive"

    for name, token in providers.items():
        if token in full:
            return name
    return None

def _vault_hidden(vault: dict) -> bool:
    """
    Return the Hidden_Marker for a vault.

    Records created by Lock_Hide_Action set hidden=True; the visible Lock_Action
    sets hidden=False.  Legacy records (created before the marker existed) were
    always renamed + hidden, so they default to True.
    """
    return vault.get("hidden", True)

# ── Windows FS helpers ────────────────────────────────────────────────────────

def _no_window_startupinfo():
    """STARTUPINFO that hides the console window of a spawned helper process."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0   # SW_HIDE
    return si


def _run(cmd: list[str], retries: int = 2) -> subprocess.CompletedProcess:
    """
    Run a Windows console helper (icacls/attrib/takeown/cmd) without flashing a
    console window and without inheriting GUI handles.

    From a windowed (pythonw / Nuitka windowed) host the OS occasionally fails
    to start a console child with 0xC0000142 (STATUS_DLL_INIT_FAILED).  This is
    transient, so we retry a couple of times before giving up.  The call is
    best-effort: callers already tolerate failure, and never surface this exit
    code to the user.
    """
    last = None
    for attempt in range(retries + 1):
        try:
            last = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
                startupinfo=_no_window_startupinfo(),
            )
        except Exception:
            return subprocess.CompletedProcess(cmd, 1, "", "")
        # 0xC0000142 comes back as a signed/large return code; retry it.
        rc = last.returncode & 0xFFFFFFFF if last.returncode is not None else 0
        if rc != STATUS_DLL_INIT_FAILED:
            return last
        time.sleep(0.15 * (attempt + 1))
    return last if last is not None else subprocess.CompletedProcess(cmd, 1, "", "")

def attrib_hide(p: Path) -> None:
    attrs = _k32.GetFileAttributesW(str(p))
    if attrs == INVALID_FILE_ATTRIBUTES:
        _run(["attrib", "+h", "+s", str(p)]); return
    _k32.SetFileAttributesW(str(p), attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)

def attrib_show(p: Path) -> None:
    attrs = _k32.GetFileAttributesW(str(p))
    if attrs == INVALID_FILE_ATTRIBUTES:
        _run(["attrib", "-h", "-s", str(p)]); return
    _k32.SetFileAttributesW(str(p), attrs & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))

def icacls_deny(p: Path) -> None:
    _run(["icacls", str(p), "/deny", "Everyone:(OI)(CI)F", "/T", "/Q"])

def icacls_restore(p: Path) -> None:
    u = os.environ.get("USERNAME", "")
    _run(["icacls", str(p), "/remove:d", "Everyone", "/T", "/Q"])
    if u:
        _run(["icacls", str(p), "/remove:d", u, "/T", "/Q"])
    _run(["icacls", str(p), "/reset", "/T", "/Q"])

def apply_lock_fs(p: Path) -> None:
    attrib_hide(p)
    icacls_deny(p)

def _lock_and_hide_fs(orig: Path, locked_path: Path) -> None:
    """Rename a folder to its hidden vault name then apply the deny ACL.
    Pure filesystem work — safe to run off the UI thread via run_blocking()."""
    orig.rename(locked_path)
    apply_lock_fs(locked_path)

def apply_lock_fs_visible(p: Path) -> None:
    """
    Filesystem lock for the visible Lock_Action: deny access for Everyone but
    leave the folder visible — no HIDDEN/SYSTEM attributes, no rename.
    Contents are still AES-256-GCM encrypted regardless of the ACL.
    """
    icacls_deny(p)

def apply_unlock_fs(p: Path) -> None:
    icacls_restore(p)
    attrib_show(p)

# ── Daemon helpers ────────────────────────────────────────────────────────────

def _is_packaged() -> bool:
    """
    True when running as a packaged executable — either PyInstaller (sets
    sys.frozen) or Nuitka (sets the module global __compiled__).  Nuitka does
    NOT set sys.frozen, which is why we check both.
    """
    return getattr(sys, "frozen", False) or "__compiled__" in globals()


def _real_exe() -> str:
    """
    The path to the actual on-disk executable that the user launched.

    With Nuitka --onefile, sys.executable points INSIDE a temporary extraction
    folder that is deleted when the process exits, so it must NOT be written to
    the registry.  sys.argv[0] holds the real launcher path for both Nuitka and
    PyInstaller; fall back to sys.executable only if argv[0] looks unusable.
    """
    argv0 = sys.argv[0] if sys.argv else ""
    try:
        if argv0 and os.path.isabs(argv0) and argv0.lower().endswith(".exe") \
                and os.path.exists(argv0):
            return argv0
    except Exception:
        pass
    return sys.executable


def daemon_running() -> bool:
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) works without admin rights
        # and is sufficient to check if the PID is alive.
        h = _k32.OpenProcess(0x1000, False, pid)
        if h:
            _k32.CloseHandle(h)
            return True
    except Exception:
        pass
    PID_FILE.unlink(missing_ok=True)
    return False

def ensure_daemon() -> None:
    if daemon_running():
        return
    if _is_packaged():
        # Packaged exe: relaunch the installed copy with --daemon.  Prefer the
        # stable installed exe (the running one may be a temp Nuitka extraction
        # that vanishes on exit).  CREATE_NO_WINDOW keeps the windowed process
        # hidden.
        exe = str(INSTALL_EXE) if INSTALL_EXE.exists() else _real_exe()
        cmd = [exe, "--daemon"]
    else:
        # From source: prefer pythonw.exe so no console window flashes.
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        exe = str(pythonw) if pythonw.exists() else sys.executable
        cmd = [exe, os.path.abspath(__file__), "--daemon"]
    subprocess.Popen(
        cmd,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
        close_fds=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)

# ── Recovery code display ─────────────────────────────────────────────────────

def _show_recovery(code: str) -> None:
    IW = 56
    def _c(t: str) -> str:
        p = max(0, IW - len(t)); l = p // 2
        return " " * l + t + " " * (p - l)
    border = "═" * IW
    print()
    print(f"  {_YL}╔{border}╗{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}║{_B}{_c('⚠  SAVE YOUR RECOVERY CODE  ⚠')}{_R}{_YL}║{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}╠{border}╣{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    p = max(0, IW - len(code)); l = p // 2
    print(f"  {_YL}║{_R}{' ' * l}{_CY}{_B}{code}{_R}{' ' * (p - l)}{_YL}║{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}╠{border}╣{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}║{_R}{_c('If you forget your password, use this code')}{_YL}║{_R}")
    print(f"  {_YL}║{_R}{_c('to reset:  locker recover <folder> <code> <newpw>')}{_YL}║{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}║{_R}{_RD}{_c('This code will NOT be shown again.')}{_R}{_YL}║{_R}")
    print(f"  {_YL}║{_c('')}║{_R}")
    print(f"  {_YL}╚{border}╝{_R}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
# UX CONTEXT — front-end abstraction
# ══════════════════════════════════════════════════════════════════════════════
#
# The command functions (cmd_lock, cmd_unlock, …) collect a password, show the
# recovery code, render progress, and report errors/success through a UxContext
# rather than calling getpass/print/_Bar/die directly.  This lets the SAME
# locking logic drive two front-ends:
#
#   ConsoleUx — today's terminal behaviour (getpass, ANSI art, _Bar, die/ok).
#   GuiUx     — tkinter dialogs, used when launched from the right-click menu.
#
# Only GuiUx imports tkinter (lazily), so the CLI and daemon paths never load it.


class UxContext:
    """Base front-end interface.  Subclasses implement console or GUI behaviour."""

    is_gui = False

    def get_password(self, folder_name: str, confirm: bool) -> Optional[str]:
        """Return a password, or None if the user cancelled."""
        raise NotImplementedError

    def show_recovery(self, code: str) -> None:
        """Display the one-time recovery code and block until acknowledged."""
        raise NotImplementedError

    def make_progress(self, total_files: int, total_bytes: int,
                      label: str, colour: str):
        """Return a progress object exposing .tick/.file_done/.finish/.pump."""
        raise NotImplementedError

    def progress_factory(self):
        """Return a callable usable as encrypt_folder(progress_factory=…)."""
        return self.make_progress

    def run_blocking(self, label: str, fn, *args, **kwargs):
        """
        Run a blocking, non-UI callable (key derivation, ACL changes, deletes)
        and return its result.

        The base/console implementation prints the label then calls it.  The
        GUI overrides this to run fn on a worker thread while keeping the window
        responsive and showing an animated "working" indicator, so long
        operations never make the UI freeze ("Not Responding").
        """
        self.info(label.rstrip("…").rstrip(".") + "...")
        return fn(*args, **kwargs)

    def error(self, msg: str) -> NoReturn:
        """Report an error then abort the action."""
        raise NotImplementedError

    def success(self, title: str, lines: list[str]) -> None:
        """Report successful completion."""
        raise NotImplementedError

    def info(self, msg: str) -> None:
        """Report a progress / informational message."""
        raise NotImplementedError

    def confirm(self, title: str, message: str) -> bool:
        """Ask the user a yes/no question. Returns True if they confirm."""
        raise NotImplementedError


class ConsoleUx(UxContext):
    """Terminal front-end — preserves the original CLI behaviour exactly."""

    is_gui = False

    def get_password(self, folder_name: str, confirm: bool) -> Optional[str]:
        try:
            pw = getpass.getpass(f"  Password for '{folder_name}': ")
        except (EOFError, KeyboardInterrupt):
            return None
        if confirm:
            try:
                pw2 = getpass.getpass("  Confirm password: ")
            except (EOFError, KeyboardInterrupt):
                return None
            if pw != pw2:
                self.error("Passwords do not match.")
        return pw

    def show_recovery(self, code: str) -> None:
        _show_recovery(code)

    def make_progress(self, total_files, total_bytes, label, colour):
        return _Bar(total_files, total_bytes, label, colour)

    def error(self, msg: str) -> NoReturn:
        print(f"\n{_RD}  [✗] {msg}{_R}\n", file=sys.stderr)
        raise AbortAction(msg)

    def success(self, title: str, lines: list[str]) -> None:
        ok(title)
        for ln in lines:
            print(f"  {ln}")

    def info(self, msg: str) -> None:
        info(msg)

    def confirm(self, title: str, message: str) -> bool:
        warn(title)
        for ln in message.splitlines():
            print(f"  {ln}")
        try:
            ans = input("  Type 'yes' to continue: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes")


# ── tkinter GUI front-end ─────────────────────────────────────────────────────
#
# All Tk usage is confined here and imported lazily inside _tk() so that the
# console and daemon code paths never pay the import cost or require a display.

def _tk():
    """Lazy import of tkinter; raises a clear error if unavailable."""
    import tkinter as tk
    from tkinter import ttk
    return tk, ttk


def _icon_path() -> Optional[str]:
    """Locate the bundled lock icon (locker.ico).

    When frozen with PyInstaller (--add-data), the icon is unpacked into
    sys._MEIPASS; otherwise it sits next to the exe or the source script.
    """
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "locker.ico")
    if _is_packaged():
        candidates.append(Path(_real_exe()).parent / "locker.ico")
        candidates.append(Path(sys.executable).parent / "locker.ico")
    else:
        candidates.append(Path(os.path.abspath(__file__)).parent / "locker.ico")
    for p in candidates:
        if p.exists():
            return str(p)
    return None


# ── Theme ─────────────────────────────────────────────────────────────────────
# A modern dark theme.  The 'clam' ttk theme is used because it honours custom
# colours (the native Windows theme ignores widget background colours).

_THEME = {
    "bg":        "#11131c",   # window background (near-black navy)
    "surface":   "#191c28",   # raised panels
    "card":      "#1f2333",   # cards / list rows
    "field":     "#262b3d",   # input fill
    "text":      "#f1f3fb",   # primary text
    "muted":     "#9aa3bd",   # secondary text
    "border":    "#2c3245",   # hairline borders
    "accent":    "#6366f1",   # primary action (indigo)
    "accent_hi": "#818cf8",   # primary hover (lighter so it pops on dark)
    "accent_lo": "#3a3f63",   # primary disabled
    "danger":    "#f87171",
    "danger_hi": "#ef4444",
    "success":   "#34d399",
    "success_hi":"#10b981",
    "warning":   "#fbbf24",
    "warning_hi":"#f59e0b",
}

_FONT      = "Segoe UI"
_FONT_BODY = (_FONT, 10)
_FONT_H1   = (_FONT, 16, "bold")
_FONT_H2   = (_FONT, 10, "bold")
_FONT_SM   = (_FONT, 9)


def _accent_text(hex_accent: str) -> str:
    """Pick black or white text for best contrast on a coloured button."""
    h = hex_accent.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    return "#11131c" if luminance > 0.6 else "#ffffff"


_TK_ROOT = None   # single hidden Tk root; all windows are Toplevels of it
_ACTIVE_PARENT = None   # the most recent visible window, so dialogs sit above it


def _get_root():
    """
    Return the one shared, hidden Tk root, creating it on first use.

    tkinter only supports a single Tk() per process; creating extra Tk() roots
    (e.g. a dialog opened from the Manager) causes event-loop conflicts that
    silently break operations.  Every window is therefore a Toplevel of this
    one hidden root, and dialogs run modally via wait_window() rather than
    nested mainloop() calls.
    """
    global _TK_ROOT
    tk, ttk = _tk()
    if _TK_ROOT is None or not _TK_ROOT.winfo_exists():
        _TK_ROOT = tk.Tk()
        _TK_ROOT.withdraw()                 # never shown
        ico = _icon_path()
        if ico:
            try:
                _TK_ROOT.iconbitmap(ico)
            except Exception:
                pass
        _apply_theme(ttk.Style(_TK_ROOT))
    return _TK_ROOT


def _apply_theme(style) -> None:
    """Configure the ttk 'clam' theme with our colours (idempotent)."""
    try:
        style.theme_use("clam")
    except Exception:
        pass
    accent = _THEME["accent"]
    style.configure(".", background=_THEME["bg"], foreground=_THEME["text"],
                    font=_FONT_BODY, borderwidth=0)
    style.configure("TFrame", background=_THEME["bg"])
    style.configure("Card.TFrame", background=_THEME["card"])
    style.configure("Surface.TFrame", background=_THEME["surface"])
    style.configure("TLabel", background=_THEME["bg"], foreground=_THEME["text"])
    style.configure("Card.TLabel", background=_THEME["card"], foreground=_THEME["text"])
    style.configure("Muted.TLabel", background=_THEME["bg"],
                    foreground=_THEME["muted"], font=_FONT_SM)
    style.configure("CardMuted.TLabel", background=_THEME["card"],
                    foreground=_THEME["muted"], font=_FONT_SM)
    style.configure("H1.TLabel", background=_THEME["bg"], foreground=_THEME["text"],
                    font=_FONT_H1)
    style.configure("HSub.TLabel", background=_THEME["bg"],
                    foreground=_THEME["muted"], font=_FONT_SM)
    style.configure("H2.TLabel", background=_THEME["bg"], foreground=_THEME["muted"],
                    font=_FONT_H2)
    style.configure("TEntry", fieldbackground=_THEME["field"],
                    foreground=_THEME["text"], bordercolor=_THEME["border"],
                    lightcolor=_THEME["border"], darkcolor=_THEME["border"],
                    insertcolor=_THEME["text"], padding=10, relief="flat")
    style.map("TEntry",
              bordercolor=[("focus", accent)],
              lightcolor=[("focus", accent)],
              darkcolor=[("focus", accent)])


def _make_root(title: str, width: int, height: int, accent: str = None):
    """
    Create a themed, centered window (a Toplevel of the shared hidden root).
    The returned object behaves like a Tk root for our purposes (title, bind,
    protocol, destroy, geometry, etc.).  Returns (tk, ttk, win, style).
    """
    tk, ttk = _tk()
    parent = _get_root()
    root = tk.Toplevel(parent)
    root.title(title)
    root.configure(bg=_THEME["bg"])
    root.resizable(False, False)
    ico = _icon_path()
    if ico:
        try:
            root.iconbitmap(ico)
        except Exception:
            pass

    style = ttk.Style(root)
    _apply_theme(style)
    accent = accent or _THEME["accent"]
    # Per-window focus accent for entries.
    style.map("TEntry",
              bordercolor=[("focus", accent)],
              lightcolor=[("focus", accent)],
              darkcolor=[("focus", accent)])


    # Checkbutton
    style.configure("TCheckbutton", background=_THEME["bg"],
                    foreground=_THEME["text"], focuscolor=_THEME["bg"])
    style.map("TCheckbutton",
              background=[("active", _THEME["bg"])],
              indicatorcolor=[("selected", accent), ("!selected", _THEME["field"])])

    # Treeview (Manager)
    style.configure("Treeview", background=_THEME["card"],
                    fieldbackground=_THEME["card"], foreground=_THEME["text"],
                    rowheight=34, borderwidth=0, font=_FONT_BODY)
    style.configure("Treeview.Heading", background=_THEME["surface"],
                    foreground=_THEME["muted"], font=(_FONT, 9, "bold"),
                    relief="flat", padding=8)
    style.map("Treeview.Heading", background=[("active", _THEME["surface"])])
    style.map("Treeview", background=[("selected", accent)],
              foreground=[("selected", _accent_text(accent))])

    style.configure("Accent.Horizontal.TProgressbar",
                    troughcolor=_THEME["field"], background=accent,
                    bordercolor=_THEME["field"], lightcolor=accent,
                    darkcolor=accent, thickness=12)

    # Center
    root.update_idletasks()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    x = (sw - width) // 2
    y = (sh - height) // 3
    root.geometry(f"{width}x{height}+{x}+{y}")
    # Topmost/focus is managed by _run_modal for dialogs and by the Manager
    # itself; don't force it here (it caused dialogs to flash and fall behind).
    return tk, ttk, root, style


def _run_modal(win) -> None:
    """
    Run a Toplevel modally and block until it closes.

    Two cases:
      • A visible parent window is already running its own mainloop (e.g. the
        Manager): use wait_window(), which nests cleanly.
      • No outer mainloop is running (a one-shot `lock --gui` command): drive
        the shared root's mainloop() and quit() it when this window closes.
        wait_window() alone is unreliable as the first/only window in a frozen
        (Nuitka) exe — it can return immediately, making the dialog flash.
    """
    root = _get_root()
    has_parent = (_ACTIVE_PARENT is not None and _win_alive(_ACTIVE_PARENT)
                  and _ACTIVE_PARENT is not root)
    parent = _ACTIVE_PARENT if has_parent else root
    try:
        win.transient(parent)
    except Exception:
        pass
    try:
        win.update_idletasks()
        win.deiconify()
        win.lift()
        win.attributes("-topmost", True)
        win.focus_force()
        win.grab_set()
        win.after(300, lambda: _win_alive(win)
                  and win.attributes("-topmost", False))
    except Exception:
        pass

    if has_parent:
        win.wait_window()
    else:
        # No ambient loop — run one and stop it when the window is destroyed.
        win.bind("<Destroy>",
                 lambda e: e.widget is win and root.quit(), add="+")
        root.mainloop()
    try:
        if _win_alive(parent) and parent is not root:
            parent.lift()
            parent.focus_force()
    except Exception:
        pass


def _win_alive(win) -> bool:
    try:
        return bool(win.winfo_exists())
    except Exception:
        return False


def _header(parent, ttk, icon: str, title: str, subtitle: str = "",
            accent: str = None):
    """
    Build a header with a coloured accent bar on the left, an icon chip, a title
    and an optional subtitle — sitting on the dark background.
    """
    import tkinter as tk
    accent = accent or _THEME["accent"]
    bar = ttk.Frame(parent, style="TFrame")
    bar.pack(fill="x", padx=24, pady=(22, 4))

    # Coloured icon chip
    chip = tk.Frame(bar, bg=accent, width=44, height=44)
    chip.pack(side="left")
    chip.pack_propagate(False)
    tk.Label(chip, text=icon, bg=accent, fg=_accent_text(accent),
             font=(_FONT, 16)).pack(expand=True)

    txt = ttk.Frame(bar, style="TFrame")
    txt.pack(side="left", padx=14, fill="x", expand=True)
    ttk.Label(txt, text=title, style="H1.TLabel").pack(anchor="w")
    if subtitle:
        lbl = ttk.Label(txt, text=subtitle, style="HSub.TLabel", wraplength=330)
        lbl.pack(anchor="w", pady=(1, 0))
    return bar


def _button(parent, text, command, kind="accent", accent=None):
    """
    A reliable flat, rounded-feel button built on tk.Button (NOT ttk).

    The ttk 'clam' theme renders custom button foreground colours unreliably on
    Windows (text can disappear).  A plain tk.Button gives full, predictable
    control over background/text colour with proper hover states.
    """
    import tkinter as tk
    accent = accent or _THEME["accent"]
    palette = {
        "accent":  (accent, _accent_text(accent), _THEME["accent_hi"]),
        "success": (_THEME["success"], _accent_text(_THEME["success"]),
                    _THEME["success_hi"]),
        "danger":  (_THEME["danger"], _accent_text(_THEME["danger"]),
                    _THEME["danger_hi"]),
        "ghost":   (_THEME["surface"], _THEME["text"], _THEME["field"]),
    }
    bg, fg, hover = palette.get(kind, palette["accent"])
    btn = tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
        relief="flat", bd=0, cursor="hand2",
        font=(_FONT, 10, "bold") if kind != "ghost" else _FONT_BODY,
        padx=18, pady=10, highlightthickness=0,
    )
    btn._bg = bg
    btn.bind("<Enter>", lambda e: btn["state"] == "normal" and btn.config(bg=hover))
    btn.bind("<Leave>", lambda e: btn["state"] == "normal" and btn.config(bg=bg))

    def _set_enabled(enabled):
        if enabled:
            btn.config(state="normal", bg=bg, fg=fg, cursor="hand2")
        else:
            btn.config(state="disabled", bg=_THEME["accent_lo"],
                       fg=_THEME["muted"], cursor="arrow")
    btn.set_enabled = _set_enabled
    return btn


class PasswordDialog:
    """
    Collect a password (with confirmation + strength meter for first-time locks).
    Returns the entered password, or None if cancelled.
    """

    _VERBS = {
        "Lock":         ("🔒", _THEME["accent"]),
        "Unlock":       ("🔓", _THEME["success"]),
        "Fully Unlock": ("🔓", _THEME["warning"]),
    }

    def __init__(self, folder_name: str, confirm: bool, verb: str = "Lock"):
        icon, accent = self._VERBS.get(verb, ("🔒", _THEME["accent"]))
        h = 390 if confirm else 270
        self.tk, self.ttk, self.root, _ = _make_root(f"{verb} Folder", 460, h, accent)
        tk, ttk = self.tk, self.ttk
        self.result: Optional[str] = None
        self._confirm = confirm
        self._show = False
        self._accent = accent

        _header(self.root, ttk, icon, f"{verb} Folder",
                f"Folder:  {folder_name}", accent)

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=22, pady=(16, 18))

        ttk.Label(body, text="Password", style="H2.TLabel").pack(anchor="w")
        row = ttk.Frame(body, style="TFrame")
        row.pack(fill="x", pady=(4, 0))
        self.pw = ttk.Entry(row, show="●", font=(_FONT, 11))
        self.pw.pack(side="left", fill="x", expand=True)
        self.eye = _button(row, "👁  Show", self._toggle, kind="ghost")
        self.eye.pack(side="left", padx=(8, 0))
        self.pw.focus_set()

        if confirm:
            ttk.Label(body, text="Confirm password", style="H2.TLabel").pack(
                anchor="w", pady=(12, 0))
            self.pw2 = ttk.Entry(body, show="●", font=(_FONT, 11))
            self.pw2.pack(fill="x", pady=(4, 0))

            meter = ttk.Frame(body, style="TFrame")
            meter.pack(fill="x", pady=(12, 0))
            self.canvas = tk.Canvas(meter, height=8, highlightthickness=0,
                                    bg=_THEME["bg"], width=300)
            self.canvas.pack(fill="x")
            self.strength = ttk.Label(body, text="", style="Muted.TLabel")
            self.strength.pack(anchor="w", pady=(4, 0))
            self.pw.bind("<KeyRelease>", self._update_strength)
            self._draw_meter(0, "")

        self.msg = ttk.Label(body, text="", foreground=_THEME["danger"],
                             background=_THEME["bg"], font=_FONT_SM,
                             wraplength=390)
        self.msg.pack(anchor="w", pady=(10, 0))

        btns = ttk.Frame(body, style="TFrame")
        btns.pack(fill="x", side="bottom", pady=(14, 0))
        _button(btns, f"{verb}", self._submit, kind="accent",
                accent=accent).pack(side="right")
        _button(btns, "Cancel", self._cancel, kind="ghost").pack(
            side="right", padx=(0, 8))

        self.root.bind("<Return>", lambda e: self._submit())
        self.root.bind("<Escape>", lambda e: self._cancel())
        self.root.protocol("WM_DELETE_WINDOW", self._cancel)

    def _draw_meter(self, score: int, label: str):
        c = self.canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 300
        seg = (w - 16) / 5
        colours = {0: _THEME["border"], 1: _THEME["danger"], 2: "#e67e22",
                   3: _THEME["warning"], 4: _THEME["success"], 5: _THEME["success"]}
        for i in range(5):
            fill = colours.get(score, _THEME["border"]) if i < score else _THEME["border"]
            x0 = i * (seg + 4)
            c.create_rectangle(x0, 0, x0 + seg, 8, fill=fill, outline="")

    def _toggle(self):
        self._show = not self._show
        ch = "" if self._show else "●"
        self.eye.config(text="🙈  Hide" if self._show else "👁  Show")
        self.pw.config(show=ch)
        if self._confirm:
            self.pw2.config(show=ch)

    def _update_strength(self, _evt=None):
        score, label = password_strength(self.pw.get())
        self._draw_meter(score, label)
        self.strength.config(text=f"Strength: {label}" if label else "")

    def _submit(self):
        pw = self.pw.get()
        if self._confirm:
            if pw != self.pw2.get():
                self.msg.config(text="Passwords do not match.")
                return
            errs = password_errors(pw)
            if errs:
                self.msg.config(text="Password needs " + ", ".join(errs) + ".")
                return
        elif not pw:
            self.msg.config(text="Password is required.")
            return
        self.result = pw
        self.root.destroy()

    def _cancel(self):
        self.result = None
        self.root.destroy()

    def _run(self):
        _run_modal(self.root)

    @classmethod
    def ask(cls, folder_name: str, confirm: bool, verb: str = "Lock") -> Optional[str]:
        dlg = cls(folder_name, confirm, verb)
        dlg._run()
        return dlg.result


class RecoverDialog:
    """
    Collect a recovery code and a new password to reset a vault's password.
    Returns (recovery_code, new_password) or None if cancelled.
    """

    def __init__(self, folder_name: str):
        accent = _THEME["warning"]
        self.tk, self.ttk, self.root, _ = _make_root(
            "Reset Password", 460, 430, accent)
        ttk = self.ttk
        self.result = None
        self._show = False

        _header(self.root, ttk, "🔑", "Reset Password",
                f"Folder:  {folder_name}", accent)

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=22, pady=(14, 18))

        ttk.Label(body, text="Recovery key", style="H2.TLabel").pack(anchor="w")
        self.code = ttk.Entry(body, font=("Consolas", 11))
        self.code.pack(fill="x", pady=(4, 0))
        self.code.focus_set()

        ttk.Label(body, text="New password", style="H2.TLabel").pack(
            anchor="w", pady=(12, 0))
        row = ttk.Frame(body, style="TFrame")
        row.pack(fill="x", pady=(4, 0))
        self.pw = ttk.Entry(row, show="●", font=(_FONT, 11))
        self.pw.pack(side="left", fill="x", expand=True)
        self.eye = _button(row, "👁  Show", self._toggle, kind="ghost")
        self.eye.pack(side="left", padx=(8, 0))

        ttk.Label(body, text="Confirm new password", style="H2.TLabel").pack(
            anchor="w", pady=(12, 0))
        self.pw2 = ttk.Entry(body, show="●", font=(_FONT, 11))
        self.pw2.pack(fill="x", pady=(4, 0))

        self.msg = ttk.Label(body, text="", foreground=_THEME["danger"],
                             background=_THEME["bg"], font=_FONT_SM, wraplength=400)
        self.msg.pack(anchor="w", pady=(10, 0))

        btns = ttk.Frame(body, style="TFrame")
        btns.pack(fill="x", side="bottom", pady=(14, 0))
        _button(btns, "Reset", self._submit, kind="accent",
                accent=accent).pack(side="right")
        _button(btns, "Cancel", self._cancel, kind="ghost").pack(
            side="right", padx=(0, 8))

        self.root.bind("<Return>", lambda e: self._submit())
        self.root.bind("<Escape>", lambda e: self._cancel())
        self.root.protocol("WM_DELETE_WINDOW", self._cancel)

    def _toggle(self):
        self._show = not self._show
        ch = "" if self._show else "●"
        self.eye.config(text="🙈  Hide" if self._show else "👁  Show")
        self.pw.config(show=ch)
        self.pw2.config(show=ch)

    def _submit(self):
        code = self.code.get().strip()
        pw = self.pw.get()
        if not code:
            self.msg.config(text="Enter your recovery key.")
            return
        if pw != self.pw2.get():
            self.msg.config(text="Passwords do not match.")
            return
        errs = password_errors(pw)
        if errs:
            self.msg.config(text="Password needs " + ", ".join(errs) + ".")
            return
        self.result = (code, pw)
        self.root.destroy()

    def _cancel(self):
        self.result = None
        self.root.destroy()

    def _run(self):
        _run_modal(self.root)

    @classmethod
    def ask(cls, folder_name: str):
        dlg = cls(folder_name)
        dlg._run()
        return dlg.result


class RecoveryDialog:
    """
    Display the one-time recovery code.  Close is disabled until the user ticks
    an acknowledgment checkbox confirming they saved it.
    """

    def __init__(self, code: str):
        self.tk, self.ttk, self.root, _ = _make_root(
            "Save Your Recovery Key", 520, 430, _THEME["warning"])
        tk, ttk = self.tk, self.ttk
        self._code = code

        _header(self.root, ttk, "⚠", "Save Your Recovery Key",
                "Shown once — store it somewhere safe", _THEME["warning"])

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=18)

        ttk.Label(
            body, wraplength=460, justify="left", style="TLabel",
            text=("If you forget your password AND lose this key, your data "
                  "cannot be recovered by anyone — including you."),
        ).pack(anchor="w")

        # Code card
        card = tk.Frame(body, bg=_THEME["field"], highlightbackground=_THEME["warning"],
                        highlightthickness=1)
        card.pack(fill="x", pady=14)
        self.code_lbl = tk.Label(card, text=code, bg=_THEME["field"],
                                 fg=_THEME["warning"], font=("Consolas", 14, "bold"),
                                 wraplength=440, justify="center", pady=18)
        self.code_lbl.pack(fill="x")

        self.copy_btn = _button(body, "📋  Copy to clipboard", self._copy,
                                kind="ghost")
        self.copy_btn.pack()
        ttk.Label(body, text="Windows clipboard history (Win+V) may retain copied text.",
                  style="Muted.TLabel").pack(anchor="center", pady=(2, 0))

        self.ack = tk.BooleanVar(value=False)
        ttk.Checkbutton(body, text="I have saved this key somewhere safe",
                        variable=self.ack,
                        command=self._toggle_close).pack(anchor="w", pady=(14, 10))

        self.close_btn = _button(body, "Close", self.root.destroy,
                                 kind="accent", accent=_THEME["warning"])
        self.close_btn.set_enabled(False)
        self.close_btn.pack(fill="x")

        self.root.protocol("WM_DELETE_WINDOW", self._block_close)

    def _copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._code)
        self.copy_btn.config(text="✓  Copied")

    def _toggle_close(self):
        self.close_btn.set_enabled(bool(self.ack.get()))

    def _block_close(self):
        if self.ack.get():
            self.root.destroy()

    def _run(self):
        _run_modal(self.root)

    @classmethod
    def show(cls, code: str) -> None:
        cls(code)._run()


class MessageDialog:
    """Modal error / info / question dialog.  question kind returns a bool."""

    _KINDS = {
        "error":    ("✕", _THEME["danger"]),
        "info":     ("ℹ", _THEME["accent"]),
        "success":  ("✓", _THEME["success"]),
        "question": ("?", _THEME["accent"]),
    }

    def __init__(self, kind: str, title: str, text: str):
        icon, accent = self._KINDS.get(kind, ("ℹ", _THEME["accent"]))
        self.tk, self.ttk, self.root, _ = _make_root(title, 440, 230, accent)
        ttk = self.ttk
        self.answer = False

        _header(self.root, ttk, icon, title, "", accent)

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=20)
        ttk.Label(body, text=text, wraplength=390, justify="left",
                  style="TLabel").pack(anchor="w")

        btns = ttk.Frame(body, style="TFrame")
        btns.pack(fill="x", side="bottom", pady=(16, 0))
        if kind == "question":
            _button(btns, "Yes", self._yes, kind="accent",
                    accent=accent).pack(side="right")
            _button(btns, "No", self._no, kind="ghost").pack(
                side="right", padx=(0, 8))
            self.root.bind("<Return>", lambda e: self._yes())
        else:
            _button(btns, "OK", self.root.destroy, kind="accent",
                    accent=accent).pack(side="right")
            self.root.bind("<Return>", lambda e: self.root.destroy())
        self.root.bind("<Escape>", lambda e: self._no()
                       if kind == "question" else self.root.destroy())

    def _yes(self):
        self.answer = True
        self.root.destroy()

    def _no(self):
        self.answer = False
        self.root.destroy()

    def _run(self):
        _run_modal(self.root)

    @classmethod
    def error(cls, text: str, title: str = "FolderLocker") -> None:
        cls("error", title, text)._run()

    @classmethod
    def info(cls, text: str, title: str = "FolderLocker") -> None:
        cls("info", title, text)._run()

    @classmethod
    def success(cls, text: str, title: str = "FolderLocker") -> None:
        cls("success", title, text)._run()

    @classmethod
    def ask_yes_no(cls, text: str, title: str = "FolderLocker") -> bool:
        dlg = cls("question", title, text)
        dlg._run()
        return dlg.answer


class BusyDialog:
    """
    Small animated "working…" window shown while a blocking, non-UI step runs
    on a background thread (key derivation, ACL/attribute changes, folder
    renames, deletes).  An indeterminate progress bar keeps the user informed
    so the app never looks frozen, and Windows never marks it "Not Responding".

    Use via run_blocking() on the GuiUx — do not touch Tk from the worker
    thread; only the main thread pumps this window.
    """

    def __init__(self, label: str, accent: str = None):
        accent = accent or _THEME["accent"]
        self.tk, self.ttk, self.root, _ = _make_root("FolderLocker", 380, 150, accent)
        ttk = self.ttk
        _header(self.root, ttk, "⏳", label, "", accent)

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=20)
        self.pbar = ttk.Progressbar(body, mode="indeterminate",
                                    style="Accent.Horizontal.TProgressbar")
        self.pbar.pack(fill="x", pady=(4, 10))
        self.stat = ttk.Label(body, text="Please wait…", style="Muted.TLabel")
        self.stat.pack(anchor="w")

        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # block manual close
        try:
            self.pbar.start(12)
        except Exception:
            pass
        try:
            self.root.transient(_ACTIVE_PARENT if _ACTIVE_PARENT else None)
            self.root.lift()
            self.root.update_idletasks()
            self.root.update()
        except Exception:
            pass

    def pump(self) -> None:
        try:
            self.root.update_idletasks()
            self.root.update()
        except Exception:
            pass

    def finish(self) -> None:
        try:
            self.pbar.stop()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass


class ProgressDialog:
    """
    GUI progress window matching the _Bar interface (.tick/.file_done/.finish).

    The encrypt/decrypt loop calls .tick(nbytes) from worker threads; those
    threads only mutate counters under a lock.  The Tk widgets are updated from
    the main thread via .pump(), which _process_files calls between chunks.
    """

    def __init__(self, total_files: int, total_bytes: int,
                 label: str, colour: str):
        accent = _THEME["accent"] if label.startswith("Encrypt") else _THEME["success"]
        self.tk, self.ttk, self.root, _ = _make_root("FolderLocker", 440, 200, accent)
        ttk = self.ttk
        self.total_files = total_files
        self.total_bytes = max(total_bytes, 1)
        self._fdone = 0
        self._bdone = 0
        self._lock = threading.Lock()
        self._start = time.monotonic()

        icon = "🔒" if label.startswith("Encrypt") else "🔓"
        _header(self.root, ttk, icon, label + "…", "", accent)

        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=20)
        self.pbar = ttk.Progressbar(body, maximum=100, mode="determinate",
                                    style="Accent.Horizontal.TProgressbar")
        self.pbar.pack(fill="x", pady=(4, 12))
        self.stat = ttk.Label(body, text="Starting…", style="Muted.TLabel")
        self.stat.pack(anchor="w")
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # block manual close
        self.root.update_idletasks()
        self.root.update()

    def tick(self, nbytes: int) -> None:
        with self._lock:
            self._bdone += nbytes

    def file_done(self) -> None:
        with self._lock:
            self._fdone += 1

    def pump(self) -> None:
        """Called from the main thread between chunks to refresh the UI."""
        with self._lock:
            bdone, fdone = self._bdone, self._fdone
        pct = min(100, bdone / self.total_bytes * 100)
        elapsed = max(time.monotonic() - self._start, 0.01)
        spd = bdone / elapsed / 1_048_576
        self.pbar["value"] = pct
        self.stat.config(
            text=f"{int(pct)}%    ·    {fdone}/{self.total_files} files    "
                 f"·    {spd:.0f} MB/s")
        try:
            self.root.update_idletasks()
            self.root.update()
        except Exception:
            pass

    def finish(self) -> None:
        with self._lock:
            self._bdone = self.total_bytes
            self._fdone = self.total_files
        try:
            self.pbar["value"] = 100
            self.stat.config(text="Done.")
            self.root.update_idletasks()
            self.root.update()
            self.root.after(250, self.root.destroy)
            self.root.update()
            self.root.destroy()
        except Exception:
            pass


class GuiUx(UxContext):
    """tkinter front-end used when launched from the right-click menu (--gui)."""

    is_gui = True

    def __init__(self):
        self._verb = "Lock"

    def get_password(self, folder_name: str, confirm: bool) -> Optional[str]:
        return PasswordDialog.ask(folder_name, confirm, self._verb)

    def show_recovery(self, code: str) -> None:
        RecoveryDialog.show(code)

    def make_progress(self, total_files, total_bytes, label, colour):
        return ProgressDialog(total_files, total_bytes, label, colour)

    def run_blocking(self, label: str, fn, *args, **kwargs):
        """
        Run fn(*args, **kwargs) on a worker thread while keeping the GUI alive.

        The heavy steps in lock/unlock — Argon2id key derivation and the
        recursive icacls/attrib/takeown ACL changes — can take several seconds
        and used to run on the Tk main thread, freezing the window (Windows
        showed "Not Responding") with no feedback after a click.  Here the main
        thread shows an animated BusyDialog and pumps Tk events while the work
        happens off-thread.
        """
        busy = BusyDialog(label)
        result = {}

        def _target():
            try:
                result["value"] = fn(*args, **kwargs)
            except BaseException as exc:   # re-raised on the main thread below
                result["error"] = exc

        worker = threading.Thread(target=_target, daemon=True)
        worker.start()
        try:
            while worker.is_alive():
                busy.pump()
                time.sleep(0.03)
            busy.pump()
        finally:
            busy.finish()

        if "error" in result:
            raise result["error"]
        return result.get("value")

    def error(self, msg: str) -> NoReturn:
        MessageDialog.error(msg)
        raise AbortAction(msg)

    def success(self, title: str, lines: list[str]) -> None:
        body = "\n".join(lines) if lines else ""
        MessageDialog.success(f"{title}\n\n{body}".strip())

    def info(self, msg: str) -> None:
        # Progress messages are shown via the ProgressDialog; nothing to do here.
        pass

    def confirm(self, title: str, message: str) -> bool:
        return MessageDialog.ask_yes_no(message, title)


# ── lock ──────────────────────────────────────────────────────────────────────

def cmd_lock(folder: str, password: str, ux: UxContext, *, hide: bool) -> None:
    target = Path(folder).resolve()
    state  = load_state()
    key_v, vault = find_vault(state, target)

    # ── Re-lock an already-registered vault ──
    if vault is not None:
        if vault["status"] == "locked":
            ux.error(f"'{Path(vault['original_path']).name}' is already locked.")
        orig = Path(vault["original_path"])
        locked = Path(vault["locked_path"])
        was_hidden = _vault_hidden(vault)
        uk = vault.get("unlock_key")
        if not uk:
            ux.error("Re-lock failed: master key missing from state.")
        ux.info(f"Re-locking '{orig.name}'...")
        encrypt_folder(orig, bytes.fromhex(uk), progress_factory=ux.progress_factory())

        def _relock_fs():
            if was_hidden:
                if locked.exists() and locked != orig:
                    # Leftover from an interrupted previous re-lock — remove it
                    # so rename succeeds (Windows does not allow rename-over-dir).
                    shutil.rmtree(locked, ignore_errors=True)
                if orig != locked:
                    orig.rename(locked)
                apply_lock_fs(locked)
            else:
                apply_lock_fs_visible(locked)

        ux.run_blocking("Locking…", _relock_fs)
        vault["status"] = "locked"
        vault["unlock_key"] = None
        save_state(state)
        ensure_daemon()
        ux.success(f"'{orig.name}' is locked and encrypted.", [])
        return

    # ── First-time lock ──
    if not target.exists() or not target.is_dir():
        ux.error(f"Folder not found: {target}")
    if target.name.startswith(LOCK_PREFIX):
        ux.error("Folder is already a vault (name starts with '.~vlt_').")

    # Warn if the folder lives inside a cloud-sync location.
    provider = _cloud_sync_warning(target)
    if provider:
        proceed = ux.confirm(
            f"This folder is inside {provider}",
            f"'{target.name}' looks like it is synced by {provider}.\n\n"
            f"Locking it will upload the ENCRYPTED files to {provider}, which can:\n"
            f"  • cause sync conflicts,\n"
            f"  • fill your cloud version history with encrypted data,\n"
            f"  • leave a plaintext copy in {provider}'s version history or trash.\n\n"
            f"Pause syncing first, or move the folder out of {provider}.\n\n"
            f"Lock it anyway?",
        )
        if not proceed:
            raise AbortAction("cancelled — cloud-synced folder")

    if not password:
        password = ux.get_password(target.name, confirm=True)
        if password is None:
            raise AbortAction("cancelled")
    if not password:
        ux.error("Password required.")

    errs = password_errors(password)
    if errs:
        ux.error(f"Password too weak — missing {', '.join(errs)}.\n\n{_POLICY}")

    if hide:
        locked_path = target.parent / (LOCK_PREFIX + target.name)
        if locked_path.exists():
            ux.error(f"A vault already exists at: {locked_path}")
    else:
        locked_path = target   # visible lock — no rename

    ux.info("Generating master key and wrapping keys (Argon2id)...")
    master_key  = os.urandom(32)    # encrypts files — never changes
    pw_salt     = os.urandom(32)
    rec_salt    = os.urandom(32)
    rec_code    = gen_recovery_code()

    def _wrap_keys():
        pw_key      = derive_key(password, pw_salt)
        rec_key     = derive_rec_key(rec_code, rec_salt)
        return wrap_key(master_key, pw_key), wrap_key(master_key, rec_key)

    # Argon2id derivation is CPU-heavy — run it off the UI thread.
    wrapped_pw, wrapped_rec = ux.run_blocking(
        "Preparing encryption keys…", _wrap_keys)

    ux.info(f"Encrypting '{target.name}'...")
    encrypt_folder(target, master_key, progress_factory=ux.progress_factory())

    if hide:
        ux.info("Locking and hiding...")
        ux.run_blocking("Locking and hiding…", _lock_and_hide_fs,
                        target, locked_path)
    else:
        ux.info("Locking...")
        ux.run_blocking("Locking…", apply_lock_fs_visible, locked_path)

    state["vaults"][str(target)] = {
        "version":       VAULT_VER,
        "original_path": str(target),
        "locked_path":   str(locked_path),
        "hidden":        hide,
        "pw_salt":       pw_salt.hex(),
        "wrapped_pw":    wrapped_pw.hex(),
        "rec_salt":      rec_salt.hex(),
        "wrapped_rec":   wrapped_rec.hex(),
        "status":        "locked",
        "unlock_key":    None,
    }
    save_state(state)
    ensure_daemon()

    if hide:
        summary = [
            f"Vault      : {locked_path}",
            "Encryption : AES-256-GCM (streaming 4 MB chunks) | Argon2id key wrapping",
            f"Unlock     : right-click → Locker → Unlock, or 'locker unlock \"{target}\"'",
        ]
        ux.success(f"'{target.name}' is encrypted, locked, and hidden.", summary)
    else:
        summary = [
            f"Folder     : {locked_path}  (still visible, access denied)",
            "Encryption : AES-256-GCM (streaming 4 MB chunks) | Argon2id key wrapping",
            f"Unlock     : right-click → Locker → Unlock, or 'locker unlock \"{target}\"'",
        ]
        ux.success(f"'{target.name}' is encrypted and locked (visible).", summary)
    ux.show_recovery(rec_code)

# ── unlock ────────────────────────────────────────────────────────────────────

def cmd_unlock(folder: str, password: str, ux: UxContext) -> None:
    target = Path(folder).resolve()
    state  = load_state()
    key_v, vault = find_vault(state, target)

    if vault is None:
        ux.error(f"No vault registered for: {target}\n  Lock it first with Locker → Lock.")
    if vault["status"] == "unlocked":
        ux.error(f"'{Path(vault['original_path']).name}' is already unlocked.")

    orig   = Path(vault["original_path"])
    locked = Path(vault["locked_path"])
    was_hidden = _vault_hidden(vault)

    if not password:
        password = ux.get_password(orig.name, confirm=False)
        if password is None:
            raise AbortAction("cancelled")

    # Argon2id derivation is CPU-heavy; run it off the UI thread with a busy
    # indicator so the window stays responsive (no "Not Responding").
    try:
        master_key = ux.run_blocking(
            "Verifying password…", _derive_master_key, vault, password)
    except BadPassword:
        ux.error("Incorrect password.")

    if not locked.exists():
        ux.error(f"Locked folder not found: {locked}")
    if was_hidden and orig.exists() and orig != locked:
        ux.error(f"Cannot restore: '{orig.name}' already exists at that location.")

    # Restoring access runs a recursive icacls/attrib pass that can take a few
    # seconds on large trees — also off the UI thread.
    def _restore():
        apply_unlock_fs(locked)
        if was_hidden and locked != orig:
            locked.rename(orig)

    ux.run_blocking("Restoring access…", _restore)

    # Save state as "unlocked" BEFORE decryption starts so that if we
    # crash midway, the daemon (or next startup) knows the vault is
    # unlocked and the master key is available for a clean re-lock.
    vault["status"]     = "unlocked"
    vault["unlock_key"] = master_key.hex()
    save_state(state)

    ux.info(f"Decrypting '{orig.name}'...")
    decrypt_folder(orig, master_key, progress_factory=ux.progress_factory())

    ensure_daemon()

    ux.success(f"'{orig.name}' is decrypted and accessible.", [
        f"Path        : {orig}",
        "Auto-relocks: on screen lock, shutdown, restart, or logoff",
    ])

# ── unlock-f ──────────────────────────────────────────────────────────────────

def cmd_unlock_f(folder: str, password: str, ux: UxContext) -> None:
    """Permanently unlock: decrypt, restore, remove from vault registry."""
    target = Path(folder).resolve()
    state  = load_state()
    key_v, vault = find_vault(state, target)

    if vault is None:
        ux.error(f"No vault registered for: {target}")

    orig   = Path(vault["original_path"])
    locked = Path(vault["locked_path"])
    was_hidden = _vault_hidden(vault)

    if not password:
        password = ux.get_password(orig.name, confirm=False)
        if password is None:
            raise AbortAction("cancelled")

    # Argon2id derivation off the UI thread (keeps the window responsive).
    try:
        master_key = ux.run_blocking(
            "Verifying password…", _derive_master_key, vault, password)
    except BadPassword:
        ux.error("Incorrect password.")

    if locked.exists():
        cur = locked
        needs_rename = was_hidden and locked != orig
    elif orig.exists():
        cur = orig
        needs_rename = False
    else:
        ux.error(f"Folder not found at:\n  {locked}\n  {orig}")

    uk = vault.get("unlock_key")
    if uk:
        master_key = bytes.fromhex(uk)   # use cached key

    ux.info("Restoring filesystem access...")
    def _restore_f():
        icacls_restore(cur)
        attrib_show(cur)
    ux.run_blocking("Restoring access…", _restore_f)

    if needs_rename:
        if orig.exists():
            ux.error(f"Cannot restore: '{orig.name}' already exists.")
        cur.rename(orig)
        cur = orig

    if vault["status"] == "locked":
        ux.info(f"Decrypting '{orig.name}'...")
        decrypt_folder(cur, master_key, progress_factory=ux.progress_factory())

    try:
        del state["vaults"][key_v]
        save_state(state)
    except Exception:
        ux.success(f"'{orig.name}' fully unlocked.",
                   ["Warning: the registry record could not be removed."])
        return

    ux.success(f"'{orig.name}' fully unlocked — removed from vault registry.", [
        f"Path  : {orig}",
        "Status: Normal folder — no encryption, no auto-relock",
    ])

# ── forget (destructive: delete an unrecoverable vault) ───────────────────────

def _force_delete_dir(p: Path) -> None:
    """
    Remove a locked vault directory even though a deny ACL blocks access.
    Takes ownership, resets the ACL, clears hidden/system attributes, then
    deletes the tree.  Raises on failure so the caller can report it.
    """
    if not p.exists():
        return
    # 1. Take ownership (needed before we can change the ACL back).
    _run(["takeown", "/f", str(p), "/r", "/d", "y"])
    # 2. Remove the deny ACE and reset to inheritable defaults.
    _run(["icacls", str(p), "/remove:d", "Everyone", "/T", "/C", "/Q"])
    _run(["icacls", str(p), "/reset", "/T", "/C", "/Q"])
    # 3. Clear hidden/system so the tree is fully accessible.
    try:
        attrib_show(p)
    except Exception:
        pass
    # 4. Delete.  shutil first; fall back to rmdir /s /q for stubborn trees.
    shutil.rmtree(p, ignore_errors=True)
    if p.exists():
        _run(["cmd", "/c", "rmdir", "/s", "/q", str(p)])
    if p.exists():
        raise OSError(f"Could not delete {p}")


def cmd_forget(folder: str, ux: UxContext, *, delete_files: bool) -> None:
    """
    Remove a vault from the registry.  If delete_files is True, also permanently
    delete the (encrypted) folder from disk — used when the password AND recovery
    key are lost and the data is unrecoverable.  DESTRUCTIVE and irreversible.
    """
    target = Path(folder).resolve()
    state  = load_state()
    key_v, vault = find_vault(state, target)
    if vault is None:
        ux.error(f"No vault registered for: {target}")

    orig   = Path(vault["original_path"])
    locked = Path(vault["locked_path"])
    name   = orig.name

    if delete_files:
        # The folder may be at either path depending on hidden/visible + status.
        cur = locked if locked.exists() else (orig if orig.exists() else None)
        if cur is not None:
            ux.info(f"Permanently deleting '{name}'...")
            try:
                # takeown + recursive icacls + rmtree can take a while — run it
                # off the UI thread so the window stays responsive.
                ux.run_blocking(f"Deleting '{name}'…", _force_delete_dir, cur)
            except Exception as exc:
                ux.error(f"Could not delete the folder:\n  {cur}\n\n{exc}\n\n"
                         f"The registry entry was left intact.")
        # else: nothing on disk — just clean up the registry entry below.

    try:
        del state["vaults"][key_v]
        save_state(state)
    except Exception as exc:
        ux.error(f"Folder handled, but the registry entry could not be removed:\n  {exc}")

    if delete_files:
        ux.success(f"'{name}' permanently deleted and removed from FolderLocker.", [
            "The encrypted folder and its registry entry are both gone.",
        ])
    else:
        ux.success(f"'{name}' removed from FolderLocker.", [
            "The registry entry was removed. The folder on disk was left as-is.",
        ])

# ── recover ───────────────────────────────────────────────────────────────────

def cmd_recover(folder: str, code: str, new_pw: str, ux: UxContext) -> None:
    """
    Reset the vault password using the recovery code.

    Envelope encryption means this is O(1) regardless of vault size:
      1. Unwrap master_key using recovery key.
      2. Re-wrap master_key with new password key.
      3. Generate a new recovery code.
      4. Save updated vault metadata.
      ← Zero files are touched.
    """
    target = Path(folder).resolve()
    state  = load_state()
    key_v, vault = find_vault(state, target)

    if vault is None:
        ux.error(f"No vault registered for: {target}")

    if not _is_v2(vault):
        ux.error(
            "This vault was created with an older version of locker (v1).\n"
            "Recovery is not available for v1 vaults.\n"
            "Use Fully Unlock with your current password to access your files,\n"
            "then Lock again to create a v2 vault with recovery support."
        )

    if "wrapped_rec" not in vault:
        ux.error("No recovery key found in this vault.")

    ux.info("Verifying recovery code...")
    rec_key = derive_rec_key(code, bytes.fromhex(vault["rec_salt"]))
    try:
        master_key = unwrap_key(bytes.fromhex(vault["wrapped_rec"]), rec_key)
    except ValueError:
        ux.error("Incorrect recovery code.")

    errs = password_errors(new_pw)
    if errs:
        ux.error(f"Password too weak — missing {', '.join(errs)}.\n\n{_POLICY}")

    ux.info("Generating new password key (Argon2id)...")
    new_pw_salt    = os.urandom(32)
    new_rec_salt   = os.urandom(32)
    new_rec_code   = gen_recovery_code()

    def _rewrap():
        new_pw_key      = derive_key(new_pw, new_pw_salt)
        new_rec_key     = derive_rec_key(new_rec_code, new_rec_salt)
        return (wrap_key(master_key, new_pw_key),
                wrap_key(master_key, new_rec_key))

    # Argon2id derivation off the UI thread.
    new_wrapped_pw, new_wrapped_rec = ux.run_blocking(
        "Updating password…", _rewrap)

    vault["pw_salt"]     = new_pw_salt.hex()
    vault["wrapped_pw"]  = new_wrapped_pw.hex()
    vault["rec_salt"]    = new_rec_salt.hex()
    vault["wrapped_rec"] = new_wrapped_rec.hex()
    # master_key unchanged → unlock_key (if cached) still valid
    save_state(state)

    ux.success("Password reset successfully.", [])
    ux.show_recovery(new_rec_code)

# ── show ──────────────────────────────────────────────────────────────────────

def cmd_show() -> None:
    state  = load_state()
    vaults = state.get("vaults", {})
    if not vaults:
        print("\n  No vaults registered yet.\n"); return

    locked   = [(k, v) for k, v in vaults.items() if v.get("status") == "locked"]
    unlocked = [(k, v) for k, v in vaults.items() if v.get("status") == "unlocked"]
    total    = len(vaults)
    bar      = "─" * 54

    print(f"\n  {_CY}{bar}{_R}")
    print(f"  {_B}FolderLocker  —  {total} vault{'s' if total != 1 else ''} registered{_R}")
    print(f"  {_CY}{bar}{_R}")

    if locked:
        print(f"\n  {_RD}{_B}LOCKED & ENCRYPTED ({len(locked)}){_R}")
        for _, v in locked:
            name    = Path(v["original_path"]).name
            has_rec = "✓" if v.get("wrapped_rec") else f"{_YL}✗  (v1 — re-lock to enable){_R}"
            ver     = v.get("version", 1)
            vis     = f"{_YL}hidden{_R}" if _vault_hidden(v) else f"{_CY}visible{_R}"
            print(f"     {_RD}●{_R} {_B}{name}{_R}  {_D}v{ver}{_R}  [{vis}]")
            print(f"       {_CY}Location:{_R} {Path(v['original_path']).parent}")
            print(f"       {_CY}Vault   :{_R} {v['locked_path']}")
            print(f"       {_CY}Recovery:{_R} {has_rec}")

    if unlocked:
        print(f"\n  {_GR}{_B}UNLOCKED ({len(unlocked)}){_R}  "
              f"{_YL}— auto-relocks on screen lock / shutdown{_R}")
        for _, v in unlocked:
            name    = Path(v["original_path"]).name
            has_rec = "✓" if v.get("wrapped_rec") else f"{_YL}✗{_R}"
            ver     = v.get("version", 1)
            vis     = f"{_YL}hidden{_R}" if _vault_hidden(v) else f"{_CY}visible{_R}"
            print(f"     {_GR}●{_R} {_B}{name}{_R}  {_D}v{ver}{_R}  [{vis}]")
            print(f"       {_CY}Location:{_R} {Path(v['original_path']).parent}")
            print(f"       {_CY}Recovery:{_R} {has_rec}")

    print(f"\n  {_CY}{bar}{_R}\n")

# ── Daemon relock ─────────────────────────────────────────────────────────────

def _relock_all_unlocked() -> None:
    """
    Re-encrypt every unlocked vault. Called on session lock / shutdown.
    Safe to call multiple times in a row (e.g. WM_QUERYENDSESSION then
    WM_ENDSESSION): checks actual filesystem state before each step so
    no step is applied twice.
    """
    try:
        state = load_state(); changed = False
        for key_v, vault in state["vaults"].items():
            if vault.get("status") != "unlocked":
                continue
            orig   = Path(vault["original_path"])
            locked = Path(vault["locked_path"])
            uk     = vault.get("unlock_key")
            hidden = _vault_hidden(vault)
            logging.info("Auto-relocking: %s", orig.name)
            try:
                if hidden:
                    # Step 1: Encrypt files only if the folder is still at orig
                    # (not already renamed by a previous call this session).
                    if uk and orig.exists():
                        encrypt_folder(orig, bytes.fromhex(uk), silent=True)
                    # Step 2: Rename orig → locked (skip if already renamed).
                    if orig.exists() and not locked.exists():
                        orig.rename(locked)
                    # Step 3: Apply filesystem lock (hide + deny).
                    if locked.exists():
                        apply_lock_fs(locked)
                else:
                    # Visible vault: encrypt in place + deny, no rename/hide.
                    if uk and orig.exists():
                        encrypt_folder(orig, bytes.fromhex(uk), silent=True)
                    if orig.exists():
                        apply_lock_fs_visible(orig)

                vault["status"]     = "locked"
                vault["unlock_key"] = None
                changed = True
            except Exception as exc:
                logging.error("Failed to relock %s: %s", orig, exc)
        if changed:
            save_state(state)
    except Exception as exc:
        logging.error("_relock_all_unlocked: %s", exc)

# ── Daemon (session + shutdown monitor) ───────────────────────────────────────

def run_daemon() -> None:
    """
    Hidden background process (pythonw.exe).
    Listens for WTS_SESSION_LOCK, WM_QUERYENDSESSION, WM_ENDSESSION.
    Also relocks stale vaults on startup (handles forced power-off).
    """
    APP_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE), level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("Daemon started (PID %d)", os.getpid())
    PID_FILE.write_text(str(os.getpid()))
    _relock_all_unlocked()

    user32   = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    wtsapi32 = ctypes.windll.wtsapi32
    WNDPROCTYPE = ctypes.WINFUNCTYPE(ctypes.c_long, W.HWND, W.UINT, W.WPARAM, W.LPARAM)

    # Track whether we already relocked during WM_QUERYENDSESSION so
    # WM_ENDSESSION doesn't do redundant (but safe) work on shutdown.
    _relocked_for_shutdown = [False]

    def wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == WM_WTSSESSION_CHANGE and wparam == WTS_SESSION_LOCK:
            logging.info("WTS_SESSION_LOCK")
            _relocked_for_shutdown[0] = False   # reset for next unlock cycle
            _relock_all_unlocked()
        elif msg == WM_QUERYENDSESSION:
            logging.info("WM_QUERYENDSESSION")
            _relock_all_unlocked()
            _relocked_for_shutdown[0] = True
            return 1   # must return non-zero to allow shutdown to proceed
        elif msg == WM_ENDSESSION:
            if wparam:
                logging.info("WM_ENDSESSION")
                if not _relocked_for_shutdown[0]:
                    _relock_all_unlocked()   # safety net if QUERYENDSESSION was skipped
        elif msg == WM_DESTROY:
            user32.PostQuitMessage(0)
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    wnd_proc_ptr = WNDPROCTYPE(wnd_proc)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", W.UINT), ("lpfnWndProc", WNDPROCTYPE),
            ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
            ("hInstance", W.HANDLE), ("hIcon", W.HANDLE),
            ("hCursor", W.HANDLE), ("hbrBackground", W.HANDLE),
            ("lpszMenuName", W.LPCWSTR), ("lpszClassName", W.LPCWSTR),
        ]

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", W.HWND), ("message", W.UINT), ("wParam", W.WPARAM),
            ("lParam", W.LPARAM), ("time", W.DWORD), ("pt", ctypes.c_long * 2),
        ]

    CN = "FolderLockerDaemon"
    hi = kernel32.GetModuleHandleW(None)
    wc = WNDCLASSW()
    wc.lpfnWndProc = wnd_proc_ptr; wc.hInstance = hi; wc.lpszClassName = CN

    if not user32.RegisterClassW(ctypes.byref(wc)):
        logging.error("RegisterClassW failed: %d", kernel32.GetLastError()); return
    hwnd = user32.CreateWindowExW(0, CN, CN, 0, 0, 0, 0, 0, None, None, hi, None)
    if not hwnd:
        logging.error("CreateWindowExW failed: %d", kernel32.GetLastError()); return
    if not wtsapi32.WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION):
        logging.error("WTSRegisterSessionNotification failed")
    logging.info("Listening for session lock / shutdown events...")

    msg = MSG()
    while True:
        ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
        if ret == 0 or ret == -1:
            break
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))

    wtsapi32.WTSUnRegisterSessionNotification(hwnd)
    PID_FILE.unlink(missing_ok=True)
    logging.info("Daemon exited.")

# ══════════════════════════════════════════════════════════════════════════════
# PRECONDITIONS
# ══════════════════════════════════════════════════════════════════════════════

def check_preconditions(ux: UxContext, folder: Optional[str] = None) -> None:
    """
    Verify platform, dependencies, and (optionally) folder existence before an
    action runs.  Routes failures through ux.error so the GUI shows a modal.
    Dependencies are already imported at module load; this re-reports cleanly.
    """
    if not sys.platform.startswith("win"):
        ux.error("FolderLocker runs only on Windows.")

    missing = []
    for mod, pkg in (("cryptography", "cryptography"),
                     ("argon2", "argon2-cffi"),
                     ("psutil", "psutil")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        ux.error("Missing dependencies: " + ", ".join(missing) +
                 "\n\nInstall with:\n  pip install " + " ".join(missing))

    if folder is not None:
        p = Path(folder)
        if not p.exists() or not p.is_dir():
            ux.error(f"Folder not found:\n  {folder}")

# ══════════════════════════════════════════════════════════════════════════════
# SELF-INSTALL / UNINSTALL  (per-user, no admin — winreg under HKCU)
# ══════════════════════════════════════════════════════════════════════════════

def _menu_commands() -> dict[str, str]:
    """
    Build the four context-menu command strings.

    Each invokes the tool with the subcommand, --gui, and the clicked folder
    path ("%1") quoted so paths with spaces survive.

    When packaged the installed (windowed) exe at INSTALL_EXE is used — never
    sys.executable, which under Nuitka --onefile points at a temp folder that
    is deleted on exit.  From source we use pythonw.exe (windowless) so a menu
    click doesn't pop a console; falls back to python.exe if pythonw is missing.
    """
    if _is_packaged():
        prefix = f'"{INSTALL_EXE}"'
    else:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        runner = str(pythonw) if pythonw.exists() else sys.executable
        prefix = f'"{runner}" "{os.path.abspath(__file__)}"'
    return {
        "01lock":       f'{prefix} lock --gui "%1"',
        "02lockhide":   f'{prefix} lock-hide --gui "%1"',
        "03unlock":     f'{prefix} unlock --gui "%1"',
        "04fullunlock": f'{prefix} unlock-f --gui "%1"',
    }


_MENU_ITEMS = [
    ("01lock",       "Lock"),
    ("02lockhide",   "Lock && Hide"),   # && renders as a single & in the menu
    ("03unlock",     "Unlock"),
    ("04fullunlock", "Fully Unlock"),
]


def _reg_delete_tree(root, subkey: str) -> None:
    """Recursively delete a registry key and all its descendants (winreg)."""
    import winreg
    try:
        with winreg.OpenKey(root, subkey, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as k:
            while True:
                try:
                    child = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _reg_delete_tree(root, subkey + "\\" + child)
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        pass


def _first_run_gui() -> None:
    """
    First-run window shown when the (frozen) exe is double-clicked and the tool
    isn't installed yet.  Uses a real window + mainloop (the pattern proven to
    work reliably in the frozen exe), rather than a transient modal dialog which
    can flash-and-vanish as the very first window in a windowed exe.

    If the user clicks Install, runs the installer and shows the result.
    """
    tk, ttk, root, style = _make_root("FolderLocker", 460, 300)
    global _ACTIVE_PARENT
    _ACTIVE_PARENT = root

    _header(root, ttk, "🔒", "FolderLocker",
            "Lock folders with a password — from the right-click menu")

    body = ttk.Frame(root, style="TFrame")
    body.pack(fill="both", expand=True, padx=24, pady=(8, 20))

    ttk.Label(
        body, wraplength=400, justify="left", style="TLabel",
        text=("FolderLocker isn't installed yet.\n\n"
              "Installing adds a \"Locker\" submenu when you right-click any "
              "folder, plus a Manager in your Start Menu. No administrator "
              "rights are needed, and you can remove it anytime from "
              "Settings → Apps."),
    ).pack(anchor="w", pady=(4, 0))

    status = ttk.Label(body, text="", style="Muted.TLabel", wraplength=400)
    status.pack(anchor="w", pady=(10, 0))

    def do_it():
        status.config(text="Installing…")
        root.update_idletasks()
        try:
            do_install(GuiUx())
        except AbortAction:
            pass
        root.destroy()

    btns = ttk.Frame(body, style="TFrame")
    btns.pack(side="bottom", fill="x", pady=(16, 0))
    _button(btns, "Install", do_it, kind="accent").pack(side="right")
    _button(btns, "Not now", root.destroy, kind="ghost").pack(
        side="right", padx=(0, 8))

    parent = _get_root()
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Destroy>", lambda e: parent.quit() if e.widget is root else None)
    root.lift()
    root.attributes("-topmost", True)
    root.after(400, lambda: _win_alive(root) and root.attributes("-topmost", False))
    root.focus_force()
    parent.mainloop()


def _menu_installed() -> bool:
    import winreg
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_MENU_ROOT).Close()
        return True
    except FileNotFoundError:
        return False


def _create_shortcut(target_cmd: list[str]) -> bool:
    """
    Create the Start Menu 'FolderLocker Manager' shortcut via a PowerShell
    WScript.Shell one-liner (avoids a pywin32 dependency).  Best-effort.
    """
    def psq(s: str) -> str:
        # PowerShell single-quoted string: escape ' by doubling it.
        return str(s).replace("'", "''")

    try:
        START_MENU_DIR.mkdir(parents=True, exist_ok=True)
        exe = target_cmd[0]
        args = " ".join(f'"{a}"' if " " in str(a) else str(a)
                        for a in target_cmd[1:])
        ico = _icon_path()
        icon_line = f"$s.IconLocation = '{psq(ico)}'; " if ico else ""
        ps = (
            "$w = New-Object -ComObject WScript.Shell; "
            f"$s = $w.CreateShortcut('{psq(SHORTCUT_PATH)}'); "
            f"$s.TargetPath = '{psq(exe)}'; "
            f"$s.Arguments = '{psq(args)}'; "
            f"$s.WorkingDirectory = '{psq(INSTALL_DIR)}'; "
            f"$s.Description = 'Open the FolderLocker vault manager'; "
            f"{icon_line}"
            "$s.Save()"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=20,
            stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
            startupinfo=_no_window_startupinfo(),
        )
        return SHORTCUT_PATH.exists()
    except Exception:
        return False


def _register_uninstall(uninstall_cmd: str, display_icon: str = "") -> None:
    """
    Add a per-user entry to Windows 'Installed apps' (Settings → Apps) so the
    tool shows up with a working Uninstall button.  HKCU — no admin needed.
    """
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL) as k:
        winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, "FolderLocker")
        winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
        winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, "FolderLocker")
        winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, uninstall_cmd)
        winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, str(INSTALL_DIR))
        winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "EstimatedSize", 0, winreg.REG_DWORD, 12000)  # ~12 MB (KB)
        if display_icon:
            winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, display_icon)


def _unregister_uninstall() -> None:
    """Remove the 'Installed apps' entry, if present."""
    import winreg
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL)
    except FileNotFoundError:
        pass


def do_install(ux: UxContext) -> None:
    import winreg
    check_preconditions(ux)

    packaged = _is_packaged()

    # 1. Copy the executable to the stable install location (packaged only).
    #    Under Nuitka --onefile the running binary is the launcher exe exposed
    #    via _real_exe(); sys.executable points at a temp folder, so use the
    #    real path.
    if packaged:
        try:
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            src = Path(_real_exe()).resolve()
            if src != INSTALL_EXE.resolve():
                shutil.copy2(src, INSTALL_EXE)   # overwrite → update
        except Exception as exc:
            ux.error(f"Could not copy executable to {INSTALL_EXE}:\n  {exc}")
        manager_cmd = [str(INSTALL_EXE), "manage", "--gui"]
        # --gui so Settings' Uninstall runs through dialogs (it has no console,
        # so a console prompt would crash with "lost sys.stdin").
        uninstall_cmd = f'"{INSTALL_EXE}" --uninstall --gui'
        display_icon = str(INSTALL_EXE)
    else:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        runner = str(pythonw) if pythonw.exists() else sys.executable
        script = os.path.abspath(__file__)
        manager_cmd = [runner, script, "manage", "--gui"]
        # pythonw + --gui: Settings launches this with no console, so it must
        # use dialogs, not input().
        uninstall_cmd = f'"{runner}" "{script}" --uninstall --gui'
        display_icon = ""

    # 2. Write the cascading context-menu registry tree under HKCU.
    cmds = _menu_commands()
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_MENU_ROOT) as root:
            winreg.SetValueEx(root, "MUIVerb", 0, winreg.REG_SZ, REG_MENU_LABEL)
            winreg.SetValueEx(root, "ExtendedSubCommandsKey", 0, winreg.REG_SZ,
                              r"Directory\shell\Locker")
            icon = str(INSTALL_EXE) if packaged else ""
            if icon:
                winreg.SetValueEx(root, "Icon", 0, winreg.REG_SZ, icon)
        for key, label in _MENU_ITEMS:
            item_path = REG_MENU_ROOT + r"\shell" + "\\" + key
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, item_path) as ik:
                winreg.SetValueEx(ik, "MUIVerb", 0, winreg.REG_SZ, label)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  item_path + r"\command") as ck:
                winreg.SetValueEx(ck, None, 0, winreg.REG_SZ, cmds[key])
    except Exception as exc:
        ux.error(f"Failed to write registry entry under {REG_MENU_ROOT}:\n  {exc}")

    # 3. Register in Windows 'Installed apps' so Settings shows an Uninstall
    #    button (best-effort — not fatal if it fails).
    try:
        _register_uninstall(uninstall_cmd, display_icon)
    except Exception:
        pass

    # 4. Start Menu Manager shortcut (best-effort).
    shortcut_ok = _create_shortcut(manager_cmd)

    lines = [
        "Right-click any folder → Locker → Lock / Lock & Hide / Unlock / Fully Unlock.",
        "To remove it later: Settings → Apps → FolderLocker → Uninstall.",
    ]
    if packaged:
        lines.append(f"Installed to: {INSTALL_EXE}")
    if not shortcut_ok:
        lines.append("(Start Menu shortcut could not be created — use the menu instead.)")
    ux.success("FolderLocker installed.", lines)


def do_uninstall(ux: UxContext) -> None:
    import winreg

    had_menu = _menu_installed()
    had_shortcut = SHORTCUT_PATH.exists()
    had_copy = INSTALL_EXE.exists()
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL).Close()
        had_uninstall_entry = True
    except FileNotFoundError:
        had_uninstall_entry = False

    if not (had_menu or had_shortcut or had_copy or had_uninstall_entry):
        ux.success("Nothing to uninstall — FolderLocker was not installed.", [])
        return

    # Warn if any vaults are still locked — uninstalling does NOT decrypt them.
    # The encrypted folders and vaults.json are left in place, but the user
    # loses the right-click menu and Manager used to reach hidden vaults.
    locked = [r for r in _load_vault_rows() if r["status"] == "locked"]
    if locked:
        names = "\n".join(f"  • {r['name']}" + ("  (hidden)" if r["hidden"] else "")
                          for r in locked[:10])
        more = f"\n  …and {len(locked) - 10} more" if len(locked) > 10 else ""
        proceed = ux.confirm(
            "You still have locked folders",
            f"{len(locked)} folder(s) are still locked and encrypted:\n\n"
            f"{names}{more}\n\n"
            f"Uninstalling does NOT unlock them — they stay encrypted on disk, "
            f"and you'll lose the right-click menu and Manager used to open them. "
            f"Unlock anything you need first.\n\n"
            f"Uninstall anyway?",
        )
        if not proceed:
            ux.success("Uninstall cancelled — your folders are untouched.", [])
            return

    failures = []

    # 1. Remove the context-menu subtree.
    try:
        _reg_delete_tree(winreg.HKEY_CURRENT_USER, REG_MENU_ROOT)
    except Exception as exc:
        failures.append(f"registry ({REG_MENU_ROOT}): {exc}")

    # 2. Remove the 'Installed apps' uninstall entry.
    try:
        _unregister_uninstall()
    except Exception as exc:
        failures.append(f"uninstall entry: {exc}")

    # 3. Remove the Start Menu shortcut.
    if had_shortcut:
        try:
            SHORTCUT_PATH.unlink()
        except Exception as exc:
            failures.append(f"shortcut: {exc}")

    # 4. Remove the installed copy.  If it's the exe currently running, Windows
    #    won't let us delete it outright — schedule a best-effort delayed delete
    #    and fall back to telling the user.
    manual_note = None
    if had_copy:
        try:
            running_self = Path(_real_exe()).resolve() == INSTALL_EXE.resolve()
        except Exception:
            running_self = False
        deleted = False
        try:
            INSTALL_EXE.unlink()
            deleted = True
        except Exception:
            deleted = False
        if not deleted:
            if running_self:
                # Schedule deletion of the running exe after it exits via a
                # detached cmd that waits, then removes the install dir.
                try:
                    subprocess.Popen(
                        ["cmd", "/c", "ping 127.0.0.1 -n 3 >nul & "
                         f'rmdir /s /q "{INSTALL_DIR}"'],
                        creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NO_WINDOW,
                        close_fds=True,
                    )
                    deleted = True   # will be gone shortly after we exit
                except Exception:
                    manual_note = f"Delete the installed copy manually: {INSTALL_EXE}"
            else:
                failures.append(f"installed copy: could not delete {INSTALL_EXE}")

    if failures:
        ux.error("Uninstall completed with problems:\n  " + "\n  ".join(failures))

    lines = []
    if manual_note:
        lines.append(manual_note)
    ux.success("FolderLocker uninstalled.", lines)

# ══════════════════════════════════════════════════════════════════════════════
# MANAGER
# ══════════════════════════════════════════════════════════════════════════════

def _load_vault_rows() -> list[dict]:
    """Return readable vault records as rows, skipping corrupt entries."""
    rows = []
    try:
        state = load_state()
    except Exception:
        return rows
    for k, v in state.get("vaults", {}).items():
        try:
            rows.append({
                "key":    k,
                "name":   Path(v["original_path"]).name,
                "path":   v["original_path"],
                "status": v.get("status", "locked"),
                "hidden": _vault_hidden(v),
            })
        except Exception:
            continue   # corrupt entry — treat as absent
    return rows


def cmd_manage(ux: UxContext) -> None:
    rows = _load_vault_rows()
    if ux.is_gui:
        _manager_gui(rows, ux)
    else:
        _manager_cli(rows, ux)


def _manager_cli(rows: list[dict], ux: UxContext) -> None:
    if not rows:
        print("\n  No vaults registered yet.\n")
        return
    print(f"\n  {_B}FolderLocker — Vaults{_R}\n")
    for i, r in enumerate(rows, 1):
        vis = "hidden" if r["hidden"] else "visible"
        print(f"   {i:>2}. {r['name']}  [{r['status']}, {vis}]")
        print(f"       {r['path']}")
    print()
    try:
        sel = input("  Select a vault to unlock (number, blank to quit): ").strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not sel:
        return
    if not sel.isdigit() or not (1 <= int(sel) <= len(rows)):
        ux.error("Invalid selection.")
    row = rows[int(sel) - 1]
    if row["status"] == "unlocked":
        ux.error(f"'{row['name']}' is already unlocked.")
    cmd_unlock(row["path"], "", ux)


def _manager_gui(rows: list[dict], ux: UxContext) -> None:
    tk, ttk, root, style = _make_root("FolderLocker Manager", 780, 470)
    root.resizable(True, True)
    root.minsize(680, 380)

    # Dialogs opened from the Manager should sit above this window.
    global _ACTIVE_PARENT
    _ACTIVE_PARENT = root

    _header(root, ttk, "🔒", "FolderLocker",
            "Your vaults — select one and unlock it")

    body = ttk.Frame(root, style="TFrame")
    body.pack(fill="both", expand=True, padx=20, pady=18)

    # Pack the button row FIRST, anchored to the bottom, so it always stays
    # visible no matter how tall the vault list grows.  (A treeview packed with
    # expand=True before the buttons would otherwise push them off-screen.)
    btns = ttk.Frame(body, style="TFrame")
    btns.pack(side="bottom", fill="x", pady=(16, 0))

    # Treeview inside a thin card border (fills the space above the buttons).
    card = tk.Frame(body, bg=_THEME["card"], highlightbackground=_THEME["border"],
                    highlightthickness=1)
    card.pack(side="top", fill="both", expand=True)
    cols = ("name", "status", "visibility", "path")
    tree = ttk.Treeview(card, columns=cols, show="headings", height=8)
    headings = {"name": "Name", "status": "Status",
                "visibility": "Visibility", "path": "Location"}
    for c, w in (("name", 190), ("status", 90), ("visibility", 90), ("path", 320)):
        tree.heading(c, text=headings[c])
        tree.column(c, width=w, anchor="w")
    tree.tag_configure("locked", foreground=_THEME["danger"])
    tree.tag_configure("unlocked", foreground=_THEME["success"])
    tree.pack(fill="both", expand=True, padx=1, pady=1)

    empty = ttk.Label(body, text="No vaults yet — right-click a folder and choose "
                                 "Locker → Lock to create one.",
                      style="Muted.TLabel")

    def refresh():
        tree.delete(*tree.get_children())
        data = _load_vault_rows()
        for r in data:
            status_txt = "🔒 locked" if r["status"] == "locked" else "🔓 unlocked"
            vis = "👁 hidden" if r["hidden"] else "visible"
            tree.insert("", "end", iid=r["key"],
                        values=(r["name"], status_txt, vis, r["path"]),
                        tags=(r["status"],))
        if not data:
            empty.pack(anchor="center", pady=14)
        else:
            empty.pack_forget()

    def do_unlock(_evt=None):
        sel = tree.selection()
        if not sel:
            MessageDialog.info("Select a vault from the list first.")
            return
        key = sel[0]
        match = [r for r in _load_vault_rows() if r["key"] == key]
        if not match:
            return
        row = match[0]
        if row["status"] == "unlocked":
            MessageDialog.info(f"'{row['name']}' is already unlocked.")
            return
        try:
            ux._verb = "Unlock"
            cmd_unlock(row["path"], "", ux)
        except AbortAction:
            pass
        refresh()

    def do_full_unlock(_evt=None):
        sel = tree.selection()
        if not sel:
            MessageDialog.info("Select a vault from the list first.")
            return
        key = sel[0]
        match = [r for r in _load_vault_rows() if r["key"] == key]
        if not match:
            return
        row = match[0]
        if not MessageDialog.ask_yes_no(
            f"Fully unlock '{row['name']}'?\n\nThis decrypts it, restores it to a "
            f"normal folder, and removes it from FolderLocker — no more auto-relock.",
            "Fully Unlock?",
        ):
            return
        try:
            ux._verb = "Fully Unlock"
            cmd_unlock_f(row["path"], "", ux)
        except AbortAction:
            pass
        refresh()

    def do_recover(_evt=None):
        sel = tree.selection()
        if not sel:
            MessageDialog.info("Select a vault from the list first.")
            return
        key = sel[0]
        match = [r for r in _load_vault_rows() if r["key"] == key]
        if not match:
            return
        row = match[0]
        creds = RecoverDialog.ask(row["name"])
        if creds is None:
            return
        code, new_pw = creds
        try:
            cmd_recover(row["path"], code, new_pw, ux)
        except AbortAction:
            pass
        refresh()

    def do_forget(_evt=None):
        sel = tree.selection()
        if not sel:
            MessageDialog.info("Select a vault from the list first.")
            return
        key = sel[0]
        match = [r for r in _load_vault_rows() if r["key"] == key]
        if not match:
            return
        row = match[0]
        # Two-step confirmation because this permanently destroys the data.
        if not MessageDialog.ask_yes_no(
            f"Permanently DELETE '{row['name']}'?\n\n"
            f"Use this only if you have lost BOTH the password and the recovery "
            f"key. The encrypted folder and all its contents will be erased and "
            f"CANNOT be recovered by anyone.",
            "Delete forever?",
        ):
            return
        if not MessageDialog.ask_yes_no(
            f"Last chance — really erase '{row['name']}' for good?\n\n"
            f"This cannot be undone.",
            "Confirm permanent deletion",
        ):
            return
        try:
            cmd_forget(row["path"], ux, delete_files=True)
        except AbortAction:
            pass
        refresh()

    tree.bind("<Double-1>", do_unlock)
    refresh()

    _button(btns, "🔓  Unlock", do_unlock, kind="accent").pack(side="left")
    _button(btns, "Fully Unlock", do_full_unlock, kind="ghost").pack(
        side="left", padx=(8, 0))
    _button(btns, "🔑  Reset password", do_recover, kind="ghost").pack(
        side="left", padx=(8, 0))
    _button(btns, "Refresh", refresh, kind="ghost").pack(side="left", padx=(8, 0))
    _button(btns, "🗑  Delete", do_forget, kind="danger").pack(side="right")
    _button(btns, "Close", root.destroy, kind="ghost").pack(side="right", padx=(0, 8))

    # The Manager is a Toplevel of the shared hidden root; run that root's loop
    # and stop it when the Manager window closes.
    parent = _get_root()
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Destroy>", lambda e: parent.quit() if e.widget is root else None)
    root.lift()
    root.focus_force()
    parent.mainloop()

# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="locker",
        description="AES-256-GCM folder locker — Argon2id + envelope encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Password requirements:
  {_POLICY}

Commands:
  lock      <folder> [password]              Encrypt & lock (folder stays visible)
  lock-hide <folder> [password]              Encrypt, lock, rename & hide
  unlock    <folder> [password]              Decrypt (auto-relocks on lock/shutdown)
  unlock-f  <folder> [password]              Fully unlock & remove from registry
  recover   <folder> <recovery-code> <newpw> Reset password (zero re-encryption)
  manage                                     Open the vault manager
  show                                       List all vaults

Setup:
  locker --install        Register the right-click menu & manager (no admin)
  locker --uninstall      Remove the menu, manager shortcut & installed copy

Examples:
  locker lock     "C:\\Downloads\\Secret" MyP@ss1!
  locker unlock   "C:\\Downloads\\Secret" MyP@ss1!

Install dependencies (running from source):
  pip install cryptography argon2-cffi psutil
        """,
    )
    parser.add_argument("--daemon", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install", action="store_true",
                        help="Register the right-click menu and manager (per-user)")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove the right-click menu, manager and installed copy")
    sub = parser.add_subparsers(dest="command")

    lk = sub.add_parser("lock", help="Encrypt & lock a folder (stays visible)")
    lk.add_argument("folder"); lk.add_argument("password", nargs="?", default="")
    lk.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    lh = sub.add_parser("lock-hide", help="Encrypt, lock, rename & hide a folder")
    lh.add_argument("folder"); lh.add_argument("password", nargs="?", default="")
    lh.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    ul = sub.add_parser("unlock", help="Decrypt & unlock (auto-relocks)")
    ul.add_argument("folder"); ul.add_argument("password", nargs="?", default="")
    ul.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    uf = sub.add_parser("unlock-f", help="Fully unlock & remove from vault registry")
    uf.add_argument("folder"); uf.add_argument("password", nargs="?", default="")
    uf.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    rc = sub.add_parser("recover", help="Reset password using recovery code")
    rc.add_argument("folder")
    rc.add_argument("recovery_code", metavar="recovery-code")
    rc.add_argument("new_password",  metavar="new-password")
    rc.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    mg = sub.add_parser("manage", help="Open the vault manager")
    mg.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    fg = sub.add_parser("forget",
                        help="Remove a vault from the registry (optionally delete its files)")
    fg.add_argument("folder")
    fg.add_argument("--delete-files", action="store_true",
                    help="Also permanently delete the encrypted folder (irreversible)")
    fg.add_argument("--gui", action="store_true", help=argparse.SUPPRESS)

    sub.add_parser("show", help="List all registered vaults and their status")

    args = parser.parse_args()

    # Daemon path: never touches the UX layer.
    if args.daemon:
        if not sys.platform.startswith("win"):
            return
        run_daemon(); return

    # GUI mode if --gui is set either at top level or on the subcommand.
    is_gui = getattr(args, "gui", False)
    ux: UxContext = GuiUx() if is_gui else ConsoleUx()
    # Hint the password dialog title with the action verb.
    if is_gui:
        ux._verb = {"unlock": "Unlock", "unlock-f": "Fully Unlock"}.get(
            args.command, "Lock")

    try:
        # Install / uninstall.
        if args.install:
            do_install(ux); return
        if args.uninstall:
            do_uninstall(ux); return

        # No command at all → first-run behaviour.
        if args.command is None:
            if not sys.platform.startswith("win"):
                die("locker only works on Windows.")
            if _menu_installed():
                # Already installed → open the Manager.
                cmd_manage(GuiUx())
            else:
                # Not installed → show the first-run install window (a real
                # window with its own mainloop; reliable in the frozen exe).
                _first_run_gui()
            return

        # All real actions share the precondition checks.
        if args.command in ("lock", "lock-hide", "unlock", "unlock-f"):
            check_preconditions(ux, args.folder)
        else:
            check_preconditions(ux)

        if   args.command == "lock":
            cmd_lock(args.folder, args.password, ux, hide=False)
        elif args.command == "lock-hide":
            cmd_lock(args.folder, args.password, ux, hide=True)
        elif args.command == "unlock":
            cmd_unlock(args.folder, args.password, ux)
        elif args.command == "unlock-f":
            cmd_unlock_f(args.folder, args.password, ux)
        elif args.command == "recover":
            cmd_recover(args.folder, args.recovery_code, args.new_password, ux)
        elif args.command == "forget":
            cmd_forget(args.folder, ux, delete_files=args.delete_files)
        elif args.command == "manage":
            cmd_manage(ux)
        elif args.command == "show":
            cmd_show()
        else:
            parser.print_help()
    except AbortAction:
        sys.exit(1)


def _has_display() -> bool:
    """Best-effort check that a GUI can be shown (always true on Windows desktop)."""
    return sys.platform.startswith("win")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        # Last-resort crash log so a windowed (no-console) exe failure is
        # diagnosable instead of vanishing silently.
        try:
            import traceback as _tb
            APP_DIR.mkdir(parents=True, exist_ok=True)
            with open(APP_DIR / "crash.log", "a", encoding="utf-8") as _fh:
                _fh.write(_tb.format_exc() + "\n")
        except Exception:
            pass
        raise
