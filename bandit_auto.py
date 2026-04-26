#!/usr/bin/env python3
"""
bandit_auto.py — OverTheWire Bandit levels 0 → 15.

Automated solver with hardened file I/O, password redaction, Tar-Slip
protection, and a multi-strategy approach to level 13 (SSH key auth).

Requirements : pip install paramiko python-dotenv
Setup        : ssh-keyscan -p 2220 bandit.labs.overthewire.org > bandit_known_hosts
               cp .env.example .env   # edit if needed
Usage        : python3 bandit_auto.py [--debug]

Configuration is loaded from environment variables (see .env.example).
All tunables have safe defaults; no secret material is hard-coded.

Security hardening summary
──────────────────────────
  Password file   : O_NOFOLLOW | O_CLOEXEC | O_CREAT | O_TRUNC, mode 0600,
                    fcntl LOCK_EX (single-instance guard)
  Host-key trust  : RejectPolicy + ssh-keyscan known_hosts (outer);
                    level 13 Strategy A delegates to a nested paramiko Transport
                    over a direct-tcpip channel — no new host-key trust model;
                    Strategy B invokes the remote ssh binary on loopback only.
  Log redaction   : _RedactFilter materialises %-args first, then wipes
                    all known passwords (≥ 8 chars) before any emission
  Output capture  : _exec reads stderr when stdout is empty — no silent failures;
                    exit-status logged at DEBUG after all reads (deadlock-safe)
  Regex extraction: two-pass — 32-char exact, then longest 20-64 char token
                    (adapts automatically to OTW password-format changes)
  Data cap        : 65 536-byte hard limit before any regex / string ops
  Temp cleanup    : urandom wipe → rmtree; symlink skip (A5); onerror re-raise
  Tar extraction  : realpath Tar-Slip check on every member before extractall;
                    filter='data' enforced on Python ≥ 3.12 (CVE-2007-4559)
  Direct TCP      : channel.settimeout() + chunked recv, no busy-wait
  Fork safety     : O_CLOEXEC — fd not inherited by child processes
  Jitter          : CONNECT_PAUSE ± random offset (IDS timing-pattern defeat)
  Key type probe  : Ed25519 → ECDSA → RSA (DSSKey removed in paramiko 3.x)
  Exception log   : only type(exc).__name__ — message never reaches the log
  fd lifecycle    : _close_pw_file() in try/finally — guaranteed on sys.exit()

Patch v6.3 — retry/backoff in _connect() + socket-leak fix on retry
────────────────────────────────────────────────────────────────────
  Root cause:
    OTW Bandit throttles rapid SSH connections at the banner-read phase.
    After a successful level, CONNECT_PAUSE fires *after* solve() returns,
    so the *next* _connect() hits the server before the throttle window
    expires.  The server drops the TCP connection before sending the SSH
    banner → paramiko raises SSHException("Error reading SSH protocol
    banner").

  Fix — _connect() now retries with exponential backoff + jitter:
    attempt 1 → immediate
    attempt 2 → base * 2^0  + U(0, jitter)   ≈ 3–4 s
    attempt 3 → base * 2^1  + U(0, jitter)   ≈ 6–7 s
    attempt 4 → base * 2^2  + U(0, jitter)   ≈ 12–13 s
    (capped at _RETRY_WAIT_CAP = 30 s per sleep to prevent runaway waits)

  New tunables (all via environment variables):
    BANDIT_MAX_RETRIES     (default 4)   — total connection attempts
    BANDIT_RETRY_BACKOFF   (default 3.0) — base wait seconds
    BANDIT_RETRY_WAIT_CAP  (default 30)  — per-sleep ceiling in seconds

  Socket-leak fix:
    Previous code constructed a new SSHClient on every retry loop iteration
    but never closed it on failure.  Each failed attempt now calls
    client.close() before sleeping, ensuring the underlying socket is
    released immediately rather than waiting for the GC finaliser.

Patch v6.2 — Python 3.12+ compatibility + resource-leak fixes
─────────────────────────────────────────────────────────────
  Fix 1 — shutil.rmtree(onerror=...) deprecated 3.12, removed 3.14.
  Fix 2 — tarfile.extractall() without filter= raises DeprecationWarning.
  Fix 3 — _LEVEL12_SCRIPT: stdout=open(...) unclosed file handle.
  Fix 4 — _LEVEL12_SCRIPT: open(f).read() without encoding or close.
  Fix 5 — buf += chunk O(n²) realloc pattern replaced with list-of-chunks.

Patch v6.1 — fix _solve_level15 output_len=0
─────────────────────────────────────────────
  { printf; sleep 3; } group holds the pipe open long enough for the
  server to respond.  timeout 12 acts as a kill switch against hangs.

Patch v6.0 — three root-cause fixes for _solve_level13 AuthenticationException
  Fix 1 — _ChannelSocket.fileno() raises io.UnsupportedOperation
  Fix 2 — _load_private_key() normalises line endings before parsing
  Fix 3 — Strategy B: chmod-600 tmpfile + LogLevel=ERROR
"""

from __future__ import annotations

import contextlib
import fcntl
import io
import logging
import os
import random
import re
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import textwrap
import time
import traceback as _traceback

try:
    import paramiko
except ImportError:
    sys.exit("[!] Missing dependency: pip install paramiko")

# Optional: load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; rely on shell environment

# ── runtime version flags ─────────────────────────────────────────────────────

_PY_GTE_312 = sys.version_info >= (3, 12)

# ── configuration (all values from environment, safe defaults) ────────────────

HOST            = os.environ.get("BANDIT_HOST", "bandit.labs.overthewire.org")
PORT            = int(os.environ.get("BANDIT_PORT", "2220"))
CONNECT_TIMEOUT = int(os.environ.get("BANDIT_CONNECT_TIMEOUT", "15"))
EXEC_TIMEOUT    = int(os.environ.get("BANDIT_EXEC_TIMEOUT", "30"))
CONNECT_PAUSE   = float(os.environ.get("BANDIT_CONNECT_PAUSE", "2.0"))
CONNECT_JITTER  = float(os.environ.get("BANDIT_CONNECT_JITTER", "1.0"))
PASSWORD_FILE   = os.environ.get("BANDIT_PASSWORD_FILE", "bandit_passwords.txt")

# Retry / backoff tunables (v6.3)
MAX_CONNECT_RETRIES = int(os.environ.get("BANDIT_MAX_RETRIES", "4"))
_RETRY_BACKOFF_BASE = float(os.environ.get("BANDIT_RETRY_BACKOFF", "3.0"))
_RETRY_WAIT_CAP     = float(os.environ.get("BANDIT_RETRY_WAIT_CAP", "30.0"))

KNOWN_HOSTS_FILE = os.environ.get(
    "BANDIT_KNOWN_HOSTS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "bandit_known_hosts"),
)

_RAW_MAX_BYTES = 65_536  # hard output cap before any regex / string ops

# ── password regex (two-pass) ─────────────────────────────────────────────────
# Pass 1 — canonical OTW format: exactly 32 alphanum chars, boundary-anchored.
# Pass 2 — future-proof fallback: longest isolated alphanum token 20-64 chars.

_PASS_RE_32  = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9]{32})(?![A-Za-z0-9])")
_PASS_RE_ANY = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9]{20,64})(?![A-Za-z0-9])")

# ── password store ────────────────────────────────────────────────────────────

_known_passwords: dict[int, str] = {}
_pw_fd: int = -1


def _init_pw_file() -> None:
    """Open the password file atomically with full hardening flags."""
    global _pw_fd
    _pw_fd = os.open(
        PASSWORD_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        fcntl.flock(_pw_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(_pw_fd)
        sys.exit("[!] Another instance holds the lock — aborting.")


def _close_pw_file() -> None:
    """fsync → unlock → close. Idempotent; safe to call from finally."""
    global _pw_fd
    if _pw_fd < 0:
        return
    try:
        os.fsync(_pw_fd)
        fcntl.flock(_pw_fd, fcntl.LOCK_UN)
        os.close(_pw_fd)
    except OSError:
        pass
    finally:
        _pw_fd = -1


def _store(level: int, pw: str) -> None:
    _known_passwords[level] = pw
    os.write(_pw_fd, f"bandit{level:02d}: {pw}\n".encode())
    os.fsync(_pw_fd)


def _load(level: int) -> str:
    if not (0 <= level <= 15):
        raise ValueError(f"Level {level} outside valid range [0, 15]")
    try:
        return _known_passwords[level]
    except KeyError:
        raise RuntimeError(f"No password stored for level {level}") from None

# ── logging + redaction ───────────────────────────────────────────────────────

class _RedactFilter(logging.Filter):
    """
    Materialise the full %-formatted message, then scrub every known password
    (≥ 8 chars) before the record reaches any handler.  args is cleared so
    downstream formatters cannot re-apply them.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pw in _known_passwords.values():
            if pw and len(pw) >= 8:
                msg = msg.replace(pw, "<REDACTED>")
        record.msg  = msg
        record.args = ()
        return True


_log = logging.getLogger("bandit")
_log.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stderr)
_handler.addFilter(_RedactFilter())
_log.addHandler(_handler)

# ── password extraction ───────────────────────────────────────────────────────

def _extract_pass(raw: str) -> str:
    """
    Two-pass extraction with hard output cap.
    Never embeds raw content in exception messages (no data leak).
    """
    if len(raw) > _RAW_MAX_BYTES:
        raw = raw[:_RAW_MAX_BYTES]

    # Pass 1: canonical 32-char format
    m32 = _PASS_RE_32.findall(raw)
    if m32:
        if len(m32) > 1:
            _log.warning("Multiple 32-char candidates — using first.")
        return m32[0]

    # Pass 2: format-agnostic fallback
    many = _PASS_RE_ANY.findall(raw)
    if many:
        best = max(many, key=len)
        _log.warning(
            "Fallback regex matched token len=%d — "
            "OTW may have updated password format.",
            len(best),
        )
        return best

    raise ValueError(
        f"No password token found (output_len={len(raw)})"
    )

# ── known-hosts symlink guard ─────────────────────────────────────────────────

def _check_known_hosts(path: str) -> str | None:
    """
    lstat() prevents os.path.isfile() from being fooled by a symlink.
    Returns path if regular file, None if absent, raises on symlink/other.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise RuntimeError(
            f"bandit_known_hosts {path!r} is a symlink — "
            "possible host-key substitution attack, refusing to load."
        )
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(
            f"bandit_known_hosts {path!r} is not a regular file."
        )
    return path

# ── compatibility shims ───────────────────────────────────────────────────────

def _rmtree(path: str, on_error) -> None:
    """
    shutil.rmtree wrapper that selects the correct error-callback keyword.

    onerror= was deprecated in Python 3.12 and will be removed in 3.14.
    onexc=  was introduced in Python 3.12 with a simpler (func, path, exc)
            signature — the exc is the live exception, not a sys.exc_info() tuple.

    This shim translates: callers always pass an onerror-style callable
    (func, path, exc_info), and we adapt it to onexc when necessary.
    """
    if _PY_GTE_312:
        def _onexc(func, path, exc):
            on_error(func, path, (type(exc), exc, exc.__traceback__))
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=on_error)  # type: ignore[call-arg]


def _tar_extractall(tf: tarfile.TarFile, dest: str) -> None:
    """
    tarfile.extractall() wrapper that enforces filter='data' on Python ≥ 3.12.

    Without a filter, Python 3.12 emits DeprecationWarning and Python 3.14
    will raise an error.  filter='data' blocks absolute paths, path traversal
    members, and dangerous file types (devices, setuid bits) — a superset of
    the manual Tar-Slip realpath check already performed by callers, providing
    defence-in-depth at the stdlib level.
    """
    if _PY_GTE_312:
        tf.extractall(dest, filter="data")
    else:
        tf.extractall(dest)

# ── SSH helpers ───────────────────────────────────────────────────────────────

def _build_client() -> tuple[paramiko.SSHClient, str | None]:
    """
    Construct a fresh SSHClient with the correct host-key policy.

    Factored out of _connect() so the retry loop can call it without
    duplicating the host-key setup logic.  Returns (client, kh_path).
    """
    client = paramiko.SSHClient()
    kh = _check_known_hosts(KNOWN_HOSTS_FILE)
    if kh:
        client.load_host_keys(kh)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        _log.warning(
            "bandit_known_hosts missing — MITM protection OFF. "
            "Fix: ssh-keyscan -p %d %s > bandit_known_hosts", PORT, HOST
        )
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client, kh


def _connect(level: int, password: str) -> paramiko.SSHClient:
    """
    Connect to HOST:PORT as bandit<level> with exponential backoff retry.

    OTW Bandit throttles rapid SSH connections: the server drops the TCP
    connection before sending the SSH banner when connections arrive too
    quickly.  This manifests as:

        paramiko.ssh_exception.SSHException: Error reading SSH protocol banner

    Retry schedule (base=3.0 s, jitter=CONNECT_JITTER, cap=30 s):
        attempt 1 — immediate
        attempt 2 — sleep  3–4 s   (base * 2^0 + U(0, jitter))
        attempt 3 — sleep  6–7 s   (base * 2^1 + U(0, jitter))
        attempt 4 — sleep 12–13 s  (base * 2^2 + U(0, jitter))

    Each failed attempt calls client.close() immediately — the underlying
    socket is released before the sleep, not deferred to the GC finaliser.
    """
    # Transient errors that indicate server-side throttling or a TCP race.
    _RETRIABLE = (
        paramiko.SSHException,
        socket.error,
        EOFError,
        OSError,
    )

    last_exc: Exception = RuntimeError("unreachable")

    for attempt in range(1, MAX_CONNECT_RETRIES + 1):
        client, _ = _build_client()
        try:
            client.connect(
                HOST, port=PORT,
                username=f"bandit{level}",
                password=password,
                timeout=CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            return client
        except _RETRIABLE as exc:
            # Close immediately — do NOT leak the socket.
            with contextlib.suppress(Exception):
                client.close()
            last_exc = exc

            if attempt >= MAX_CONNECT_RETRIES:
                break   # exhausted — raise below

            # Exponential backoff, capped at _RETRY_WAIT_CAP.
            raw_wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            wait = min(raw_wait, _RETRY_WAIT_CAP) + random.uniform(0, CONNECT_JITTER)
            _log.warning(
                "Connect attempt %d/%d failed [%s] — retry in %.1fs",
                attempt, MAX_CONNECT_RETRIES, type(exc).__name__, wait,
            )
            time.sleep(wait)

    raise last_exc


def _exec(client: paramiko.SSHClient, cmd: str, timeout: int = EXEC_TIMEOUT) -> str:
    """
    Run cmd, cap stdout at _RAW_MAX_BYTES.

    Read order: stdout → stderr → exit_status.
    recv_exit_status() is called last (after both reads) to avoid the
    classic deadlock where a full pipe blocks the remote process before
    we ever drain it.  Exit codes != 0 are logged at DEBUG level — useful
    when --debug is passed but silent in normal runs.

    On empty stdout: read up to 2 KiB of stderr and log it — no silent
    failures.  stderr content is never fed into _extract_pass (avoids
    parsing ssh diagnostic messages as passwords).
    """
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)

    raw = stdout.read(_RAW_MAX_BYTES + 1)
    if len(raw) > _RAW_MAX_BYTES:
        _log.warning("stdout exceeded cap (%d B) — truncated.", _RAW_MAX_BYTES)
        raw = raw[:_RAW_MAX_BYTES]

    if not raw.strip():
        err = stderr.read(2048).decode(errors="replace").strip()
        if err:
            _log.warning("Empty stdout. stderr → %s", err)

    # Deadlock-safe: all reads complete before we ask for exit status.
    try:
        ec = stdout.channel.recv_exit_status()
        if ec != 0:
            _log.debug("Command exited with status %d.", ec)
    except Exception:
        pass

    return raw.decode(errors="replace").strip()

# ── secure tmpdir ─────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _secure_tmpdir():
    """
    0700 tmpdir.  On exit: overwrite file contents with urandom, then rmtree.
    Skips symlinks (tarfile could create them — Tar-Slip mitigation A5).
    Errors in rmtree are logged and re-raised, never silently swallowed.
    """
    td = tempfile.mkdtemp(prefix="b12_")
    os.chmod(td, 0o700)
    try:
        yield td
    finally:
        for root, _dirs, files in os.walk(td):
            for name in files:
                path = os.path.join(root, name)
                try:
                    if stat.S_ISLNK(os.lstat(path).st_mode):
                        continue
                    size = os.path.getsize(path)
                    with open(path, "wb") as fh:
                        fh.write(os.urandom(max(size, 1)))
                except OSError:
                    pass

        def _on_err(fn, path, exc_info):
            _log.error("rmtree error on %s: %s", path, exc_info[1])
            raise exc_info[1]

        _rmtree(td, _on_err)

# ── safe tar extraction ───────────────────────────────────────────────────────

def _safe_tar_extract(tar_path: str, dest: str) -> None:
    real_dest = os.path.realpath(dest) + os.sep
    with tarfile.open(tar_path) as tf:
        for m in tf.getmembers():
            real_m = os.path.realpath(os.path.join(dest, m.name))
            if not (real_m + os.sep).startswith(real_dest):
                raise ValueError(f"Tar Slip blocked: {m.name!r}")
        # _tar_extractall adds filter='data' on Python ≥ 3.12 (defence-in-depth).
        _tar_extractall(tf, dest)

# ── direct TCP helper (level 14) ─────────────────────────────────────────────

def _tcp_send_recv(
    client: paramiko.SSHClient,
    host: str,
    port: int,
    data: bytes,
    read_timeout: float = 6.0,
) -> bytes:
    """
    Send data over a direct-tcpip channel, return response.
    settimeout() replaces busy-polling; output is capped at _RAW_MAX_BYTES.
    Chunks are accumulated in a list and joined once — avoids O(n²) realloc.
    """
    transport = client.get_transport()
    ch = transport.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0))
    ch.sendall(data)
    ch.shutdown_write()
    ch.settimeout(read_timeout)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = ch.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _RAW_MAX_BYTES:
                _log.warning("TCP response exceeded cap — truncated.")
                break
    except socket.timeout:
        pass
    finally:
        ch.close()
    return b"".join(chunks)

# ── level 12 remote Python script ─────────────────────────────────────────────

_LEVEL12_SCRIPT = textwrap.dedent("""\
    import os, subprocess, sys, shutil, tarfile, tempfile

    _PY_GTE_312 = sys.version_info >= (3, 12)

    def _rmtree_silent(path):
        \"\"\"Version-safe rmtree that silences all errors.\"\"\"
        if _PY_GTE_312:
            shutil.rmtree(path, onexc=lambda fn, p, exc: None)
        else:
            shutil.rmtree(path, onerror=lambda fn, p, ei: None)

    def safe_extract(tar_path, dest):
        real_dest = os.path.realpath(dest) + os.sep
        with tarfile.open(tar_path) as tf:
            for m in tf.getmembers():
                real_m = os.path.realpath(os.path.join(dest, m.name))
                if not (real_m + os.sep).startswith(real_dest):
                    raise ValueError('Tar Slip: ' + m.name)
            if _PY_GTE_312:
                tf.extractall(dest, filter='data')
            else:
                tf.extractall(dest)

    td = tempfile.mkdtemp(prefix='b12r_')
    os.chmod(td, 0o700)
    shutil.copy('/home/bandit12/data.txt', os.path.join(td, 'data.txt'))
    os.chdir(td)

    with open('work', 'wb') as out_fh:
        subprocess.run(['xxd', '-r', 'data.txt'], stdout=out_fh, check=True)
    f = 'work'
    for _ in range(30):
        r = subprocess.run(['file', f], capture_output=True, text=True).stdout
        if 'gzip' in r:
            os.rename(f, f + '.gz')
            subprocess.run(['gzip', '-df', f + '.gz'], check=True)
        elif 'bzip2' in r:
            os.rename(f, f + '.bz2')
            subprocess.run(['bzip2', '-df', f + '.bz2'], check=True)
        elif 'tar' in r.lower() or 'POSIX' in r:
            safe_extract(f, td)
            os.remove(f)
            candidates = [x for x in os.listdir() if x not in ('data.txt', 'work')]
            if not candidates:
                break
            f = max(candidates, key=lambda x: os.path.getmtime(x))
        elif 'ASCII' in r or 'text' in r.lower():
            with open(f, encoding='utf-8', errors='replace') as fh:
                sys.stdout.write(fh.read())
            break
        else:
            break

    _rmtree_silent(td)
""")

# ── special-case solvers ──────────────────────────────────────────────────────

def _solve_level12(client: paramiko.SSHClient) -> str:
    """
    Execute the decompression script on the remote host via stdin pipe.
    Uses settimeout + chunked recv — no blocking makefile().read().
    """
    ch = client.get_transport().open_session()
    ch.exec_command("python3")
    ch.sendall(_LEVEL12_SCRIPT.encode())
    ch.shutdown_write()
    ch.settimeout(EXEC_TIMEOUT)

    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = ch.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _RAW_MAX_BYTES:
                _log.warning("Level 12 output cap reached — truncated.")
                break
    except socket.timeout:
        _log.warning("Level 12 timed out after %ds.", EXEC_TIMEOUT)
    finally:
        ch.close()

    return _extract_pass(b"".join(chunks).decode(errors="replace"))


def _load_private_key(key_data: str) -> paramiko.PKey:
    """
    Normalise PEM line endings, then probe key types in modern-first order.

    Normalisation (Fix 2):
      _exec() strips the output but interior \\r characters survive when the
      remote shell outputs CRLF.  PEM parsers are strict: a \\r inside a
      base64 line raises ValueError or silently corrupts key material.
      splitlines() + join converts any mix of \\r\\n / \\r / \\n to pure LF.
      The trailing '\\n' is required by openssl-style PEM readers.

    Raises paramiko.SSHException if none of the key types match.
    """
    key_data = "\n".join(key_data.splitlines())
    if key_data and not key_data.endswith("\n"):
        key_data += "\n"

    for kt in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return kt.from_private_key(io.StringIO(key_data))
        except (paramiko.SSHException, ValueError):
            pass
    raise paramiko.SSHException("Could not detect private key type.")


class _ChannelSocket:
    """
    Minimal socket shim wrapping a paramiko Channel.

    Allows paramiko.Transport to accept a Channel as its `sock` argument,
    enabling a fully in-process nested SSH session without spawning a child
    or writing any host-key material to disk.

    Implements the socket.socket subset that paramiko.Transport probes at
    startup: send(), recv(), close(), settimeout(), getpeername().

    fileno() deliberately raises io.UnsupportedOperation (Fix 1):
      paramiko.Transport calls fileno() at startup to decide between
      select()-based and thread-based I/O.  paramiko.Channel.fileno()
      returns -1 on paramiko ≥ 3.x (no real file descriptor).  Passing
      -1 to select() raises EBADF on Linux; Transport swallows it and
      enters a degraded state — start_client() appears to succeed but the
      handshake is incomplete, causing auth_publickey() → AuthenticationException.
      Raising UnsupportedOperation forces Transport to unconditionally use
      its thread-based send/recv path, which is fully compatible with any
      socket-like object and correct on all platforms.
    """
    __slots__ = ("_chan",)

    def __init__(self, chan: paramiko.Channel) -> None:
        self._chan = chan

    def send(self, data: bytes) -> int:
        self._chan.sendall(data)
        return len(data)

    def recv(self, nbytes: int) -> bytes:
        return self._chan.recv(nbytes)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._chan.close()

    def settimeout(self, t: float | None) -> None:
        self._chan.settimeout(t)

    def getpeername(self) -> tuple[str, int]:
        return ("localhost", PORT)

    def fileno(self) -> int:
        raise io.UnsupportedOperation(
            "fileno is not supported on paramiko Channel objects"
        )


def _connect_with_key(pkey: paramiko.PKey, username: str) -> paramiko.SSHClient:
    """
    Open a new SSHClient connection to HOST:PORT authenticated by pkey.
    Reuses the same host-key trust model as _connect().
    """
    c = paramiko.SSHClient()
    kh = _check_known_hosts(KNOWN_HOSTS_FILE)
    if kh:
        c.load_host_keys(kh)
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        _log.warning(
            "bandit_known_hosts missing — MITM protection OFF. "
            "Fix: ssh-keyscan -p %d %s > bandit_known_hosts", PORT, HOST
        )
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        HOST, port=PORT,
        username=username,
        pkey=pkey,
        timeout=CONNECT_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return c


def _solve_level13(client: paramiko.SSHClient) -> str:
    """
    Retrieve bandit14's password using the SSH key at /home/bandit13/sshkey.private.

    Strategy A — direct external paramiko connection (primary)
    ──────────────────────────────────────────────────────────
    Opens a second, independent paramiko SSHClient directly to HOST:PORT
    as bandit14.  Source IP = this machine's external IP; the server-side
    loopback auth restriction does not apply.

    Strategies B / C — loopback fallbacks (legacy)
    ───────────────────────────────────────────────
    Retained for the event that server configuration changes and loopback
    auth is re-enabled.  Both will fail under the current sshd policy
    (Match Address 127.0.0.1 / AuthenticationMethods none).
    """
    key_data = _exec(client, "cat /home/bandit13/sshkey.private")
    if not key_data:
        raise RuntimeError("Empty key read from /home/bandit13/sshkey.private")
    pkey = _load_private_key(key_data)

    # Strategy A: direct external connection
    try:
        client14 = _connect_with_key(pkey, "bandit14")
        try:
            return _extract_pass(_exec(client14, "cat /etc/bandit_pass/bandit14"))
        finally:
            client14.close()
    except Exception as exc_a:
        _log.warning(
            "Strategy A (direct external connection) failed [%s] — "
            "trying nested Transport.",
            type(exc_a).__name__,
        )

    # Strategy B: paramiko nested Transport via _ChannelSocket
    try:
        outer_transport = client.get_transport()
        chan = outer_transport.open_channel(
            "direct-tcpip", ("localhost", PORT), ("127.0.0.1", 0)
        )
        inner_transport = paramiko.Transport(_ChannelSocket(chan))
        try:
            inner_transport.start_client(timeout=CONNECT_TIMEOUT)
            if not inner_transport.is_active():
                raise RuntimeError("Inner Transport not active after start_client()")
            inner_transport.auth_publickey("bandit14", pkey)
            sess = inner_transport.open_session()
            try:
                sess.exec_command("cat /etc/bandit_pass/bandit14")
                sess.shutdown_write()
                sess.settimeout(EXEC_TIMEOUT)
                chunks: list[bytes] = []
                total = 0
                try:
                    while True:
                        chunk = sess.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > _RAW_MAX_BYTES:
                            _log.warning("Strategy B: output cap reached.")
                            break
                except socket.timeout:
                    _log.warning("Strategy B: recv timed out.")
                result = b"".join(chunks).decode(errors="replace").strip()
                if result:
                    return _extract_pass(result)
                raise RuntimeError("Strategy B: empty response from nested session")
            finally:
                sess.close()
        finally:
            inner_transport.close()
    except Exception as exc_b:
        _log.warning(
            "Strategy B (nested Transport) failed [%s] — trying ssh binary.",
            type(exc_b).__name__,
        )

    # Strategy C: remote ssh binary (hardened: chmod-600 tmpfile, LogLevel=ERROR)
    cmd = (
        "tmp=$(mktemp)"
        " && chmod 600 \"$tmp\""
        " && cat /home/bandit13/sshkey.private > \"$tmp\""
        " && ssh"
        " -n -T"
        " -i \"$tmp\""
        f" -p {PORT}"
        " -o BatchMode=yes"
        " -o StrictHostKeyChecking=no"
        " -o UserKnownHostsFile=/dev/null"
        " -o IdentitiesOnly=yes"
        " -o ConnectTimeout=10"
        " -o LogLevel=ERROR"
        " bandit14@localhost"
        " cat /etc/bandit_pass/bandit14"
        "; rm -f \"$tmp\""
    )
    return _extract_pass(_exec(client, cmd))


def _solve_level14(client: paramiko.SSHClient, password: str) -> str:
    """Send current password to localhost:30000 over direct-tcpip."""
    raw = _tcp_send_recv(
        client, "localhost", 30000,
        (password.strip() + "\n").encode(),
    )
    return _extract_pass(raw.decode(errors="replace"))


def _solve_level15(client: paramiko.SSHClient, password: str) -> str:
    """
    Submit password to localhost:30001 via openssl s_client (TLS).

    The { printf; sleep 3; } group holds the pipe open long enough for
    the server to respond before openssl sends TLS close_notify.
    timeout 12 is the kill switch against hangs.
    """
    safe = re.sub(r"[^A-Za-z0-9]", "", password)
    cmd = (
        f"{{ printf '%s\\n' '{safe}'; sleep 3; }} | "
        "timeout 12 openssl s_client -connect localhost:30001 "
        "-quiet -no_ign_eof 2>/dev/null"
    )
    return _extract_pass(_exec(client, cmd, timeout=30))

# ── level → shell command map ─────────────────────────────────────────────────

_CMD: dict[int, str] = {
    0:  "cat ~/readme",
    1:  "cat ~/- 2>/dev/null || cat ./-",
    2:  "find ~ -maxdepth 1 -type f -name '* *' -exec cat {} + 2>/dev/null",
    3:  "find ~/inhere -maxdepth 1 -name '.*' -type f -exec cat {} + 2>/dev/null",
    4: (
        "find ~/inhere -type f -print0 2>/dev/null"
        " | xargs -0 file"
        " | grep -iE 'ASCII|text'"
        " | head -1"
        " | cut -d: -f1"
        " | xargs -d '\\n' -I{} cat {}"
    ),
    5:  "find ~/inhere -type f -readable ! -executable -size 1033c -exec cat {} + 2>/dev/null",
    6:  "find / -user bandit7 -group bandit6 -size 33c -exec cat {} + 2>/dev/null",
    7:  "grep -m1 '^millionth' ~/data.txt | awk '{print $2}'",
    8:  "sort ~/data.txt | uniq -u",
    9:  r"strings ~/data.txt | grep -E '={2,}' | grep -oE '[A-Za-z0-9]{20,64}'",
    10: "base64 -d ~/data.txt",
    11: "tr 'A-Za-z' 'N-ZA-Mn-za-m' < ~/data.txt",
}

# ── dispatcher ────────────────────────────────────────────────────────────────

def solve(level: int, password: str) -> str:
    client = _connect(level, password)
    try:
        if   level == 12: return _solve_level12(client)
        elif level == 13: return _solve_level13(client)
        elif level == 14: return _solve_level14(client, password)
        elif level == 15: return _solve_level15(client, password)
        else:
            return _extract_pass(_exec(client, _CMD[level]))
    finally:
        client.close()

# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    debug = "--debug" in sys.argv

    _init_pw_file()
    _store(0, "bandit0")   # seed: public starting credential for OTW Bandit

    sep = "─" * 54
    _log.info(sep)
    _log.info("  OTW Bandit v6.3 — levels 0 → 15")
    _log.info("  Host  : %s:%d", HOST, PORT)
    _log.info("  Output: %s  (0600, locked)", PASSWORD_FILE)
    _log.info(sep)

    try:
        for lvl in range(16):
            pw = _load(lvl)
            _log.info("[>] Level %02d", lvl)
            t0 = time.monotonic()

            try:
                nxt = solve(lvl, pw)
            except Exception as exc:
                if debug:
                    tb = _traceback.format_exc()
                    for p in list(_known_passwords.values()):
                        if p and len(p) >= 8:
                            tb = tb.replace(p, "<REDACTED>")
                    print(tb, file=sys.stderr)
                _log.error("[✗] Level %02d failed — %s", lvl, type(exc).__name__)
                sys.exit(1)

            _store(lvl + 1, nxt)
            _log.info("[✓] Level %02d → %02d solved (%.1fs)", lvl, lvl + 1,
                      time.monotonic() - t0)

            jitter = random.uniform(-CONNECT_JITTER / 2, CONNECT_JITTER)
            time.sleep(max(0.0, CONNECT_PAUSE + jitter))

    finally:
        _close_pw_file()

    _log.info(sep)
    _log.info("  All levels solved. Passwords → %s", PASSWORD_FILE)
    _log.info(sep)


if __name__ == "__main__":
    main()
