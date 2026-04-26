# bandit-auto

> Automated solver for [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) levels 0 → 15.  
> Built for learning, auditing, and reference — not a shortcut, a dissection.

```
  [>] Level 00  [✓] Level 00 → 01 solved (1.3s)
  [>] Level 01  [✓] Level 01 → 02 solved (0.9s)
  ...
  [>] Level 14  [✓] Level 14 → 15 solved (4.1s)
  All levels solved. Passwords → bandit_passwords.txt
```

---

## Features

| Capability | Detail |
|---|---|
| **Full level coverage** | Levels 0–15, one uninterrupted run |
| **Hardened file I/O** | `O_NOFOLLOW \| O_CLOEXEC \| O_CREAT \| O_TRUNC`, mode `0600`, `fcntl LOCK_EX` |
| **Log redaction** | All discovered passwords scrubbed from every log line before emission |
| **Tar-Slip protection** | `realpath` check on every archive member before `extractall` |
| **MITM protection** | `RejectPolicy` + pre-scanned `bandit_known_hosts`; symlink guard on the file itself |
| **Two-pass regex** | Exact 32-char match → longest 20-64 char fallback (future-proof against OTW format changes) |
| **IDS jitter** | Randomised inter-level sleep prevents timing-pattern detection |
| **Multi-strategy level 13** | Strategy A (direct external key auth) → B (nested Transport) → C (remote ssh binary) |
| **TLS level 15** | `{ printf; sleep 3; }` pipe group prevents premature `close_notify` before server responds |
| **64 KiB output cap** | Hard limit on raw bytes before any regex or string operation |
| **Environment-driven config** | Zero hard-coded tunables; everything overridable via `.env` or shell exports |

---

## Architecture

```
bandit_auto.py
│
├── Configuration layer
│   └── os.environ → HOST, PORT, timeouts, paths (python-dotenv optional)
│
├── Security primitives
│   ├── _RedactFilter      — scrub passwords from log records
│   ├── _check_known_hosts — lstat() symlink guard
│   ├── _secure_tmpdir()   — urandom wipe + rmtree context manager
│   └── _safe_tar_extract  — Tar-Slip via realpath boundary check
│
├── SSH transport layer
│   ├── _connect()         — paramiko SSHClient, RejectPolicy when known_hosts present
│   ├── _exec()            — deadlock-safe stdout/stderr drain, exit-status at DEBUG
│   ├── _tcp_send_recv()   — direct-tcpip channel with chunked recv + timeout
│   └── _ChannelSocket     — socket shim for nested paramiko.Transport (fileno fix)
│
├── Level solvers
│   ├── _CMD dict          — levels 0–11: pure shell one-liners
│   ├── _solve_level12()   — remote Python stdin pipe: xxd → gzip/bzip2/tar loop
│   ├── _solve_level13()   — PEM normalisation + 3-strategy SSH key auth
│   ├── _solve_level14()   — direct-tcpip to :30000
│   └── _solve_level15()   — openssl s_client TLS to :30001, pipe-hold fix
│
└── Dispatcher / main()
    ├── solve(level, pw)   — route to solver, guarantee client.close()
    └── main()             — sequential run, jitter, fsync password store
```

---

## Installation

**Prerequisites:** Python ≥ 3.10, `pip`, network access to `bandit.labs.overthewire.org:2220`.

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/bandit-auto.git
cd bandit-auto

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pre-scan host keys  ← required for MITM protection
ssh-keyscan -p 2220 bandit.labs.overthewire.org > bandit_known_hosts

# 4. Configure (optional — defaults are correct for OTW)
cp .env.example .env
```

---

## Usage

```bash
# Normal run
python3 bandit_auto.py

# Verbose debug output (redacted tracebacks, per-level timings)
python3 bandit_auto.py --debug
```

On success, passwords are written to `bandit_passwords.txt` (mode `0600`, exclusively file-locked to prevent concurrent runs):

```
bandit00: bandit0
bandit01: <REDACTED>
bandit02: <REDACTED>
...
bandit15: <REDACTED>
```

### Environment overrides

All tunables can be set in `.env` or exported before running:

| Variable | Default | Purpose |
|---|---|---|
| `BANDIT_HOST` | `bandit.labs.overthewire.org` | SSH target hostname |
| `BANDIT_PORT` | `2220` | SSH target port |
| `BANDIT_CONNECT_TIMEOUT` | `15` | TCP + handshake timeout (s) |
| `BANDIT_EXEC_TIMEOUT` | `30` | Remote command timeout (s) |
| `BANDIT_CONNECT_PAUSE` | `2.0` | Base sleep between levels (s) |
| `BANDIT_CONNECT_JITTER` | `1.0` | Jitter range added to pause (s) |
| `BANDIT_PASSWORD_FILE` | `bandit_passwords.txt` | Output file path |
| `BANDIT_KNOWN_HOSTS` | `./bandit_known_hosts` | Pre-scanned host keys path |

---

## Security Notes

This tool connects to a public, intentionally vulnerable wargame server. Several design decisions reflect real-world operational security practices:

**What is protected:**

- **Passwords in logs** — `_RedactFilter` materialises and scrubs every log record. Exception messages are never logged (only `type(exc).__name__`), preventing raw command output from leaking into stderr.
- **Password file on disk** — opened with `O_NOFOLLOW` (blocks symlink swap attacks), `O_CLOEXEC` (not inherited by child processes), and exclusively `flock`'d (single-instance guard). Contents are `fsync`'d on every write.
- **Host keys** — `RejectPolicy` refuses any host not in `bandit_known_hosts`. The known-hosts file itself is validated with `lstat()` to block symlink substitution.
- **Temporary files** — overwritten with `os.urandom` before `rmtree`. Symlinks inside extracted archives are skipped (Tar-Slip mitigation).
- **Shell injection** — the level-15 password is stripped to `[A-Za-z0-9]` before interpolation into the shell command.
- **Key material** — the SSH private key from level 13 is parsed in memory (`io.StringIO`); never written to a local file.

**What is explicitly out of scope:**

This is a CTF automation tool targeting a public training server. It is not designed for use against production systems. The level-13 Strategy C (`ssh -o StrictHostKeyChecking=no`) is a deliberate fallback for the wargame environment and should never be used against real infrastructure.

---

## License

[MIT](LICENSE)
