# bandit-auto

> Automated solver for [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) levels 0 → 15.  
> Built for **learning, auditing, and reference** — not a shortcut, a dissection.

```
  [>] Level 00  [✓] Level 00 → 01 solved (1.3s)
  [>] Level 01  [✓] Level 01 → 02 solved (0.9s)
  ...
  [>] Level 14  [✓] Level 14 → 15 solved (4.1s)
  All levels solved. Passwords → bandit_passwords.txt
```

---

## Requirements

- Python **≥ 3.10**
- `pip install paramiko python-dotenv`
- Network access to `bandit.labs.overthewire.org:2220`

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/sente-ns/bandit-auto.git
cd bandit-auto

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pre-scan host keys  ← required for MITM protection
ssh-keyscan -p 2220 bandit.labs.overthewire.org > bandit_known_hosts

# 4. (Optional) configure overrides
cp .env.example .env   # edit if needed

# 5. Run
python3 bandit_auto.py
```

> **Without `bandit_known_hosts`** the tool falls back to `AutoAddPolicy` and logs a warning.  
> MITM protection is disabled until you run the `ssh-keyscan` step.

---

## Usage

```bash
# Normal run — passwords written to bandit_passwords.txt
python3 bandit_auto.py

# Verbose mode — redacted tracebacks + per-level timings on stderr
python3 bandit_auto.py --debug
```

On success, `bandit_passwords.txt` (mode `0600`, exclusively locked) contains:

```
bandit00: bandit0
bandit01: <password>
bandit02: <password>
...
bandit15: <password>
```

---

## Configuration

All tunables are read from environment variables (or `.env`). No secrets are hard-coded.

### Connection

| Variable | Default | Description |
|---|---|---|
| `BANDIT_HOST` | `bandit.labs.overthewire.org` | SSH target hostname |
| `BANDIT_PORT` | `2220` | SSH target port |
| `BANDIT_CONNECT_TIMEOUT` | `15` | TCP + handshake timeout (s) |
| `BANDIT_EXEC_TIMEOUT` | `30` | Remote command timeout (s) |

### Pacing & jitter

| Variable | Default | Description |
|---|---|---|
| `BANDIT_CONNECT_PAUSE` | `2.0` | Base sleep between levels (s) |
| `BANDIT_CONNECT_JITTER` | `1.0` | Random ± offset added to pause (s) |

### Retry / backoff

OTW Bandit throttles rapid SSH connections at the banner phase.  
The retry system handles `SSHException`, `socket.error`, `EOFError`, and `OSError` with exponential backoff. Each failed attempt closes the underlying socket immediately — no GC-deferred leak.

| Variable | Default | Description |
|---|---|---|
| `BANDIT_MAX_RETRIES` | `4` | Total connection attempts before giving up |
| `BANDIT_RETRY_BACKOFF` | `3.0` | Backoff base in seconds (`base × 2^(attempt−1)`) |
| `BANDIT_RETRY_WAIT_CAP` | `30.0` | Per-sleep ceiling in seconds |

Retry schedule with defaults (jitter excluded):

```
Attempt 1 — immediate
Attempt 2 — ~3 s   (3.0 × 2^0)
Attempt 3 — ~6 s   (3.0 × 2^1)
Attempt 4 — ~12 s  (3.0 × 2^2)
```

### Paths

| Variable | Default | Description |
|---|---|---|
| `BANDIT_PASSWORD_FILE` | `bandit_passwords.txt` | Output file path |
| `BANDIT_KNOWN_HOSTS` | `./bandit_known_hosts` | Pre-scanned host keys |

---

## Architecture

```
bandit_auto.py
│
├── Configuration layer
│   └── os.environ → HOST, PORT, timeouts, retry params, paths
│       (python-dotenv optional — falls back to shell environment)
│
├── Security primitives
│   ├── _RedactFilter       scrub all known passwords from every log record
│   ├── _check_known_hosts  lstat() guard — blocks symlink substitution attacks
│   ├── _secure_tmpdir()    urandom wipe + version-safe rmtree context manager
│   └── _safe_tar_extract   realpath boundary check on every archive member
│
├── SSH transport layer
│   ├── _build_client()     SSHClient factory — host-key policy in one place
│   ├── _connect()          exponential backoff retry; socket closed on each failure
│   ├── _exec()             deadlock-safe stdout/stderr drain; exit-status at DEBUG
│   ├── _tcp_send_recv()    direct-tcpip channel with chunked recv + timeout
│   └── _ChannelSocket      socket shim for nested paramiko.Transport (fileno fix)
│
├── Level solvers
│   ├── _CMD dict           levels 0–11: pure shell one-liners
│   ├── _solve_level12()    remote Python via stdin pipe: xxd → gzip/bzip2/tar loop
│   ├── _solve_level13()    PEM normalisation + 3-strategy SSH key auth
│   ├── _solve_level14()    direct-tcpip to :30000
│   └── _solve_level15()    openssl s_client TLS to :30001 with pipe-hold fix
│
└── Dispatcher / main()
    ├── solve(level, pw)    route to solver; guarantee client.close()
    └── main()              sequential run, jitter sleep, fsync password store
```

---

## Level Solver Reference

| Level | Technique | Notes |
|---|---|---|
| 0 | `cat ~/readme` | Seed credential: `bandit0` |
| 1 | `cat ./-` | Dashed filename — explicit path |
| 2 | `find` + glob | Spaces in filename |
| 3 | `find -name '.*'` | Hidden file in subdirectory |
| 4 | `file` + `grep ASCII` | Only human-readable file among binaries |
| 5 | `find -readable ! -executable -size 1033c` | Attribute-filtered search |
| 6 | `find / -user bandit7 -group bandit6 -size 33c` | Filesystem-wide search |
| 7 | `grep millionth` + `awk` | Word after keyword in large file |
| 8 | `sort \| uniq -u` | Only line appearing once |
| 9 | `strings \| grep ===` | Printable strings near `=` separators |
| 10 | `base64 -d` | Base64 encoded data |
| 11 | `tr ROT13` | ROT13 substitution cipher |
| 12 | Remote Python pipe | Recursive decompression: xxd → gzip / bzip2 / tar |
| 13 | SSH private key auth | Strategy A → B → C (see below) |
| 14 | TCP :30000 | Send password over direct-tcpip channel |
| 15 | TLS :30001 | `openssl s_client` with pipe-hold group |

### Level 13 — multi-strategy key auth

The SSH private key is at `/home/bandit13/sshkey.private`. Three strategies are attempted in order:

**Strategy A** — direct external paramiko connection *(primary)*  
Opens a second `SSHClient` directly to `HOST:PORT` as `bandit14`.  
Source IP = this machine's external address; server-side loopback restriction does not apply.

**Strategy B** — paramiko nested Transport via `_ChannelSocket` *(fallback)*  
Tunnels a second SSH session over a `direct-tcpip` channel from the existing connection. `_ChannelSocket.fileno()` raises `io.UnsupportedOperation` to force paramiko into thread-based I/O — required because `Channel.fileno()` returns `-1` on paramiko ≥ 3.x, which causes `select()` to fail with `EBADF`.

**Strategy C** — remote `ssh` binary *(last resort)*  
Invokes `ssh bandit14@localhost` on the remote host. Key is written to a `chmod 600` tmpfile; `LogLevel=ERROR` suppresses diagnostic noise. Marked explicitly out-of-scope for non-CTF use.

---

## Security Hardening Summary

| Concern | Measure |
|---|---|
| Password leaks in logs | `_RedactFilter` materialises `%`-args and scrubs all known passwords (≥ 8 chars) before any handler sees the record |
| Exception messages | Only `type(exc).__name__` reaches the log — raw command output never does |
| Password file on disk | `O_NOFOLLOW \| O_CLOEXEC \| O_CREAT \| O_TRUNC`, mode `0600`, `fcntl LOCK_EX` (single-instance guard), `fsync` on every write |
| Host-key trust | `RejectPolicy` + pre-scanned `bandit_known_hosts`; `lstat()` symlink guard on the file itself; policy lives in `_build_client()` — no drift between code paths |
| Tar-Slip (CVE-2007-4559) | `realpath` boundary check on every archive member before `extractall`; `filter='data'` enforced on Python ≥ 3.12 for defence-in-depth |
| Shell injection (level 15) | Password stripped to `[A-Za-z0-9]` before interpolation |
| Temp file contents | Overwritten with `os.urandom` before `rmtree`; symlinks inside archives are skipped during wipe |
| Key material | SSH private key from level 13 parsed in memory via `io.StringIO` — never written to a local file |
| Socket leaks | Each failed `_connect()` attempt calls `client.close()` before sleeping — socket released immediately, not deferred to GC |
| fd inheritance | `O_CLOEXEC` — password file fd not inherited by child processes |
| IDS timing detection | `CONNECT_PAUSE ± random jitter` between levels |
| Output safety | Hard 65 536-byte cap on raw bytes before any regex or string operation |
| PEM line endings | `splitlines()` + LF-join normalises any `\r\n / \r / \n` mix before key parsing |

### Explicitly out of scope

This tool targets a public, intentionally vulnerable wargame server.  
Strategy C (`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`) is a deliberate CTF fallback.  
**Never use it against real infrastructure.**

---

## Changelog

| Version | Summary |
|---|---|
| **v6.3** | Retry with exponential backoff in `_connect()`; socket-leak fix on retry; `_build_client()` factory eliminates host-key policy drift; new env vars `BANDIT_MAX_RETRIES`, `BANDIT_RETRY_BACKOFF`, `BANDIT_RETRY_WAIT_CAP` |
| v6.2 | Python 3.12+ compat: `rmtree(onexc=)`, `tarfile filter='data'`, resource-leak fixes, O(n²) chunk realloc fix |
| v6.1 | Fix `_solve_level15` empty output — `{ printf; sleep 3; }` pipe-hold prevents premature `close_notify` |
| v6.0 | Fix `_solve_level13` `AuthenticationException` — `_ChannelSocket.fileno()`, PEM line-ending normalisation, Strategy C hardening |

---

## License

[MIT](LICENSE)
