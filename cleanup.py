#!/usr/bin/env python3
"""
cleanup.py — Gauntlet System Cleanup Utility
=============================================
Resets the test environment to a known-good idle state:

  1. Kills any running gearbox.py instance (process-level).
  2. Kills any running Responder instance (process-level).
  3. Stops every running Nessus scan that Gearbox may have started.
  4. Reverts the test_direct Ethernet interface:
       • Kills dnsmasq bound to test_direct
       • Flushes any static IP address
       • Requests a fresh DHCP lease via dhclient / dhcpcd

Usable two ways:
  • Standalone CLI:  python3 cleanup.py
  • Flask endpoint:  imported by app.py → /api/system_cleanup
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Nessus credential helpers (self-contained — does not import gearbox)
# ---------------------------------------------------------------------------

_NESSUS_URL = "https://127.0.0.1:8834"


def _gearbox_config_dir() -> Path:
    """
    Return the ~/.config/gearbox directory for the *real* user even when
    cleanup.py is invoked under sudo (where Path.home() → /root).

    Priority:
      1. SUDO_USER env var  → /home/<sudo_user>/.config/gearbox
      2. HOME env var       → $HOME/.config/gearbox
      3. Path.home()        → fallback
    """
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user:
        candidate = Path(f"/home/{sudo_user}") / ".config" / "gearbox"
        if candidate.parent.parent.exists():
            return candidate
    home_env = os.environ.get("HOME", "").strip()
    if home_env:
        return Path(home_env) / ".config" / "gearbox"
    return Path.home() / ".config" / "gearbox"


def _load_nessus_creds() -> tuple[str, str]:
    """Return (username, password) from ~/.config/gearbox/config.yaml, or ('', '').
    Reads the same file and key as gearbox.py's NessusConfig.load().
    Works without PyYAML by falling back to a minimal line-by-line parser."""
    config_dir  = _gearbox_config_dir()
    config_file = config_dir / "config.yaml"

    if not config_file.exists():
        return "", ""

    raw_text = ""
    try:
        with open(config_file, encoding="utf-8") as f:
            raw_text = f.read()
    except Exception:
        return "", ""

    # Try PyYAML first
    try:
        import yaml  # type: ignore
        cfg    = yaml.safe_load(raw_text) or {}
        nessus = cfg.get("nessus", {})
        user   = nessus.get("username", "").strip()
        enc    = nessus.get("password_enc", "").strip()
    except Exception:
        # Fallback: parse the two keys we need with a simple regex
        # Handles standard "  key: value" YAML indentation
        user_m = re.search(r'^\s*username\s*:\s*(.+)$', raw_text, re.MULTILINE)
        enc_m  = re.search(r'^\s*password_enc\s*:\s*(.+)$', raw_text, re.MULTILINE)
        user   = user_m.group(1).strip().strip('"\'') if user_m else ""
        enc    = enc_m.group(1).strip().strip('"\'')  if enc_m  else ""

    if not user or not enc:
        return "", ""
    pwd = _decrypt(enc, config_dir)
    return (user, pwd) if pwd else ("", "")


def _get_nessus_key(config_dir: Path) -> bytes:
    """Read the Fernet key written by gearbox's NessusConfig._get_or_create_key().
    If the key file is absent, derives the same machine-based pseudo-key."""
    key_file = config_dir / ".nessus_key"
    if key_file.exists():
        return key_file.read_bytes().strip()
    # Mirror the deterministic fallback used by NessusConfig
    try:
        import base64, hashlib, platform
        home = str(config_dir.parent.parent)   # two levels up from .config/gearbox
        seed = platform.node() + home + "gearbox_nessus"
        raw  = hashlib.sha256(seed.encode()).digest()
        return base64.urlsafe_b64encode(raw)
    except Exception:
        return b""


def _decrypt(enc: str, config_dir: Path | None = None) -> str:
    """Decrypt a password stored by gearbox's NessusConfig.
    Handles both the b64: obfuscation prefix and Fernet-encrypted values.

    Fernet decryption tries, in order:
      1. cryptography.fernet.Fernet  (preferred — same package as gearbox)
      2. openssl subprocess           (fallback when cryptography not installed
                                       on the system Python running cleanup.py)
    """
    if config_dir is None:
        config_dir = _gearbox_config_dir()

    # Base64-obfuscated fallback (written when cryptography package is absent)
    if enc.startswith("b64:"):
        try:
            import base64
            return base64.b64decode(enc[4:]).decode()
        except Exception:
            return ""

    # ── Attempt 1: cryptography package (Fernet) ────────────────────────────
    try:
        from cryptography.fernet import Fernet  # type: ignore
        key = _get_nessus_key(config_dir)
        if key:
            return Fernet(key).decrypt(enc.encode()).decode()
    except ImportError:
        pass  # cryptography not available on this Python — fall through
    except Exception:
        return ""

    # ── Attempt 2: openssl subprocess (always present on Kali/Debian) ───────
    # Fernet token layout (after base64url-decode):
    #   [0x80][8-byte timestamp][16-byte IV][n-byte ciphertext (PKCS7)][32-byte HMAC]
    # Key layout (after base64url-decode of the 44-char key string):
    #   [16-byte HMAC key][16-byte AES-128-CBC key]
    try:
        import base64 as _b64
        import struct as _struct
        import tempfile as _tmp

        raw_key = _get_nessus_key(config_dir)
        if not raw_key:
            return ""

        key_bytes = _b64.urlsafe_b64decode(raw_key + b"==")
        tok_bytes = _b64.urlsafe_b64decode(enc + "==")

        if len(tok_bytes) < 57 or tok_bytes[0] != 0x80:
            return ""

        iv         = tok_bytes[9:25]           # bytes 9-24
        ciphertext = tok_bytes[25:-32]          # everything before 32-byte HMAC
        aes_key    = key_bytes[16:32]           # last 16 bytes of 32-byte key

        with _tmp.NamedTemporaryFile(delete=False) as tf:
            tf.write(ciphertext)
            tf_name = tf.name

        try:
            r = subprocess.run(
                ["openssl", "enc", "-d", "-aes-128-cbc", "-nosalt",
                 "-K", aes_key.hex(), "-iv", iv.hex(), "-in", tf_name],
                capture_output=True, timeout=5)
        finally:
            try:
                os.unlink(tf_name)
            except Exception:
                pass

        if r.returncode != 0:
            return ""

        data = r.stdout
        if not data:
            return ""
        # Remove PKCS7 padding
        pad = data[-1]
        if pad < 1 or pad > 16:
            return ""
        return data[:-pad].decode("utf-8")
    except Exception:
        return ""


class _NessusResponse:
    """Thin wrapper around urllib response so callers can use .status_code and .json()."""
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> Any:
        import json as _json
        return _json.loads(self._body.decode("utf-8", errors="replace"))


def _nessus_req(method: str, path: str, token: str = "",
                api_token: str = "", **kwargs) -> Any:
    """
    Single Nessus API request — uses requests if available, falls back to
    urllib (standard library, always present) so cleanup.py works regardless
    of which Python interpreter is running it.
    """
    import json as _json
    import ssl as _ssl
    import urllib.request as _ureq

    url = f"{_NESSUS_URL}{path}"
    headers = {"Connection": "close", "Content-Type": "application/json"}
    if token:
        headers["X-Cookie"] = f"token={token}"
    if api_token:
        headers["X-API-Token"] = api_token

    # Encode body from json= kwarg if present
    body: bytes | None = None
    json_data = kwargs.get("json")
    if json_data is not None:
        body = _json.dumps(json_data).encode("utf-8")

    # Try requests first (richer error handling, same interface as gearbox)
    try:
        import requests as _req   # type: ignore
        try:
            import urllib3 as _u3  # type: ignore
            _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        resp = _req.request(method, url, headers=headers, verify=False,
                            timeout=15, **kwargs)
        return resp
    except ImportError:
        pass
    except Exception:
        return None

    # Fall back to urllib (no third-party deps)
    try:
        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE

        req = _ureq.Request(url, data=body, headers=headers, method=method)
        timeout = kwargs.get("timeout", 15)
        with _ureq.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
            return _NessusResponse(resp.status, resp.read())
    except Exception:
        return None


def _nessus_api_token() -> str:
    """Fetch the X-API-Token from the Nessus JS bundle."""
    import ssl as _ssl
    import urllib.request as _ureq

    # Try requests first
    try:
        import requests as _req   # type: ignore
        try:
            import urllib3 as _u3  # type: ignore
            _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        resp = _req.get(f"{_NESSUS_URL}/nessus6.js", verify=False, timeout=10,
                        headers={"Connection": "close"})
        m = re.search(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            resp.text, re.I)
        if m:
            return m.group(0)
        return "4f9b6a3e-5c2d-4e1a-9f7b-3a8c6d2e1f05"
    except ImportError:
        pass
    except Exception:
        return "4f9b6a3e-5c2d-4e1a-9f7b-3a8c6d2e1f05"

    # urllib fallback
    try:
        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE
        req = _ureq.Request(f"{_NESSUS_URL}/nessus6.js",
                            headers={"Connection": "close"})
        with _ureq.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        m = re.search(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            text, re.I)
        if m:
            return m.group(0)
    except Exception:
        pass
    return "4f9b6a3e-5c2d-4e1a-9f7b-3a8c6d2e1f05"


# ---------------------------------------------------------------------------
# Individual cleanup actions
# ---------------------------------------------------------------------------

def kill_gearbox() -> dict:
    """Kill every running gearbox.py process on the system."""
    result = {"action": "kill_gearbox", "killed": [], "errors": []}

    for pattern in ("gearbox.py",):
        try:
            r = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True)
            pids = [int(p) for p in r.stdout.split() if p.strip().isdigit()]
            # Exclude our own PID in case cleanup.py is somehow matched
            our_pid = os.getpid()
            pids = [p for p in pids if p != our_pid]
            for pid in pids:
                try:
                    os.kill(pid, 15)   # SIGTERM
                    time.sleep(0.5)
                    try:
                        os.kill(pid, 9)    # SIGKILL if still alive
                    except ProcessLookupError:
                        pass
                    result["killed"].append(pid)
                except ProcessLookupError:
                    pass
                except Exception as e:
                    result["errors"].append(f"pid {pid}: {e}")
        except FileNotFoundError:
            try:
                subprocess.run(
                    ["pkill", "-9", "-f", pattern],
                    capture_output=True)
            except Exception as e:
                result["errors"].append(str(e))

    result["status"] = "ok" if not result["errors"] else "partial"
    if not result["killed"] and not result["errors"]:
        result["status"] = "ok"
        result["note"] = "No gearbox.py process found"
    return result


def kill_responder() -> dict:
    """Kill every running Responder process on the system."""
    result = {"action": "kill_responder", "killed": [], "errors": []}

    # Find Responder PIDs via pgrep (case-insensitive on name, also match path)
    for pattern in ("responder", "Responder"):
        try:
            r = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True)
            pids = [int(p) for p in r.stdout.split() if p.strip().isdigit()]
            for pid in pids:
                try:
                    os.kill(pid, 15)   # SIGTERM
                    time.sleep(0.5)
                    try:
                        os.kill(pid, 9)    # SIGKILL if still alive
                    except ProcessLookupError:
                        pass
                    result["killed"].append(pid)
                except ProcessLookupError:
                    pass
                except Exception as e:
                    result["errors"].append(f"pid {pid}: {e}")
        except FileNotFoundError:
            # pgrep not available — try pkill directly
            try:
                subprocess.run(
                    ["pkill", "-9", "-f", pattern],
                    capture_output=True)
            except Exception as e:
                result["errors"].append(str(e))

    result["status"] = "ok" if not result["errors"] else "partial"
    if not result["killed"] and not result["errors"]:
        result["status"] = "ok"
        result["note"] = "No Responder process found"
    return result


def stop_nessus_scans() -> dict:
    """Authenticate to Nessus and stop every currently running scan."""
    result = {"action": "stop_nessus_scans", "stopped": [], "errors": []}

    user, pwd = _load_nessus_creds()
    # Mirror every env var checked by app.py and gearbox.py
    if not user:
        for _k in ("nessus_user", "NESSUS_USER", "NESSUS_USERNAME"):
            user = os.environ.get(_k, "").strip()
            if user:
                break
    if not pwd:
        for _k in ("nessus_pass", "NESSUS_PASS", "nessus_password", "NESSUS_PASSWORD"):
            pwd = os.environ.get(_k, "").strip()
            if pwd:
                break
    if not user or not pwd:
        result["status"] = "skipped"
        result["note"] = "Nessus credentials not configured"
        return result

    api_token = _nessus_api_token()

    # Authenticate
    auth = _nessus_req("POST", "/session", api_token=api_token,
                       json={"username": user, "password": pwd})
    if not auth or auth.status_code not in (200, 201):
        result["status"] = "error"
        result["errors"].append(
            f"Nessus auth failed"
            + (f" (HTTP {auth.status_code})" if auth else " (unreachable)"))
        return result

    token = auth.json().get("token", "")
    if not token:
        result["status"] = "error"
        result["errors"].append("Nessus returned empty session token")
        return result

    # List all scans
    scans_resp = _nessus_req("GET", "/scans", token=token, api_token=api_token)
    if not scans_resp or scans_resp.status_code != 200:
        result["status"] = "error"
        result["errors"].append("Could not retrieve scan list from Nessus")
        return result

    scans = scans_resp.json().get("scans") or []
    running = [s for s in scans if s.get("status") in ("running", "pending")]

    for scan in running:
        scan_id = scan.get("id")
        name    = scan.get("name", str(scan_id))
        stop_r  = _nessus_req("POST", f"/scans/{scan_id}/stop",
                               token=token, api_token=api_token)
        if stop_r and stop_r.status_code in (200, 409):
            result["stopped"].append({"id": scan_id, "name": name})
        else:
            code = stop_r.status_code if stop_r else "no response"
            result["errors"].append(f"Scan '{name}' (id={scan_id}): HTTP {code}")

    # Destroy session
    _nessus_req("DELETE", "/session", token=token, api_token=api_token)

    result["status"] = "ok" if not result["errors"] else "partial"
    if not running:
        result["note"] = "No running Nessus scans found"
    return result


def revert_test_direct() -> dict:
    """
    Revert the test_direct interface to DHCP default:
      1. Kill dnsmasq processes bound to test_direct.
      2. Flush all IP addresses from the interface.
      3. Request a new DHCP lease.
    """
    result = {"action": "revert_test_direct", "steps": [], "errors": []}
    iface = "test_direct"

    # Check the interface exists
    check = subprocess.run(
        ["ip", "link", "show", iface],
        capture_output=True)
    if check.returncode != 0:
        result["status"] = "skipped"
        result["note"] = f"Interface '{iface}' not found on this system"
        return result

    # Kill dnsmasq processes bound to test_direct
    try:
        r = subprocess.run(
            ["pgrep", "-f", f"dnsmasq.*{iface}"],
            capture_output=True, text=True)
        pids = [int(p) for p in r.stdout.split() if p.strip().isdigit()]
        for pid in pids:
            try:
                os.kill(pid, 15)
                time.sleep(0.5)
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
            except Exception as e:
                result["errors"].append(f"dnsmasq pid {pid}: {e}")
        if pids:
            result["steps"].append(f"Killed dnsmasq pids: {pids}")
    except Exception as e:
        result["errors"].append(f"dnsmasq kill: {e}")

    # Flush all IP addresses from interface
    try:
        subprocess.run(
            ["ip", "addr", "flush", "dev", iface],
            capture_output=True, timeout=10, check=True)
        result["steps"].append(f"Flushed IP addresses from {iface}")
    except Exception as e:
        result["errors"].append(f"ip addr flush: {e}")

    # Bring the interface up in case it was left down
    try:
        subprocess.run(
            ["ip", "link", "set", iface, "up"],
            capture_output=True, timeout=5)
    except Exception:
        pass

    # Request a new DHCP lease
    dhcp_client = shutil.which("dhclient") or shutil.which("dhcpcd")
    if dhcp_client:
        client_name = Path(dhcp_client).name
        try:
            subprocess.run(
                [dhcp_client, iface],
                capture_output=True, timeout=30)
            result["steps"].append(
                f"DHCP lease requested via {client_name} on {iface}")
        except subprocess.TimeoutExpired:
            result["steps"].append(
                f"{client_name} timed out — interface may be awaiting a DHCP server")
        except Exception as e:
            result["errors"].append(f"{client_name}: {e}")
    else:
        result["errors"].append(
            "No DHCP client found (dhclient/dhcpcd) — "
            "interface flushed but no lease requested")

    result["status"] = "ok" if not result["errors"] else "partial"
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_cleanup() -> dict:
    """
    Run all three cleanup actions and return a combined result dict.
    Safe to call from Flask or from the CLI.
    """
    results = {
        "gearbox":      kill_gearbox(),
        "responder":    kill_responder(),
        "nessus":       stop_nessus_scans(),
        "test_direct":  revert_test_direct(),
    }
    overall = all(r.get("status") in ("ok", "skipped")
                  for r in results.values())
    results["overall_status"] = "ok" if overall else "partial"
    return results


def _require_sudo() -> None:
    """
    Ensure the process is running with root privileges.

    If already root (euid == 0), returns immediately.
    Otherwise, prompts for the sudo password with masked input, validates it
    via 'sudo -S -v', then re-executes this script under sudo and exits.
    The password is never stored or echoed.
    """
    import getpass
    import termios
    import tty

    if os.geteuid() == 0:
        return  # already root

    print("Gauntlet System Cleanup requires root privileges.")

    # Prompt with masked input (show '*' per character, handle backspace)
    def _masked_input(prompt: str) -> str:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        password = []
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                if ch in ("\x7f", "\x08"):   # backspace / DEL
                    if password:
                        password.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":           # Ctrl-C
                    sys.stdout.write("\n")
                    raise KeyboardInterrupt
                else:
                    password.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.stdout.write("\n")
        return "".join(password)

    try:
        password = _masked_input("Password: ")
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)

    # Validate password via sudo -S -v (refreshes timestamp, no command run)
    val = subprocess.run(
        ["sudo", "-S", "-v"],
        input=(password + "\n").encode(),
        capture_output=True,
    )
    if val.returncode != 0:
        print("Incorrect password or sudo not available.", file=sys.stderr)
        sys.exit(1)

    # Re-execute this script under sudo.
    # -E  preserves the current environment (PATH, nessus_user/pass, venv
    #     Python paths) — same flag app.py uses when it launches gearbox.
    # -S  reads the password from stdin.
    # Use shutil.which so the venv python3 (on PATH) is found, not the
    # bare system interpreter that lacks cryptography/pyyaml.
    script     = os.path.abspath(__file__)
    python_exe = shutil.which("python3") or sys.executable
    child = subprocess.run(
        ["sudo", "-E", "-S", python_exe, script] + sys.argv[1:],
        input=(password + "\n").encode(),
    )
    sys.exit(child.returncode)


def _debug_creds() -> None:
    """Print a step-by-step trace of credential discovery. Run with --debug-creds."""
    print("\n── Nessus credential debug ─────────────────────────────")

    # 1. Config directory resolution
    sudo_user = os.environ.get("SUDO_USER", "")
    home_env  = os.environ.get("HOME", "")
    print(f"  SUDO_USER  : {sudo_user!r}")
    print(f"  HOME       : {home_env!r}")
    print(f"  Path.home(): {Path.home()}")

    config_dir  = _gearbox_config_dir()
    config_file = config_dir / "config.yaml"
    key_file    = config_dir / ".nessus_key"
    print(f"  config_dir : {config_dir}")
    print(f"  config.yaml: {'EXISTS' if config_file.exists() else 'MISSING'}")
    print(f"  .nessus_key: {'EXISTS' if key_file.exists() else 'MISSING (will use pseudo-key)'}")

    if not config_file.exists():
        print("\n  ✗ config.yaml not found — no credentials to load")
        return

    # 2. YAML parsing
    try:
        raw = config_file.read_text(encoding="utf-8")
    except Exception as e:
        print(f"\n  ✗ Cannot read config.yaml: {e}")
        return

    print(f"\n  config.yaml contents ({len(raw)} bytes):")
    for line in raw.splitlines():
        # Mask the actual encrypted value but show the key name
        if "password_enc" in line:
            print(f"    {line.split(':')[0]}: <redacted ({len(line)} chars)>")
        else:
            print(f"    {line}")

    try:
        import yaml
        cfg    = yaml.safe_load(raw) or {}
        nessus = cfg.get("nessus", {})
        user   = nessus.get("username", "").strip()
        enc    = nessus.get("password_enc", "").strip()
        print("\n  Parsed via PyYAML")
    except ImportError:
        print("\n  PyYAML not available — using regex fallback")
        user_m = re.search(r'^\s*username\s*:\s*(.+)$', raw, re.MULTILINE)
        enc_m  = re.search(r'^\s*password_enc\s*:\s*(.+)$', raw, re.MULTILINE)
        user   = user_m.group(1).strip().strip('"\'') if user_m else ""
        enc    = enc_m.group(1).strip().strip('"\'')  if enc_m  else ""
    except Exception as e:
        print(f"\n  ✗ YAML parse error: {e}")
        return

    print(f"  username   : {user!r}")
    print(f"  password_enc: {'<present, ' + str(len(enc)) + ' chars>' if enc else '<EMPTY>'}")

    if not user or not enc:
        print("\n  ✗ username or password_enc missing from config.yaml")
        return

    # 3. Decryption
    print("\n  Attempting decryption …")
    if enc.startswith("b64:"):
        print("  Format: b64: prefix")
        try:
            import base64
            pwd = base64.b64decode(enc[4:]).decode()
            print(f"  ✓ b64 decoded successfully ({len(pwd)} chars)")
        except Exception as e:
            print(f"  ✗ b64 decode failed: {e}")
        return

    print("  Format: Fernet token")

    # Try cryptography
    try:
        from cryptography.fernet import Fernet  # type: ignore
        key = _get_nessus_key(config_dir)
        print(f"  cryptography available, key={'present' if key else 'EMPTY'}")
        if key:
            try:
                pwd = Fernet(key).decrypt(enc.encode()).decode()
                print(f"  ✓ Fernet decryption succeeded ({len(pwd)} chars)")
                return
            except Exception as e:
                print(f"  ✗ Fernet decryption failed: {e}")
    except ImportError:
        print("  cryptography not installed — trying openssl fallback")

    # Try openssl
    import base64 as _b64, tempfile as _tmp
    try:
        key_bytes = _get_nessus_key(config_dir)
        print(f"  Key bytes length: {len(key_bytes)}")
        raw_key   = _b64.urlsafe_b64decode(key_bytes + b"==")
        tok_bytes = _b64.urlsafe_b64decode(enc + "==")
        print(f"  Token length: {len(tok_bytes)} bytes, version byte: {hex(tok_bytes[0]) if tok_bytes else 'N/A'}")
        if len(tok_bytes) < 57 or tok_bytes[0] != 0x80:
            print(f"  ✗ Token format invalid (need >=57 bytes and version 0x80)")
            return
        iv         = tok_bytes[9:25]
        ciphertext = tok_bytes[25:-32]
        aes_key    = raw_key[16:32]
        print(f"  IV: {iv.hex()}")
        print(f"  Ciphertext: {len(ciphertext)} bytes")
        print(f"  AES key: {aes_key.hex()}")
        with _tmp.NamedTemporaryFile(delete=False) as tf:
            tf.write(ciphertext)
            tf_name = tf.name
        try:
            r = subprocess.run(
                ["openssl", "enc", "-d", "-aes-128-cbc", "-nosalt",
                 "-K", aes_key.hex(), "-iv", iv.hex(), "-in", tf_name],
                capture_output=True, timeout=5)
        finally:
            try: os.unlink(tf_name)
            except Exception: pass
        print(f"  openssl returncode: {r.returncode}")
        if r.stderr.strip():
            print(f"  openssl stderr: {r.stderr.decode(errors='replace').strip()}")
        if r.returncode == 0 and r.stdout:
            pad = r.stdout[-1]
            pwd = r.stdout[:-pad].decode("utf-8")
            print(f"  ✓ openssl decryption succeeded ({len(pwd)} chars)")
        else:
            print("  ✗ openssl decryption failed")
    except Exception as e:
        print(f"  ✗ openssl path error: {e}")

    print("\n── end debug ───────────────────────────────────────────\n")


if __name__ == "__main__":
    if "--debug-creds" in sys.argv:
        _debug_creds()
        sys.exit(0)
    _require_sudo()
    print("Gauntlet System Cleanup\n" + "=" * 40)
    output = run_cleanup()
    for key, res in output.items():
        if key == "overall_status":
            continue
        status = res.get("status", "?")
        note   = res.get("note", "")
        print(f"\n[{key}]  status={status}"
              + (f"  — {note}" if note else ""))
        for step in res.get("steps", []):
            print(f"  ✓ {step}")
        for err in res.get("errors", []):
            print(f"  ✗ {err}", file=sys.stderr)
        for item in res.get("killed", []):
            print(f"  ✓ killed pid {item}")
        for item in res.get("stopped", []):
            print(f"  ✓ stopped scan '{item['name']}' (id={item['id']})")
    print(f"\nOverall: {output['overall_status']}")
