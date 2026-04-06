#!/usr/bin/env python3
"""
install.py — Gearbox installer
================================
Installs all Python packages and system/external tools required by gearbox.py.

Platform handling:
  Linux (Debian/Ubuntu/Kali) — apt-get for system tools
  macOS                      — Homebrew for system tools
  Both platforms             — go install for Go-based tools, git clone for
                               GitHub-only tools, pip for Python packages

GitHub-based tools are cloned to /opt/<toolname>/.

Usage:
  python3 install.py [--skip-pip] [--skip-system] [--skip-go] [--skip-git]
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"

_SYSTEM = platform.system()
_IS_KALI = False
if _SYSTEM == "Linux":
    try:
        with open("/etc/os-release") as _f:
            _IS_KALI = "kali" in _f.read().lower()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Python packages
# ---------------------------------------------------------------------------
_PIP_PACKAGES = [
    # (pip_spec, import_name, required, description)
    ("pyyaml>=6.0.1",       "yaml",        True,  "YAML project config parsing — PyYAML team (https://pyyaml.org)"),
    ("requests>=2.31.0",    "requests",    False, "Nessus REST API + NVD/OSV CVE lookups — Python Requests (https://docs.python-requests.org)"),
    ("qrcode[pil]>=7.4.2",  "qrcode",      False, "QR code generation for photo upload prompts — Lincoln Loop (https://github.com/lincolnloop/python-qrcode)"),
    ("Pillow>=10.0.0",      "PIL",         False, "Image processing required by qrcode[pil] — Pillow contributors (https://github.com/python-pillow/Pillow)"),
    ("pyserial>=3.5",       "serial",      False, "DB9 serial port auto-detection — Chris Liechti (https://github.com/pyserial/pyserial)"),
    ("cryptography>=41.0.0","cryptography",False, "Fernet encryption for Nessus credentials — PyCA team (https://cryptography.io)"),
]

# ---------------------------------------------------------------------------
# System tool definitions
# ---------------------------------------------------------------------------
# Each dict:
#   bin          — executable to look for on PATH
#   apt          — apt-get package name (Linux)
#   kali_apt     — override apt name on Kali (None = not in Kali apt)
#   brew         — Homebrew formula name (macOS, None = not available)
#   go_pkg       — 'go install' package spec (None = not Go-based)
#   git_repo     — GitHub URL for git-clone fallback (None = not git-based)
#   git_dest     — clone destination under /opt/ (e.g. "testssl.sh")
#   required     — bool
#   description  — human-readable purpose
# ---------------------------------------------------------------------------
_SYSTEM_TOOLS = [
    {
        "bin": "nmap", "apt": "nmap", "kali_apt": "nmap", "brew": "nmap",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": True,
        "description": "Host discovery + port scanning — Gordon Lyon @Fyodor (https://nmap.org)",
    },
    {
        "bin": "tcpdump", "apt": "tcpdump", "kali_apt": "tcpdump", "brew": "tcpdump",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": True,
        "description": "Packet capture — tcpdump / libpcap team (https://www.tcpdump.org)",
    },
    {
        "bin": "ethtool", "apt": "ethtool", "kali_apt": "ethtool", "brew": None,
        "go_pkg": None,
        "git_repo": "https://github.com/sigma-1/ethtool.git", "git_dest": "ethtool",
        "required": True,
        "description": "Ethernet link-status detection — kernel.org / sigma-1 (https://github.com/sigma-1/ethtool)",
    },
    {
        "bin": "sslscan", "apt": "sslscan", "kali_apt": "sslscan", "brew": "sslscan",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "TLS cipher + certificate analysis — rbsec (https://github.com/rbsec/sslscan)",
    },
    {
        "bin": "testssl.sh", "apt": None, "kali_apt": "testssl.sh", "brew": "testssl",
        "go_pkg": None,
        "git_repo": "https://github.com/drwetter/testssl.sh.git", "git_dest": "testssl.sh",
        "required": False,
        "description": "Comprehensive TLS testing — Dirk Wetter @drwetter (https://github.com/drwetter/testssl.sh)",
    },
    {
        "bin": "nuclei", "apt": None, "kali_apt": "nuclei", "brew": "nuclei",
        "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "git_repo": None, "git_dest": None, "required": False,
        "description": "Template-based CVE scanning — ProjectDiscovery @projectdiscovery (https://github.com/projectdiscovery/nuclei)",
    },
    {
        "bin": "gowitness", "apt": "gowitness", "kali_apt": "gowitness", "brew": None,
        "go_pkg": "github.com/sensepost/gowitness/v3/cmd/gowitness@latest",
        "git_repo": None, "git_dest": None, "required": False,
        "description": "Web screenshots — SensePost @sensepost (https://github.com/sensepost/gowitness)",
    },
    {
        "bin": "ssh-audit", "apt": "ssh-audit", "kali_apt": "ssh-audit", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "SSH algorithm enumeration — Joe Testa @jtesta (https://github.com/jtesta/ssh-audit)",
    },
    {
        "bin": "responder", "apt": "responder", "kali_apt": "responder", "brew": None,
        "go_pkg": None,
        "git_repo": "https://github.com/lgandx/Responder.git", "git_dest": "Responder",
        "required": False,
        "description": "LLMNR/NBT-NS credential capture — Laurent Gaffie @lgandx (https://github.com/lgandx/Responder)",
    },
    {
        "bin": "smbmap", "apt": "smbmap", "kali_apt": "smbmap", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "SMB share enumeration — ShawnDEvans (https://github.com/ShawnDEvans/smbmap)",
    },
    {
        "bin": "dnsmasq", "apt": "dnsmasq", "kali_apt": "dnsmasq", "brew": "dnsmasq",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "DHCP server for test interface — Simon Kelley (https://www.thekelleys.org.uk/dnsmasq)",
    },
    {
        "bin": "curl", "apt": "curl", "kali_apt": "curl", "brew": "curl",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "HTTP client — Daniel Stenberg @bagder (https://curl.se)",
    },
    {
        "bin": "openssl", "apt": "openssl", "kali_apt": "openssl", "brew": "openssl",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "TLS certificate inspection — OpenSSL project (https://openssl.org)",
    },
    {
        "bin": "cec-client", "apt": "cec-utils", "kali_apt": "cec-utils", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "HDMI CEC command testing — Pulse-Eight (https://github.com/Pulse-Eight/libcec)",
    },
    {
        "bin": "ddcutil", "apt": "ddcutil", "kali_apt": "ddcutil", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "DDC-CI HDMI monitor control — Sanford Rockowitz (https://www.ddcutil.com)",
    },
    {
        "bin": "get-edid", "apt": "read-edid", "kali_apt": "read-edid", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "HDMI EDID reading — Matthew Kern (https://github.com/groeck/read-edid)",
    },
    {
        "bin": "edid-decode", "apt": "edid-decode", "kali_apt": "edid-decode", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "EDID data decoding — Hans Verkuil (https://git.linuxtv.org/edid-decode.git)",
    },
    {
        "bin": "candump", "apt": "can-utils", "kali_apt": "can-utils", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "CAN bus frame capture — SocketCAN / can-utils team (https://github.com/linux-can/can-utils)",
    },
    {
        "bin": "minicom", "apt": "minicom", "kali_apt": "minicom", "brew": "minicom",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "Serial terminal emulator — Miquel van Smoorenburg / Adam Lackorzynski",
    },
    {
        "bin": "pm3", "apt": None, "kali_apt": "proxmark3", "brew": None,
        "go_pkg": None,
        "git_repo": "https://github.com/RfidResearchGroup/proxmark3.git", "git_dest": "proxmark3",
        "required": False,
        "description": "Proxmark3 RFID/NFC tool — RfidResearchGroup (https://github.com/RfidResearchGroup/proxmark3)",
    },
    {
        "bin": "git", "apt": "git", "kali_apt": "git", "brew": "git",
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "Version control (required for git-based tool installs)",
    },
    {
        "bin": "shcheck.py", "apt": None, "kali_apt": None, "brew": None,
        "go_pkg": None,
        "git_repo": "https://github.com/santoru/shcheck.git", "git_dest": "shcheck",
        "required": False,
        "description": "HTTP security header checker — santoru (https://github.com/santoru/shcheck)",
    },
    {
        "bin": "lsusb", "apt": "usbutils", "kali_apt": "usbutils", "brew": None,
        "go_pkg": None, "git_repo": None, "git_dest": None, "required": False,
        "description": "USB device enumeration (Linux only) — usbutils team",
    },
]

_OPT_DIR = Path("/opt")


def _banner() -> None:
    print("=" * 60)
    print(f"  Gearbox {VERSION} — Installer")
    print("  Device Security Assessment Orchestrator")
    print("=" * 60)
    print()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Gearbox dependency installer")
    p.add_argument("--skip-pip",    action="store_true", help="Skip Python pip installs")
    p.add_argument("--skip-system", action="store_true", help="Skip system package installs (apt/brew)")
    p.add_argument("--skip-go",     action="store_true", help="Skip Go-based tool installs")
    p.add_argument("--skip-git",    action="store_true", help="Skip git-clone based tool installs")
    return p.parse_args()


def _check_python() -> None:
    print("[*] Checking Python version...")
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 9):
        print(f"[!] Python 3.9+ required; found {major}.{minor}. Please upgrade.")
        sys.exit(1)
    print(f"    Python {major}.{minor} — OK")
    print()


def _install_pip(skip: bool) -> None:
    if skip:
        print("[*] Skipping pip installs (--skip-pip).")
        print()
        return

    print("[*] Installing Python packages...")
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if os.path.exists(req_file):
        print(f"    Using: {req_file}")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", req_file],
            capture_output=False,
        )
        if result.returncode != 0:
            print("[!] pip install returned non-zero. Check output above.")
    else:
        for pkg_spec, import_name, required, description in _PIP_PACKAGES:
            label = pkg_spec.split(">=")[0].split("==")[0]
            marker = "[required]" if required else "[optional]"
            print(f"    {marker}  {label}  — {description.split(' — ')[0]}")
            subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", pkg_spec], check=False)
    print()


def _ensure_go() -> bool:
    """Return True if 'go' is available on PATH (install it if missing on Linux)."""
    if shutil.which("go"):
        return True
    print("[*] Go toolchain not found. Attempting to install...")
    if _SYSTEM == "Linux":
        if shutil.which("apt-get"):
            subprocess.run(["sudo", "apt-get", "install", "-y", "golang-go"], check=False)
        return bool(shutil.which("go"))
    elif _SYSTEM == "Darwin":
        if shutil.which("brew"):
            _brew_user = os.environ.get("SUDO_USER", "")
            _brew_pfx  = ["sudo", "-u", _brew_user] if _brew_user and _brew_user != "root" else []
            subprocess.run(_brew_pfx + ["brew", "install", "go"], check=False)
        return bool(shutil.which("go"))
    return False


def _git_clone_to_opt(repo_url: str, dest_name: str) -> bool:
    """Clone repo to /opt/<dest_name> if not already present."""
    dest = _OPT_DIR / dest_name
    if dest.exists():
        print(f"    [EXISTS]  /opt/{dest_name} — skipping clone")
        return True
    print(f"    Cloning {repo_url} → /opt/{dest_name}")
    result = subprocess.run(
        ["sudo", "git", "clone", "--depth", "1", repo_url, str(dest)],
        capture_output=False,
    )
    return result.returncode == 0


def _install_system_tools(skip_system: bool, skip_go: bool, skip_git: bool) -> None:
    print("[*] Checking / installing system tools...")
    missing_apt:  list[str] = []
    missing_brew: list[str] = []

    for tool in _SYSTEM_TOOLS:
        bin_name = tool["bin"]
        found    = bool(shutil.which(bin_name))
        label    = "[OK]" if found else ("[required]" if tool["required"] else "[optional]")
        print(f"    {label:<12} {bin_name:<20}  {tool['description'].split(' — ')[0]}")

        if found:
            continue

        # Determine install strategy
        if _SYSTEM == "Linux" and not skip_system:
            apt_name = tool.get("kali_apt") if _IS_KALI else tool.get("apt")
            if apt_name:
                missing_apt.append(apt_name)

        elif _SYSTEM == "Darwin" and not skip_system:
            brew_name = tool.get("brew")
            if brew_name:
                missing_brew.append(brew_name)

        # Go install
        if not found and tool.get("go_pkg") and not skip_go:
            if _ensure_go():
                print(f"    [go install] {tool['go_pkg']}")
                env = os.environ.copy()
                env["PATH"] = env.get("PATH", "") + ":" + str(Path.home() / "go" / "bin")
                subprocess.run(["go", "install", tool["go_pkg"]], env=env, check=False)

        # Git clone fallback
        if not found and tool.get("git_repo") and not skip_git:
            if shutil.which("git"):
                _git_clone_to_opt(tool["git_repo"], tool["git_dest"])
            else:
                print(f"    [!] git not found — cannot clone {tool['git_repo']}")

    print()

    # Batch install system packages
    if missing_apt and not skip_system:
        unique_apt = list(dict.fromkeys(missing_apt))
        print(f"[*] Installing {len(unique_apt)} apt package(s)...")
        subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
        subprocess.run(
            ["sudo", "apt-get", "install", "-y"] + unique_apt,
            capture_output=False,
        )
        print()

    if missing_brew and not skip_system:
        if shutil.which("brew"):
            unique_brew = list(dict.fromkeys(missing_brew))
            print(f"[*] Installing {len(unique_brew)} Homebrew package(s)...")
            _brew_user = os.environ.get("SUDO_USER", "")
            _brew_pfx  = ["sudo", "-u", _brew_user] if _brew_user and _brew_user != "root" else []
            for pkg in unique_brew:
                subprocess.run(_brew_pfx + ["brew", "install", pkg], check=False)
            print()
        else:
            print("[!] Homebrew not found. Install from https://brew.sh then re-run.")
            print()


def _verify() -> None:
    print("[*] Verification summary...")
    import importlib
    for pkg_spec, import_name, required, description in _PIP_PACKAGES:
        label = pkg_spec.split(">=")[0]
        try:
            importlib.import_module(import_name)
            print(f"    [OK]  {label}")
        except ImportError:
            marker = "[MISSING]" if required else "[OK-optional-missing]"
            print(f"    {marker}  {label}")

    print()
    for tool in _SYSTEM_TOOLS:
        if shutil.which(tool["bin"]):
            print(f"    [OK]  {tool['bin']}")
        else:
            marker = "[MISSING]" if tool["required"] else "[--]"
            print(f"    {marker}  {tool['bin']} (optional)" if not tool["required"] else f"    {marker}  {tool['bin']}")
    print()


def _install_symlinks() -> None:
    """Create /usr/local/bin symlinks for all-user access (including root)."""
    from pathlib import Path as _Path
    import stat as _stat
    app_dir = _Path(__file__).parent.resolve()
    bin_dir = _Path("/usr/local/bin")

    # (script_relative_to_app_dir, symlink_name_in_bin_dir)
    LINKS = [
        ("gearbox.py", "gearbox"),
    ]

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("[!] Cannot access /usr/local/bin — run as root to install symlinks.")
        return

    for script_rel, link_name in LINKS:
        script = app_dir / script_rel
        link   = bin_dir / link_name
        if not script.exists():
            print(f"[~] Script not found, skipping symlink: {script}")
            continue
        # Make script executable
        current = script.stat().st_mode
        script.chmod(current | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
        # Ensure shebang
        try:
            text = script.read_text(encoding="utf-8", errors="ignore")
            if not text.startswith("#!"):
                script.write_text("#!/usr/bin/env python3\n" + text, encoding="utf-8")
        except Exception:
            pass
        # Create/replace symlink
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(script)
        print(f"[+] Symlink installed: {link}  →  {script}")


def main() -> None:
    _banner()
    args = _parse_args()
    _check_python()
    _install_pip(args.skip_pip)
    _install_system_tools(args.skip_system, args.skip_go, args.skip_git)
    _verify()
    _install_symlinks()
    print("[+] Gearbox installation complete.")
    print("    Run:  sudo python3 gearbox.py project.yaml")
    print()


if __name__ == "__main__":
    main()
