#!/usr/bin/env python3
# install.py — Gearbox Device Security Assessment Orchestrator
# VERSION: referenced from /opt/pr0t31n/Gearbox/VERSION
# Installs all dependencies for gearbox.py and configures the system.

import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
def _pip_installed(pkg_spec):
    """Return True if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "pyyaml": "yaml", "Pillow": "PIL", "qrcode": "qrcode",
        "paho-mqtt": "paho", "pyOpenSSL": "OpenSSL", "pybluez2": "bluetooth",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"

def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")

def phase_header(title: str) -> None:
    bar = "=" * 60
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)

def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"

# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1

# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0

def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Package lists
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "nmap", "tcpdump",
    "curl", "openssl", "sslscan", "tshark", "can-utils", "minicom",
    "usbutils", "cec-utils", "ddcutil", "read-edid", "edid-decode",
    "dnsmasq", "isc-dhcp-client", "iputils-ping",
    "ssh-audit", "smbmap", "ubertooth", "dhcpcd5",
    # Build
    "python3-pip", "python3-dev", "git", "build-essential", "cmake", "automake",
]

DNF_PACKAGES = [
    "nmap", "tcpdump",
    "curl", "openssl", "sslscan", "wireshark-cli", "can-utils", "minicom",
    "usbutils", "dnsmasq", "dhclient", "iputils",
    "ssh-audit", "smbmap", "ubertooth", "dhcpcd",
    # Build
    "python3-pip", "python3-devel", "git", "gcc", "cmake", "automake",
]

ZYPPER_PACKAGES = [
    "nmap", "tcpdump",
    "curl", "openssl", "sslscan", "wireshark", "can-utils", "minicom",
    "usbutils", "dnsmasq", "dhcp-client", "iputils",
    "ssh-audit", "smbmap", "dhcpcd",
    # Build
    "python3-pip", "python3-devel", "git", "gcc", "cmake", "automake",
]

BREW_PACKAGES = [
    "nmap", "tcpdump",
    "curl", "openssl", "sslscan", "minicom", "dnsmasq",
    # Build
    "git", "cmake", "automake",
]

PIP_PACKAGES = [
    "pyyaml>=6.0.1",
    "requests>=2.31.0",
    "qrcode[pil]>=7.4.2",
    "Pillow>=10.0.0",
    "pyserial>=3.5",
    "cryptography>=41.0.0",
]

# ---------------------------------------------------------------------------
# Bluetooth / BLE testing toolchain (Section: BluetoothModule)
# ---------------------------------------------------------------------------
# Installed by a dedicated best-effort phase so a distro-specific or Kali-only
# package can never abort the core package batch. Core BlueZ packages exist on
# every supported distro; the "extras" are attempted one-by-one and skipped
# silently when unavailable.

# Core BlueZ stack — provides bluetoothctl, hcitool, hciconfig, sdptool,
# l2ping, btmon, btmgmt (bluez) + hcidump (bluez-hcidump) + bt-adapter/bt-device
# (bluez-tools) + headers for pybluez (libbluetooth-dev).
BT_APT_CORE = ["bluez", "bluez-tools", "bluez-hcidump", "libbluetooth-dev"]
BT_DNF_CORE = ["bluez", "bluez-libs", "bluez-tools", "bluez-hcidump"]
BT_ZYPPER_CORE = ["bluez", "bluez-devel"]

# Best-effort extras — Kali/pentest-repo BT tooling. Installed individually.
BT_APT_EXTRAS = [
    "bettercap",     # BLE recon / enum / write (ble.* modules)
    "spooftooph",    # BD_ADDR spoofing / device cloning
    "bluelog",       # BR/EDR site survey logger
    "bluesnarfer",   # OBEX/AT bluesnarf test (legacy BR/EDR)
    "redfang",       # non-discoverable device brute (fang)
    "btscanner",     # interactive BR/EDR scanner + SDP dump
]

# Python BLE libraries — pure/near-pure, safe under --break-system-packages.
BT_PIP_PACKAGES = [
    "bleak>=0.21.1",   # async cross-platform BLE GATT client (scan + enum + read/write)
    "btlejack>=2.1.0", # BLE connection sniff / jam / hijack (Micro:Bit backend)
    "pygatt>=4.0.5",   # GATT client over BlueZ gatttool / BGAPI
    "pybluez2>=0.46",  # classic BR/EDR sockets + SDP (best-effort; may need libbluetooth-dev)
]

# Source-build BT tooling with no distro package.
BT_GIT_REPOS = [
    {
        "url":        "https://github.com/mikeryan/crackle.git",
        "dest":       "/opt/crackle",
        "label":      "crackle (BLE legacy-pairing TK/LTK cracker)",
        "linux_only": True,
        "post_cmds":  ["crackle_build"],
    },
    {
        "url":        "https://github.com/nccgroup/Sniffle.git",
        "dest":       "/opt/Sniffle",
        "label":      "Sniffle (TI CC1352/CC26x2 BLE sniffer host CLI)",
        "linux_only": False,
        "post_cmds":  [],   # host-side python_cli/sniff_receiver.py — no build
    },
    {
        "url":        "https://github.com/seemoo-lab/internalblue.git",
        "dest":       "/opt/internalblue",
        "label":      "InternalBlue (Broadcom/Cypress HCI research framework)",
        "linux_only": True,
        "post_cmds":  [],
    },
]

# ---------------------------------------------------------------------------
# Wireless / RF / Smart-card testing toolchain
#   (Sections: WiFiModule, SubGHzModule, UWBModule, SmartCardModule,
#              ZWaveModule, LoRaModule)
# ---------------------------------------------------------------------------
# Installed by a dedicated best-effort phase (phase_wireless) — every package
# is attempted individually so a distro-specific or Kali-only package can never
# abort the batch. 802.11 monitor-mode + injection tooling is Linux-only in
# practice; the apt block is therefore only applied on Linux distros.
WIRELESS_APT_PKGS = [
    "aircrack-ng",
    "reaver",
    "bully",
    "pixiewps",
    "hcxdumptool",
    "hcxtools",
    "wifite",
    "bettercap",
    "mdk4",
    "iw",
    "wireless-tools",
    "net-tools",
    "rtl-433",
    "rtl-sdr",
    "hackrf",
    "libhackrf-dev",
    "librtlsdr-dev",
    "soapysdr-tools",
    "gnuradio",
    "gnuradio-dev",
    "python3-pyqt5",
    "python3-numpy",
    "wireshark-common",
    "tshark",
    "pcscd",
    "pcsc-tools",
    "opensc",
    "libpcsclite1",
    "libccid",
    "gr-osmosdr",
    "gr-lora",
    "sdrpp",
]

WIRELESS_BREW_PKGS = [
    "aircrack-ng",
    "bettercap",
    "rtl_433",
    "rtl-sdr",
    "hackrf",
    "soapysdr",
    "gnuradio",
    "wireshark",
    "pcsc-tools",
    "opensc",
]

WIRELESS_PIP_PACKAGES = [
    "urh>=2.9.4",
    "pyusb>=1.2",
    "numpy>=1.21",
    "pyserial>=3.5",
]

WIRELESS_GIT_REPOS = [
    {
        "url":        "https://github.com/atlas0fd00m/rfcat",
        "dest":       "/opt/rfcat",
        "label":      "rfcat (YARD Stick One host tool)",
        "linux_only": False,
        "post_cmds":  ["rfcat_pip_build"],
    },
    {
        "url":        "https://github.com/homewsn/whsniff.git",
        "dest":       "/opt/whsniff",
        "label":      "whsniff (CC2531 / Sonoff ZBDongle / CatSniffer Zigbee → pcap)",
        "linux_only": True,
        "post_cmds":  ["whsniff_build"],
    },
    {
        "url":        "https://github.com/RfidResearchGroup/ChameleonUltra.git",
        "dest":       "/opt/ChameleonUltra",
        "label":      "Chameleon Ultra CLI (alternate RFID/NFC reader/emulator)",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/Uberi/DWM3001C-starter-firmware.git",
        "dest":       "/opt/DWM3001C-starter-firmware",
        "label":      "DWM3001C starter firmware + UWB sniffer/UCI tooling",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/cureHsu/EZ-Wave.git",
        "dest":       "/opt/EZ-Wave",
        "label":      "EZ-Wave (Z-Wave SDR recon/exploit)",
        "linux_only": True,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/baol/waving-z.git",
        "dest":       "/opt/waving-z",
        "label":      "waving-z (RTL-SDR Z-Wave decoder)",
        "linux_only": True,
        "post_cmds":  ["cmake_build"],
    },
    {
        "url":        "https://github.com/JiapengLi/lorawan-parser.git",
        "dest":       "/opt/lorawan-parser",
        "label":      "lorawan-parser (LoRaWAN PHYPayload decoder)",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/rpp0/gr-lora.git",
        "dest":       "/opt/gr-lora",
        "label":      "gr-lora (GNU Radio LoRa demodulator)",
        "linux_only": True,
        "post_cmds":  [],
    },
]

# ---------------------------------------------------------------------------
# Phase 1 — System packages
# ---------------------------------------------------------------------------

def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists…")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info("Upgrading installed packages…")
    run(["apt-get", "upgrade", "-y"], check=True, dry_run=dry_run)
    info(f"Installing packages…")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)
    info("Note: ethtool will be installed from git source if not available via apt.")


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing packages…")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)
    info("cec-utils, ddcutil, read-edid, edid-decode may not be "
         "available in standard RHEL repos — add EPEL if needed.")


def phase_zypper(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (zypper)")
    require_root()
    run(["zypper", "refresh"], dry_run=dry_run)
    run(["zypper", "update", "-y"], dry_run=dry_run)
    info(f"Installing packages…")
    run(["zypper", "install", "-y"] + ZYPPER_PACKAGES, check=True, dry_run=dry_run)


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            warn("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    try:
        _installed = set(subprocess.run(
            base_cmd + ["list", "--formula", "-1"],
            capture_output=True, text=True, check=True).stdout.strip().splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        _installed = set()
    _missing = [p for p in BREW_PACKAGES if p not in _installed]
    for p in BREW_PACKAGES:
        if p in _installed:
            info(f"✓ {p} already installed")
    if _missing:
        info(f"Installing brew packages: {' '.join(_missing)}")
        run(base_cmd + ["install"] + _missing, dry_run=dry_run)
    else:
        info("All brew packages already installed.")
    warn("Some Linux-specific tools (can-utils, cec-utils, ddcutil, ethtool) are not "
         "available on macOS.")


# ---------------------------------------------------------------------------
# Phase 2 — Pip
# ---------------------------------------------------------------------------

def find_pip() -> list:
    """Return pip command as a list."""
    for candidate in ("pip3", "pip"):
        if shutil.which(candidate):
            return [candidate]
    if shutil.which("python3"):
        return ["python3", "-m", "pip"]
    return ["pip3"]


def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")
    base_cmd = find_pip()
    _to_install = []
    for pkg in PIP_PACKAGES:
        if _pip_installed(pkg):
            info(f"✓ {pkg} already installed")
        else:
            _to_install.append(pkg)
    if _to_install:
        for pkg in _to_install:
            info(f"Installing: {pkg}")
            run(base_cmd + ["install", "--break-system-packages", pkg],
                check=True, dry_run=dry_run)
    else:
        info("All pip packages already installed.")
    success("Pip phase complete.")


# ---------------------------------------------------------------------------
# Phase 3 — Go tools
# ---------------------------------------------------------------------------

GO_TOOLS = [
    {
        "pkg":   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "label": "nuclei",
    },
    {
        "pkg":   "github.com/sensepost/gowitness@latest",
        "label": "gowitness",
    },
]


def phase_go(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 3 — Go Tools")

    go_bin = shutil.which("go")
    if not go_bin:
        warn("Go not found in PATH. Skipping Go tool installation.")
        warn("Install Go from https://go.dev/dl/ then re-run with --skip-apt --skip-pip.")
        return

    # Determine GOPATH / install destination
    gopath = os.environ.get("GOPATH", str(Path.home() / "go"))
    go_install_bin = str(Path(gopath) / "bin")
    info(f"Go found: {go_bin}")
    info(f"Tools will be installed to: {go_install_bin}")

    for tool in GO_TOOLS:
        if shutil.which(tool["label"]):
            info(f"{tool['label']} already installed — skipping")
            continue
        info(f"Installing {tool['label']} ({tool['pkg']})…")
        rc = run(["go", "install", tool["pkg"]], dry_run=dry_run)
        if rc == 0:
            tool_path = shutil.which(tool["label"]) or str(Path(go_install_bin) / tool["label"])
            if not dry_run:
                # Create symlink in /usr/local/bin if not already on PATH
                link = Path("/usr/local/bin") / tool["label"]
                installed_bin = Path(go_install_bin) / tool["label"]
                if installed_bin.exists() and not link.exists():
                    try:
                        link.symlink_to(installed_bin)
                        success(f"Symlinked {tool['label']} → {link}")
                    except OSError as exc:
                        warn(f"Could not symlink {tool['label']}: {exc}")
        else:
            warn(f"{tool['label']}: installation failed — check go output above.")

    success("Go phase complete.")


# ---------------------------------------------------------------------------
# Phase 4 — Git repositories
# ---------------------------------------------------------------------------

GIT_REPOS_ALL = [
    {
        "url":        "https://github.com/drwetter/testssl.sh.git",
        "dest":       "/opt/testssl.sh",
        "label":      "testssl.sh",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/lgandx/Responder.git",
        "dest":       "/opt/Responder",
        "label":      "Responder",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/RfidResearchGroup/proxmark3.git",
        "dest":       "/opt/proxmark3",
        "label":      "proxmark3",
        "linux_only": False,
        # Build only on Linux
        "post_cmds":  ["linux_build"],
    },
    {
        "url":        "https://github.com/santoru/shcheck.git",
        "dest":       "/opt/shcheck",
        "label":      "shcheck",
        "linux_only": False,
        "post_cmds":  [],
    },
    {
        "url":        "https://github.com/sigma-1/ethtool.git",
        "dest":       "/opt/ethtool",
        "label":      "ethtool (from source)",
        "linux_only": True,
        "post_cmds":  ["ethtool_build"],
    },
]


def _build_proxmark3(dry_run: bool) -> None:
    info("Building proxmark3 (make clean && make -j4)…")
    run(["make", "clean"], cwd="/opt/proxmark3", dry_run=dry_run)
    run(["make", "-j4"], cwd="/opt/proxmark3", dry_run=dry_run)


def _build_ethtool(dry_run: bool) -> None:
    info("Building ethtool from source…")
    run(["./autogen.sh"], cwd="/opt/ethtool", dry_run=dry_run)
    run(["./configure"], cwd="/opt/ethtool", dry_run=dry_run)
    run(["make"], cwd="/opt/ethtool", dry_run=dry_run)
    run(["make", "install"], cwd="/opt/ethtool", dry_run=dry_run)


def _build_crackle(dry_run: bool) -> None:
    info("Building crackle (make)…")
    rc = run(["make"], cwd="/opt/crackle", dry_run=dry_run)
    if rc == 0 and not dry_run:
        # Expose the built binary on PATH.
        src = Path("/opt/crackle/crackle")
        link = Path("/usr/local/bin/crackle")
        if src.exists() and not link.exists():
            try:
                link.symlink_to(src)
                success(f"Symlinked crackle → {link}")
            except OSError as exc:
                warn(f"Could not symlink crackle: {exc}")


def _build_cmake(dest: str, label: str, dry_run: bool) -> None:
    info(f"Building {label} (cmake)…")
    build_dir = str(Path(dest) / "build")
    run(['mkdir', '-p', build_dir], dry_run=dry_run)
    run(['cmake', '..'], cwd=build_dir, dry_run=dry_run)
    run(['make', '-j4'], cwd=build_dir, dry_run=dry_run)


def _build_whsniff(dest: str, dry_run: bool) -> None:
    """Build whsniff (needs libusb-1.0-dev) and symlink onto PATH."""
    info("Building whsniff (make)…")
    _install_individually(["apt-get", "install", "-y"], ["libusb-1.0-0-dev"], dry_run)
    run(["make"], cwd=dest, dry_run=dry_run)
    src = Path(dest) / "whsniff"
    link = Path("/usr/local/bin/whsniff")
    if not dry_run and src.exists() and not link.exists():
        try:
            link.symlink_to(src); success(f"Symlinked whsniff → {link}")
        except OSError as exc:
            warn(f"Could not symlink whsniff: {exc}")


def _build_rfcat_pip(dest: str, dry_run: bool) -> None:
    info("Installing rfcat (pip install . — YARD Stick One host tool)…")
    pip_cmd = find_pip()
    rc = run(pip_cmd + ["install", "--break-system-packages", "."], cwd=dest, dry_run=dry_run)
    if rc == 0:
        success("  rfcat installed")
    else:
        warn("  rfcat pip build failed — YARD Stick One features degrade gracefully")


def clone_or_update(repo: dict, os_id: str, dry_run: bool) -> None:
    url   = repo["url"]
    dest  = repo["dest"]
    label = repo["label"]

    if repo.get("linux_only") and os_id == "macos":
        info(f"Skipping {label} — Linux only.")
        return

    dest_path = Path(dest)
    if dest_path.exists():
        info(f"{label}: directory exists — pulling latest changes…")
        rc = run(["git", "-C", dest, "pull", "--ff-only"], dry_run=dry_run)
        if rc != 0:
            warn(f"{label}: git pull failed — continuing with existing clone.")
    else:
        info(f"{label}: cloning {url} → {dest}")
        rc = run(["git", "clone", "--depth=1", url, dest], check=True, dry_run=dry_run)
        if rc != 0:
            error(f"{label}: clone failed — skipping post-install steps.")
            return

    for post in repo.get("post_cmds", []):
        is_linux = os_id not in ("macos", "windows")
        if post == "linux_build" and is_linux:
            _build_proxmark3(dry_run)
        elif post == "linux_build" and not is_linux:
            warn(f"{label}: skipping Linux build on {os_id}.")
        elif post == "ethtool_build":
            _build_ethtool(dry_run)
        elif post == "crackle_build":
            _build_crackle(dry_run)
        elif post == "cmake_build" and is_linux:
            _build_cmake(dest, label, dry_run)
        elif post == "cmake_build" and not is_linux:
            warn(f"{label}: skipping cmake build on {os_id}.")
        elif post == "rfcat_pip_build":
            _build_rfcat_pip(dest, dry_run)
        elif post == "whsniff_build" and is_linux:
            _build_whsniff(dest, dry_run)
        elif post == "whsniff_build" and not is_linux:
            warn(f"{label}: skipping whsniff build on {os_id}.")


def phase_git(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 4 — Git Repositories")
    for repo in GIT_REPOS_ALL:
        clone_or_update(repo, os_id, dry_run)
    success("Git phase complete.")


# ---------------------------------------------------------------------------
# Phase 4b — Bluetooth / BLE testing toolchain
# ---------------------------------------------------------------------------

def _install_individually(base_cmd: list, pkgs: list, dry_run: bool) -> None:
    """Install packages one-by-one so a single unavailable package cannot abort
    the whole batch (extras differ across Kali / Ubuntu / RHEL)."""
    for pkg in pkgs:
        rc = run(base_cmd + [pkg], dry_run=dry_run)
        if rc == 0:
            success(f"  {pkg} installed")
        else:
            warn(f"  {pkg} unavailable on this distro — skipped")


def phase_bluetooth(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 4b — Bluetooth / BLE Testing Toolchain")

    # ── Core BlueZ stack (batch; present on every supported distro) ──────────
    if os_id in ("kali", "ubuntu"):
        require_root()
        info("Installing core BlueZ stack (bluez, bluez-tools, hcidump, libbluetooth-dev)…")
        run(["apt-get", "install", "-y"] + BT_APT_CORE, dry_run=dry_run)
        info("Installing best-effort BT extras (bettercap, spooftooph, bluelog, …)…")
        _install_individually(["apt-get", "install", "-y"], BT_APT_EXTRAS, dry_run)
    elif os_id == "rhel":
        require_root()
        run(["dnf", "install", "-y"] + BT_DNF_CORE, dry_run=dry_run)
        _install_individually(["dnf", "install", "-y"], ["bettercap"], dry_run)
    elif os_id == "suse":
        require_root()
        run(["zypper", "install", "-y"] + BT_ZYPPER_CORE, dry_run=dry_run)
    elif os_id == "macos":
        warn("macOS has no BlueZ stack — Bluetooth link-layer testing requires Linux.")
        warn("Only the Python BLE client (bleak) and blueutil will be usable here.")
        brew_bin = shutil.which("brew")
        if brew_bin and os.environ.get("SUDO_USER"):
            run(["sudo", "-u", os.environ["SUDO_USER"], brew_bin, "install", "blueutil"],
                dry_run=dry_run)
        else:
            info("Install blueutil manually:  brew install blueutil")
    else:
        warn(f"Unknown OS '{os_id}' — install bluez / bluez-tools manually.")

    # ── Python BLE libraries (best-effort) ───────────────────────────────────
    info("Installing Python BLE libraries (bleak, btlejack, pygatt, pybluez2)…")
    pip_cmd = find_pip()
    for pkg in BT_PIP_PACKAGES:
        if _pip_installed(pkg):
            success(f"  ✓ {pkg} already installed")
            continue
        rc = run(pip_cmd + ["install", "--break-system-packages", pkg], dry_run=dry_run)
        if rc == 0:
            success(f"  {pkg} installed")
        else:
            warn(f"  {pkg} failed (needs build deps?) — BLE features degrade gracefully")

    # ── Source-build BT tooling (crackle, Sniffle host CLI, InternalBlue) ────
    for repo in BT_GIT_REPOS:
        clone_or_update(repo, os_id, dry_run)

    success("Bluetooth toolchain phase complete.")
    info("Passive link-layer sniffing needs a flashed sniffer board — flash it with")
    info("Quiver:  'FIRMWARE - Flash Sniffle firmware' (TI CC1352P-4 / CC26x2R1) for")
    info("crackle-readable pcaps, or 'FIRMWARE - Flash nRF Sniffer firmware' (nRF52840/")
    info("nRF52833) for Wireshark, or 'FIRMWARE - Flash ButteRFly (BLE MITM)' for injection.")


# ---------------------------------------------------------------------------
# Phase 4c — Wireless / RF / Smart-card toolchain
# ---------------------------------------------------------------------------

def phase_wireless(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 4c — Wireless / RF / Smart-card Toolchain")

    # ── System packages (per-package best-effort — never abort the batch) ────
    if os_id in ("kali", "ubuntu"):
        require_root()
        info("Installing Wi-Fi / SDR / smart-card packages (best-effort, individual)…")
        _install_individually(["apt-get", "install", "-y"], WIRELESS_APT_PKGS, dry_run)
    elif os_id == "rhel":
        require_root()
        _install_individually(["dnf", "install", "-y"], WIRELESS_APT_PKGS, dry_run)
    elif os_id == "suse":
        require_root()
        _install_individually(["zypper", "install", "-y"], WIRELESS_APT_PKGS, dry_run)
    elif os_id == "macos":
        warn("macOS: 802.11 monitor mode / injection unsupported — only SDR-decode,")
        warn("smart-card (native PC/SC) and analysis tooling are usable here.")
        brew_bin = shutil.which("brew")
        if brew_bin and os.environ.get("SUDO_USER"):
            base = ["sudo", "-u", os.environ["SUDO_USER"], brew_bin, "install"]
            _install_individually(base, WIRELESS_BREW_PKGS, dry_run)
        else:
            info("Install manually:  brew install " + " ".join(WIRELESS_BREW_PKGS))
    else:
        warn(f"Unknown OS '{os_id}' — install Wi-Fi / SDR / smart-card tools manually.")

    # ── Python libraries (best-effort) ───────────────────────────────────────
    info("Installing wireless Python libraries (urh, pyusb, numpy, pyserial)…")
    pip_cmd = find_pip()
    for pkg in WIRELESS_PIP_PACKAGES:
        if _pip_installed(pkg):
            success(f"  ✓ {pkg} already installed")
            continue
        rc = run(pip_cmd + ["install", "--break-system-packages", pkg], dry_run=dry_run)
        if rc == 0:
            success(f"  {pkg} installed")
        else:
            warn(f"  {pkg} failed (needs build deps?) — features degrade gracefully")

    # ── Source-build tooling (rfcat, EZ-Wave, waving-z, lorawan-parser, …) ────
    for repo in WIRELESS_GIT_REPOS:
        clone_or_update(repo, os_id, dry_run)

    success("Wireless / RF / smart-card toolchain phase complete.")
    info("Radio capture needs SDR/sniffer hardware — flash sniffer firmware with")
    info("Quiver (LoRa / Z-Wave CatSniffer, UWB DWM3001C, Sub-GHz YARD Stick One).")


# ---------------------------------------------------------------------------
# Phase 5 — Symlinks
# ---------------------------------------------------------------------------

SYMLINKS = {
    "/usr/local/bin/gearbox": "/opt/pr0t31n/Gearbox/gearbox.py",
}


def phase_symlinks(dry_run: bool) -> None:
    phase_header("PHASE 5 — Symlinks")
    for link, target in SYMLINKS.items():
        target_path = Path(target)
        link_path   = Path(link)
        if not target_path.exists():
            warn(f"Target not found: {target} — symlink will be created anyway.")
        if link_path.is_symlink() or link_path.exists():
            info(f"Removing existing: {link}")
            if not dry_run:
                try:
                    link_path.unlink()
                except OSError as exc:
                    error(f"Could not remove {link}: {exc}")
                    continue
        info(f"Creating symlink: {link} → {target}")
        if not dry_run:
            try:
                link_path.symlink_to(target)
                if target_path.exists():
                    target_path.chmod(0o755)
                success(f"Symlink created: {link}")
            except OSError as exc:
                error(f"Could not create symlink {link}: {exc}")
        else:
            cprint(f"    [DRY-RUN] ln -s {target} {link}", MAGENTA)


# ---------------------------------------------------------------------------
# Phase 6 — Service installation
# ---------------------------------------------------------------------------

SYSTEMD_UNIT = """\
[Unit]
Description=Gearbox Device Security Assessment Orchestrator
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/pr0t31n/Gearbox/gearbox.py
WorkingDirectory=/opt/pr0t31n/Gearbox
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pr0t31n.gearbox</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/opt/pr0t31n/Gearbox/gearbox.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/pr0t31n/Gearbox</string>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/gearbox.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/gearbox.err</string>
</dict>
</plist>
"""


def phase_service(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 6 — Service Installation")
    if os_id in ("kali", "ubuntu", "rhel", "suse"):
        service_path = Path("/etc/systemd/system/pr0t31n-gearbox.service")
        info(f"Writing systemd unit: {service_path}")
        if not dry_run:
            try:
                service_path.write_text(SYSTEMD_UNIT)
                run(["systemctl", "daemon-reload"], dry_run=dry_run)
                run(["systemctl", "enable", "pr0t31n-gearbox"], dry_run=dry_run)
                success(f"Systemd service installed and enabled: {service_path}")
            except OSError as exc:
                error(f"Failed to write service file: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {service_path}", MAGENTA)
            cprint(f"    [DRY-RUN] systemctl daemon-reload && systemctl enable pr0t31n-gearbox", MAGENTA)

    elif os_id == "macos":
        plist_path = Path("/Library/LaunchDaemons/com.pr0t31n.gearbox.plist")
        info(f"Writing launchd plist: {plist_path}")
        if not dry_run:
            try:
                plist_path.write_text(LAUNCHD_PLIST)
                run(["launchctl", "load", str(plist_path)], dry_run=dry_run)
                success(f"Launchd plist installed: {plist_path}")
            except OSError as exc:
                error(f"Failed to write plist: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {plist_path}", MAGENTA)
    else:
        warn(f"Service installation skipped for OS: {os_id}")


# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

VERIFY_TOOLS = [
    "nmap", "tcpdump", "curl", "openssl", "sslscan", "nuclei", "gowitness",
    # Bluetooth / BLE
    "bluetoothctl", "hcitool", "hciconfig", "sdptool", "l2ping", "btmgmt",
    "gatttool", "bettercap", "crackle",
    # Wireless / RF / smart-card
    "aircrack-ng", "rtl_433", "hackrf_transfer", "pcsc_scan", "opensc-tool",
]

VERIFY_PY_MODULES = [
    ("yaml",        "yaml"),
    ("requests",    "requests"),
    ("qrcode",      "qrcode"),
    ("PIL",         "PIL"),
    ("serial",      "serial"),
    ("cryptography","cryptography"),
    ("bleak",       "bleak"),
    ("btlejack",    "btlejack"),
    ("numpy",       "numpy"),
    ("pyusb",       "usb"),
]


def phase_verify() -> None:
    phase_header("POST-INSTALL SUMMARY")
    all_ok = True

    cprint("  System tools:", BOLD)
    for tool in VERIFY_TOOLS:
        found = shutil.which(tool)
        if found:
            success(f"  {tool:25s} found at {found}")
        else:
            warn(f"  {tool:25s} NOT FOUND")
            all_ok = False

    print()
    cprint("  Python modules:", BOLD)
    for display_name, import_name in VERIFY_PY_MODULES:
        spec = importlib.util.find_spec(import_name)
        if spec is not None:
            success(f"  {display_name:20s} importable")
        else:
            warn(f"  {display_name:20s} NOT FOUND — pip install --break-system-packages {display_name}")
            all_ok = False

    print()
    cprint("  Git tools:", BOLD)
    for repo in GIT_REPOS_ALL + WIRELESS_GIT_REPOS:
        dest = Path(repo["dest"])
        if dest.exists():
            success(f"  {repo['label']:30s} cloned at {repo['dest']}")
        else:
            warn(f"  {repo['label']:30s} NOT FOUND at {repo['dest']}")
            all_ok = False

    print()
    if all_ok:
        success("All required tools verified successfully.")
    else:
        warn("Some required tools are missing. Review warnings above.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Gearbox installer — Device Security Assessment Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--skip-apt",  action="store_true", help="Skip system package installation")
    p.add_argument("--skip-pip",  action="store_true", help="Skip pip package installation")
    p.add_argument("--skip-go",   action="store_true", help="Skip Go tool installation")
    p.add_argument("--skip-git",  action="store_true", help="Skip git repository cloning")
    p.add_argument("--skip-bt",   action="store_true", help="Skip Bluetooth/BLE toolchain installation")
    p.add_argument("--skip-wireless", action="store_true", help="Skip wireless / RF / smart-card toolchain installation")
    p.add_argument("--check",     action="store_true", help="Dry-run — print commands without executing")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 60, GREEN, bold=True)
    cprint("  Gearbox Installer", GREEN, bold=True)
    cprint("  Device Security Assessment Orchestrator", GREEN, bold=True)
    cprint("=" * 60 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    os_id = detect_os()
    info(f"Detected OS: {os_id}")

    if os_id == "windows":
        warn("Windows detected.")
        warn("Many Gearbox tools require Linux. Limited functionality is available.")
        warn("Install Python dependencies manually:")
        warn("  pip install pyyaml requests qrcode[pil] Pillow pyserial cryptography")
        warn("Then run:  python gearbox.py")
        sys.exit(0)

    # Phase 1 — system packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "suse":
            phase_zypper(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            warn(f"Unknown OS '{os_id}' — skipping system package phase.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — pip
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — Go
    if not args.skip_go:
        phase_go(os_id, dry_run)
    else:
        info("Skipping Go phase (--skip-go).")

    # Phase 4 — Git
    if not args.skip_git:
        phase_git(os_id, dry_run)
    else:
        info("Skipping git phase (--skip-git).")

    # Phase 4b — Bluetooth / BLE toolchain
    if not args.skip_bt:
        phase_bluetooth(os_id, dry_run)
    else:
        info("Skipping Bluetooth phase (--skip-bt).")

    # Phase 4c — Wireless / RF / Smart-card toolchain
    if not args.skip_wireless:
        phase_wireless(os_id, dry_run)
    else:
        info("Skipping wireless phase (--skip-wireless).")

    # Phase 5 — Symlinks
    if is_root() or dry_run:
        phase_symlinks(dry_run)
    else:
        warn("Not running as root — skipping symlink creation.")

    # Phase 6 — Service
    if is_root() or dry_run:
        phase_service(os_id, dry_run)
    else:
        warn("Not running as root — skipping service installation.")

    # Verify
    phase_verify()

    print()
    cprint("  Gearbox installation complete.", GREEN, bold=True)
    cprint("  Run:  gearbox --help  to get started.\n", CYAN)


if __name__ == "__main__":
    main()
