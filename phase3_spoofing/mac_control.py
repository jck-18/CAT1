"""Phase 3 - MAC address spoofing: orchestration and verification.

Changes the adapter's MAC by writing the NetworkAddress override directly into
the registry and restarting the adapter - the same mechanism SMAC (and most
Windows MAC-spoofing tools) use under the hood, just without a GUI to click
through. That means the whole cycle - before -> spoof -> verify -> restore -
runs unattended, which matters live: a demo that depends on someone clicking
the right thing in a third-party tool in front of an audience is a demo with
one more way to go wrong than it needs.

What this script does:
  * reads the real adapter state from Windows (`getmac /v` + `ipconfig /all`)
  * spoofs the MAC via HKLM\\...\\<adapter class>\\<N>\\NetworkAddress + an
    adapter restart, and restores it by deleting that registry value
  * snapshots before / after / restored, with timestamps, to an auditable log
  * verifies the change (and the restore) actually took

Produces:
  outputs/mac_log.json - full snapshots, every stage, with all adapters
  outputs/mac_log.csv  - flat before/after/restored log for the report

Usage:
    python mac_control.py view                  # current adapters and MACs
    python mac_control.py demo                   # automated before -> spoof -> restore
    python mac_control.py spoof [--mac AA-BB-CC-DD-EE-FF]
    python mac_control.py restore
    python mac_control.py snapshot --stage before
    python mac_control.py verify --expected 00-11-22-33-44-55
    python mac_control.py restart-adapter        # needs an elevated shell
    python mac_control.py report                 # before/after table from the log

Scope: this only ever touches this laptop's own adapter, with the owner sitting
in front of it. Spoofing someone else's MAC on a network you do not own is a
different thing entirely and is not what this project does.
"""

from __future__ import annotations

import argparse
import csv as csv_module
import io
import random
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, confirm, die, ensure_dir, info, is_admin, normalise_mac,
    now_iso, ok, pause, print_table, read_json, rel, require_admin, run,
    step, warn, write_csv, write_json,
)

try:
    import winreg
except ImportError:
    winreg = None  # not Windows - functions below fail loudly instead of at import time

LOG_FIELDS = ["stage", "timestamp", "host", "interface", "adapter_description",
              "mac", "ipv4", "elevated", "note"]

STAGES = ("before", "after", "restored", "adhoc")

# The registry class that holds every NIC driver's settings, including the
# NetworkAddress override. This is the exact location SMAC (and Windows
# itself) uses - writing it directly just skips the GUI in front of it.
NIC_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"


# --------------------------------------------------------------------------
# Reading adapter state from Windows
# --------------------------------------------------------------------------


def parse_getmac() -> list[dict]:
    """`getmac /v /fo csv /nh` ->
    "Connection Name","Network Adapter","Physical Address","Transport Name"
    """
    result = run(["getmac", "/v", "/fo", "csv", "/nh"], timeout=60)
    if result.returncode != 0:
        warn(f"getmac failed: {result.stderr.strip()}")
        return []

    adapters = []
    for row in csv_module.reader(io.StringIO(result.stdout)):
        if len(row) < 3:
            continue
        connection, description, mac = row[0], row[1], row[2]
        transport = row[3] if len(row) > 3 else ""
        adapters.append({
            "interface": connection.strip(),
            "adapter_description": description.strip(),
            "mac": normalise_mac(mac) if "N/A" not in mac else None,
            "transport": transport.strip(),
            "connected": "disconnected" not in transport.lower(),
        })
    return adapters


def parse_ipconfig() -> dict[str, dict]:
    """`ipconfig /all` -> {connection name: {description, mac, ipv4}}.

    getmac gives us the MAC but no IP; ipconfig gives us both. Cross-checking
    the two is the point - if they disagree, something is stale.
    """
    result = run(["ipconfig", "/all"], timeout=60)
    if result.returncode != 0:
        return {}

    adapters: dict[str, dict] = {}
    current: str | None = None
    for line in result.stdout.splitlines():
        header = re.match(r"^[A-Za-z].*adapter\s+(.+?):\s*$", line)
        if header:
            current = header.group(1).strip()
            adapters[current] = {"description": None, "mac": None, "ipv4": None}
            continue
        if not current:
            continue
        entry = adapters[current]
        if match := re.search(r"Description[ .]*:\s*(.+)$", line):
            entry["description"] = match.group(1).strip()
        elif match := re.search(r"Physical Address[ .]*:\s*([0-9A-Fa-f:-]+)", line):
            entry["mac"] = normalise_mac(match.group(1))
        elif match := re.search(r"IPv4 Address[ .]*:\s*([0-9.]+)", line):
            entry["ipv4"] = match.group(1).strip()
    return adapters


def read_adapters() -> list[dict]:
    """Merged view: getmac as the spine, ipconfig for the IP address."""
    ipconfig = parse_ipconfig()
    adapters = parse_getmac()

    for adapter in adapters:
        match = ipconfig.get(adapter["interface"])
        if not match:
            # getmac's connection name and ipconfig's adapter name usually agree;
            # when they do not, fall back to matching on the adapter description.
            for entry in ipconfig.values():
                if entry.get("description") == adapter["adapter_description"]:
                    match = entry
                    break
        if match:
            adapter["ipv4"] = match.get("ipv4")
            if match.get("mac") and match["mac"] != adapter["mac"]:
                adapter["mac_ipconfig"] = match["mac"]
        else:
            adapter["ipv4"] = None

    if not adapters:  # getmac unavailable - fall back to ipconfig alone
        for name, entry in ipconfig.items():
            adapters.append({
                "interface": name,
                "adapter_description": entry.get("description"),
                "mac": entry.get("mac"),
                "ipv4": entry.get("ipv4"),
                "transport": "",
                "connected": bool(entry.get("ipv4")),
            })
    return adapters


def find_adapter(adapters: list[dict], wanted: str) -> dict | None:
    wanted_lower = wanted.strip().lower()
    for adapter in adapters:
        if adapter["interface"].lower() == wanted_lower:
            return adapter
    for adapter in adapters:                     # tolerate "Wi-Fi" vs "Wi-Fi 2"
        if wanted_lower in adapter["interface"].lower():
            return adapter
    for adapter in adapters:
        if wanted_lower in (adapter.get("adapter_description") or "").lower():
            return adapter
    return None


def show_adapters(adapters: list[dict], highlight: str | None = None) -> None:
    print_table(
        [[("*" if highlight and a["interface"] == highlight else " "),
          a["interface"], a.get("mac") or "-", a.get("ipv4") or "-",
          "up" if a.get("connected") else "down",
          (a.get("adapter_description") or "")[:40]]
         for a in adapters],
        ["", "INTERFACE", "MAC", "IPv4", "LINK", "ADAPTER"],
    )


# --------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------


def load_log() -> dict:
    if config.MAC_LOG_JSON.exists():
        try:
            return read_json(config.MAC_LOG_JSON)
        except (ValueError, OSError):
            warn("existing mac_log.json is unreadable - starting a new one")
    return {"host": config.this_host(), "created_at": now_iso(), "entries": []}


def save_log(log: dict) -> None:
    ensure_dir(config.PHASE3_OUTPUTS)
    log["updated_at"] = now_iso()
    write_json(config.MAC_LOG_JSON, log)
    write_csv(config.MAC_LOG_CSV, log["entries"], LOG_FIELDS)


def snapshot(stage: str, note: str | None = None,
             interface: str | None = None, quiet: bool = False) -> dict:
    """Record the current state of the target adapter (plus all others)."""
    interface = interface or config.spoof_interface()
    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        show_adapters(adapters)
        die(f"adapter {interface!r} not found - set SPOOF_INTERFACE in "
            f"shared/config.py to one of the INTERFACE values above.")

    entry = {
        "stage": stage,
        "timestamp": now_iso(),
        "host": config.this_host(),
        "interface": target["interface"],
        "adapter_description": target.get("adapter_description"),
        "mac": target.get("mac"),
        "ipv4": target.get("ipv4"),
        "elevated": is_admin(),
        "note": note,
        "all_adapters": adapters,
    }

    log = load_log()
    log["interface"] = target["interface"]
    log["entries"].append(entry)
    save_log(log)

    if not quiet:
        ok(f"[{stage}] {target['interface']}  MAC={target.get('mac')}  "
           f"IPv4={target.get('ipv4')}")
    return entry


def last_entry(log: dict, stage: str) -> dict | None:
    matches = [e for e in log.get("entries", []) if e.get("stage") == stage]
    return matches[-1] if matches else None


# --------------------------------------------------------------------------
# Registry-based MAC change
# --------------------------------------------------------------------------


# Maps a friendly interface name (e.g. "Wi-Fi") to the NetCfgInstanceId GUID
# Windows currently has bound to it - the authoritative, unambiguous link.
NETWORK_CONNECTIONS_KEY = r"SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}"


def _netcfg_instance_id_for_interface(interface_name: str) -> str | None:
    """The NetCfgInstanceId GUID currently bound to this friendly interface
    name. Only one adapter can hold a given name at a time, so this is
    unambiguous - unlike matching on DriverDesc text (see the docstring on
    find_adapter_registry_key for why that matters)."""
    if not winreg:
        return None
    wanted = interface_name.strip().lower()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY) as root:
            index = 0
            while True:
                try:
                    guid = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, f"{guid}\\Connection") as conn:
                        name, _ = winreg.QueryValueEx(conn, "Name")
                        if str(name).strip().lower() == wanted:
                            return guid
                except OSError:
                    continue
    except OSError:
        return None
    return None


def _registry_key_by_instance_id(target_guid: str) -> str | None:
    """The NIC class subkey whose own NetCfgInstanceId matches target_guid."""
    if not winreg:
        return None
    wanted = target_guid.strip("{}").lower()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NIC_CLASS_KEY) as class_key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(class_key, index)
                except OSError:
                    break
                index += 1
                if not subkey_name.isdigit():
                    continue
                try:
                    with winreg.OpenKey(class_key, subkey_name) as sub:
                        instance_id, _ = winreg.QueryValueEx(sub, "NetCfgInstanceId")
                        if str(instance_id).strip("{}").lower() == wanted:
                            return subkey_name
                except OSError:
                    continue
    except OSError:
        return None
    return None


def _registry_key_by_driver_desc(adapter_description: str) -> str | None:
    """Fallback only: first subkey whose DriverDesc matches. Unreliable on its
    own - a driver reinstall can leave an orphaned subkey behind with the same
    DriverDesc as the live one, and this would happily match the wrong (dead)
    instance, silently no-op the write, and look like success."""
    if not winreg or not adapter_description:
        return None
    wanted = adapter_description.strip().lower()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NIC_CLASS_KEY) as class_key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(class_key, index)
                except OSError:
                    break
                index += 1
                if not subkey_name.isdigit():
                    continue
                try:
                    with winreg.OpenKey(class_key, subkey_name) as sub:
                        driver_desc, _ = winreg.QueryValueEx(sub, "DriverDesc")
                        if wanted in str(driver_desc).strip().lower():
                            return subkey_name
                except OSError:
                    continue
    except OSError:
        return None
    return None


def find_adapter_registry_key(adapter_description: str,
                              interface_name: str | None = None) -> str | None:
    """Find this adapter's numbered subkey under the NIC class GUID - the
    same location SMAC edits.

    Resolved via NetCfgInstanceId when we have the friendly interface name
    (e.g. "Wi-Fi"): Network\\{GUID}\\<instance>\\Connection\\Name tells us
    exactly which instance GUID currently owns that name, and the matching
    Class subkey is the one actually bound to the live adapter. DriverDesc
    text matching alone is not enough - a stale subkey left behind by an
    earlier driver install can share the same DriverDesc as the live one, and
    picking that one instead writes to a key nothing reads, which looks like
    success (no error) but changes nothing.
    """
    if interface_name:
        target_guid = _netcfg_instance_id_for_interface(interface_name)
        if target_guid:
            key = _registry_key_by_instance_id(target_guid)
            if key:
                return key
    return _registry_key_by_driver_desc(adapter_description)


def driver_supports_network_address(subkey: str) -> bool:
    """Whether this adapter's driver registers NetworkAddress as a configurable
    advanced property (Ndi\\Params\\NetworkAddress under its class subkey).

    IMPORTANT: this only tells you whether "Network Address" appears in Device
    Manager's Advanced tab - i.e. the GUI registration. It is NOT a reliable
    predictor of whether the driver honours a NetworkAddress registry override:
    that's a separate NDIS-layer behaviour, and drivers exist that honour the
    value without exposing the GUI property (and vice versa). Use this only as
    an informational hint, never as a gate that skips the actual attempt - the
    empirical before/after MAC comparison is the only real answer."""
    if not winreg:
        return False
    path = f"{NIC_CLASS_KEY}\\{subkey}\\Ndi\\Params\\NetworkAddress"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
            return True
    except OSError:
        return False


def set_registry_mac(subkey: str, mac_hex: str) -> bool:
    reg_path = f"{NIC_CLASS_KEY}\\{subkey}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, mac_hex)
        return True
    except PermissionError:
        warn("registry write denied - re-run from an elevated shell")
        return False
    except OSError as exc:
        warn(f"registry write failed: {exc}")
        return False


def clear_registry_mac(subkey: str) -> bool:
    """Delete the NetworkAddress override so the adapter falls back to its
    burned-in hardware MAC."""
    reg_path = f"{NIC_CLASS_KEY}\\{subkey}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteValue(key, "NetworkAddress")
        return True
    except FileNotFoundError:
        return True  # already clear - already on the hardware MAC
    except PermissionError:
        warn("registry write denied - re-run from an elevated shell")
        return False
    except OSError as exc:
        warn(f"registry clear failed: {exc}")
        return False


def generate_locally_administered_mac() -> str:
    """A random unicast, locally-administered MAC: the second-least-
    significant bit of the first octet set (locally administered, i.e. not a
    real vendor's burned-in address) and the least-significant bit clear
    (unicast, not multicast). This is the same convention OS-level MAC
    randomisation (Android/iOS/Windows Wi-Fi privacy features) uses, and it
    means we are not colliding with a real device's actual vendor OUI by
    guessing one."""
    first = (random.randint(0, 255) | 0x02) & 0xFE
    rest = [random.randint(0, 255) for _ in range(5)]
    return "-".join(f"{b:02X}" for b in [first, *rest])


def _wait_for_adapter(interface: str, timeout: float = 25.0,
                      interval: float = 1.5) -> dict | None:
    """Poll until the adapter comes back after a restart and reports a MAC.
    Windows can take a few seconds to bring the link back up and get a new
    DHCP lease, so this retries rather than trusting a fixed sleep."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        adapters = read_adapters()
        target = find_adapter(adapters, interface)
        if target and target.get("mac"):
            return target
        last = target
        time.sleep(interval)
    return last


def _pnp_restart_adapter(interface: str, timeout: int = 30) -> bool:
    """Disable + re-enable the adapter's PnP device, not just its admin/link
    state. netsh's `admin=disabled/enabled` (what restart_adapter() does)
    toggles the interface like right-click 'Disable' in Network Connections -
    for some drivers that is not a deep enough reset to make them re-read a
    NetworkAddress registry override. A real PnP device restart (what you'd
    get manually disabling/enabling the device in Device Manager) reliably
    reloads the driver and its registry-configured properties."""
    if not is_admin():
        return False
    ps = (
        f"$id = (Get-NetAdapter -Name '{interface}' -ErrorAction Stop).PnPDeviceID; "
        f"Disable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop; "
        f"Start-Sleep -Seconds 2; "
        f"Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop"
    )
    step(f"PowerShell: PnP device restart of {interface}")
    try:
        result = run(["powershell", "-NoProfile", "-Command", ps], timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        warn(f"PnP restart could not run: {exc}")
        return False
    if result.returncode != 0:
        warn(f"PnP restart failed: {(result.stderr or result.stdout).strip()}")
        return False
    ok("adapter PnP-reset - give Windows a few seconds to reconnect")
    return True


def _restart_for_mac_change(interface: str) -> None:
    """Reset the adapter so a NetworkAddress registry change actually takes
    effect. Tries the stronger PnP-level restart first; falls back to the
    plain interface toggle if PowerShell's NetAdapter/PnpDevice cmdlets are
    unavailable for some reason."""
    if not _pnp_restart_adapter(interface):
        warn("falling back to a plain interface restart (netsh)")
        restart_adapter(interface, assume_yes=True)


def spoof_mac(interface: str, new_mac: str | None = None) -> dict:
    """Change the adapter's MAC via registry + restart. No prompts - this is
    meant to run unattended during the demo.

    Returns {"changed": bool, "old_mac": str|None, "new_mac": str|None, "adapter": dict}.
    """
    require_admin("changing a MAC address writes to HKLM and needs an elevated shell")
    if not winreg:
        die("winreg is unavailable - this only runs on Windows")

    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        die(f"adapter {interface!r} not found")
    original_mac = target.get("mac")

    mac = normalise_mac(new_mac) if new_mac else generate_locally_administered_mac()
    mac_hex = (mac or "").replace("-", "")
    if len(mac_hex) != 12:
        die(f"invalid MAC to spoof: {new_mac!r}")

    subkey = find_adapter_registry_key(target.get("adapter_description") or "",
                                       interface_name=target["interface"])
    if not subkey:
        die(f"could not find the registry key for {target['interface']!r} "
            f"({target.get('adapter_description')}) - is this a standard "
            f"Windows NIC driver?")

    # Note, don't gate: the absence of an Ndi\Params\NetworkAddress entry only
    # means the driver doesn't expose "Network Address" in Device Manager's
    # Advanced tab (a GUI registration). It does NOT prove the driver ignores
    # the NetworkAddress registry value on init - that's a separate NDIS-layer
    # mechanism many drivers honour regardless. So we always attempt and let
    # the before/after comparison be the source of truth.
    gui_property = driver_supports_network_address(subkey)
    if not gui_property:
        info(f"note: {target['interface']!r} does not expose a 'Network "
             f"Address' advanced property (Device Manager GUI). That doesn't "
             f"decide whether the driver honours the registry override, so "
             f"attempting anyway.")

    step(f"Writing NetworkAddress={mac_hex} to registry key {subkey}")
    if not set_registry_mac(subkey, mac_hex):
        die("registry write failed - are you really running elevated?")

    _restart_for_mac_change(target["interface"])
    info("waiting for the adapter to come back up...")
    after = _wait_for_adapter(target["interface"]) or target

    changed = normalise_mac(after.get("mac")) != normalise_mac(original_mac)
    if changed:
        ok(f"spoofed: {original_mac} -> {after.get('mac')}")
    else:
        warn(f"DID NOT CHANGE: {original_mac} -> {after.get('mac')}")
        warn("the registry write took but the driver did not apply it after a "
             "PnP restart. This is common on Wi-Fi (802.11 ties association to "
             "the MAC, and many Wi-Fi drivers - especially newer 6/6E ones - "
             "refuse a registry override); wired Ethernet usually accepts it. "
             "Try 'spoof --interface Ethernet', or another laptop.")
    return {"changed": changed, "old_mac": original_mac, "new_mac": after.get("mac"),
            "adapter": after, "gui_property": gui_property}


def restore_mac(interface: str) -> dict:
    """Clear the NetworkAddress override via registry + restart, so the
    adapter falls back to its hardware MAC. No prompts."""
    require_admin("restoring the MAC writes to HKLM and needs an elevated shell")
    if not winreg:
        die("winreg is unavailable - this only runs on Windows")

    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        die(f"adapter {interface!r} not found")
    spoofed_mac = target.get("mac")

    subkey = find_adapter_registry_key(target.get("adapter_description") or "",
                                       interface_name=target["interface"])
    if not subkey:
        die(f"could not find the registry key for {target['interface']!r}")

    step(f"Clearing NetworkAddress override on registry key {subkey}")
    clear_registry_mac(subkey)

    _restart_for_mac_change(target["interface"])
    info("waiting for the adapter to come back up...")
    after = _wait_for_adapter(target["interface"]) or target

    expected = config.expected_mac()
    restored = (normalise_mac(after.get("mac")) == normalise_mac(expected)) if expected else None
    if restored is True:
        ok(f"restored to hardware MAC {after.get('mac')}")
    elif restored is False:
        warn(f"now showing {after.get('mac')}, expected {expected} - check manually")
    else:
        ok(f"NetworkAddress override cleared; adapter now shows {after.get('mac')}")
    return {"restored": restored, "spoofed_mac": spoofed_mac, "mac": after.get("mac"),
            "adapter": after}


# --------------------------------------------------------------------------
# Other actions
# --------------------------------------------------------------------------


def restart_adapter(interface: str, assume_yes: bool = False) -> bool:
    """Disable then re-enable the adapter so a new MAC takes effect."""
    if not is_admin():
        warn("restarting an adapter needs an elevated shell - skipping.\n"
             "    Re-run from PowerShell 'Run as administrator'.")
        return False

    if not assume_yes and not confirm(
            f"disable and re-enable {interface!r}? You will drop off the "
            f"network for a few seconds.", default=False):
        info("skipped")
        return False

    for state in ("disabled", "enabled"):
        step(f"netsh: {state} {interface}")
        result = run(["netsh", "interface", "set", "interface",
                      f"name={interface}", f"admin={state}"], timeout=60)
        if result.returncode != 0:
            warn(f"netsh failed: {(result.stderr or result.stdout).strip()}")
            return False
    ok("adapter restarted - give Windows a few seconds to reconnect")
    return True


def verify(expected: str | None, interface: str | None = None) -> int:
    """Compare the adapter's current MAC against an expected value."""
    interface = interface or config.spoof_interface()
    expected = normalise_mac(expected or config.expected_mac())
    if not expected:
        die("nothing to verify against.\n"
            "    Pass --expected AA-BB-CC-DD-EE-FF, or record this laptop's "
            "real MAC in shared/config.py (HOSTS -> mac).")

    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        die(f"adapter {interface!r} not found")

    current = normalise_mac(target.get("mac"))
    step(f"Verifying {target['interface']}")
    print(f"    expected : {expected}")
    print(f"    current  : {current}")

    if current == expected:
        ok("MATCH - the adapter is using the expected MAC")
        return 0
    warn("DIFFERENT - the adapter is not using the expected MAC "
         "(that is a pass if you just spoofed it, and a fail if you just "
         "restored it)")
    return 1


def print_report() -> int:
    if not config.MAC_LOG_JSON.exists():
        die(f"no log yet at {rel(config.MAC_LOG_JSON)} - run "
            f"'python mac_control.py demo' first.")
    log = read_json(config.MAC_LOG_JSON)
    entries = log.get("entries", [])
    if not entries:
        die("the log is empty")

    step(f"MAC log for {log.get('host')} ({len(entries)} entries)")
    print_table([[e["stage"], e["timestamp"][11:19], e["interface"],
                  e.get("mac") or "-", e.get("ipv4") or "-",
                  (e.get("note") or "")[:38]] for e in entries],
                ["STAGE", "TIME", "INTERFACE", "MAC", "IPv4", "NOTE"])

    before, after = last_entry(log, "before"), last_entry(log, "after")
    restored = last_entry(log, "restored")

    step("Result")
    if before and after:
        changed = normalise_mac(before.get("mac")) != normalise_mac(after.get("mac"))
        (ok if changed else warn)(
            f"spoof: {before.get('mac')} -> {after.get('mac')} "
            f"({'changed' if changed else 'UNCHANGED - the spoof did not take'})")
    if before and restored:
        back = normalise_mac(before.get("mac")) == normalise_mac(restored.get("mac"))
        (ok if back else warn)(
            f"restore: {restored.get('mac')} "
            f"({'back to the original' if back else 'NOT restored - fix this before you finish'})")
    return 0


# --------------------------------------------------------------------------
# The automated demo - this is what gets run in the presentation
# --------------------------------------------------------------------------


def demo(interface: str, assume_yes: bool, new_mac: str | None) -> int:
    banner("PHASE 3 - MAC SPOOFING (AUTOMATED)")
    info("scope: this laptop's own adapter, changed and then restored")
    info(f"target adapter: {interface}")
    require_admin("this demo changes the adapter's MAC via the registry")

    step("1. Current state (before)")
    adapters = read_adapters()
    show_adapters(adapters, highlight=interface)
    before = snapshot("before", note="pre-spoof baseline", interface=interface)
    original = before.get("mac")

    step("2. Spoofing (registry write + adapter restart, no manual steps)")
    result = spoof_mac(interface, new_mac=new_mac)
    if result["changed"]:
        info("the new address has the locally-administered bit set "
             "(second hex digit 2/6/A/E) - that marks it as not a real "
             "vendor's burned-in address, the same convention OS privacy-MAC "
             "features use")

    step("3. Verify (after)")
    after = snapshot("after", note="post-spoof", interface=interface)
    if result["changed"]:
        ok(f"spoof confirmed: {original} -> {after.get('mac')}")
        info("this is the moment for Member 1 to re-run "
             "'python phase1_discovery/scan.py --discovery-only' - the "
             "laptop reappears under a different MAC.")
    else:
        warn("the MAC did not change. Common causes: not running elevated, "
             "or the driver refuses NetworkAddress overrides. Try "
             "'restart-adapter' manually, or use a different adapter.")

    step("4. Live re-scan handoff")
    if assume_yes:
        info("--yes set: skipping the pause for the live re-scan")
    else:
        pause("   Press Enter once Member 1's live re-scan is done...")

    step("5. Restore")
    restore_mac(interface)
    restored = snapshot("restored", note="post-restore", interface=interface)
    if normalise_mac(restored.get("mac")) == normalise_mac(original):
        ok(f"restored to {original} - the laptop is back to its real identity")
    else:
        warn(f"still showing {restored.get('mac')}, expected {original}. "
             f"Run 'python mac_control.py restore' again or check manually.")

    print_report()
    step("Next")
    info(f"{rel(config.MAC_LOG_JSON)} is the evidence for the Phase 3 "
         f"slide; Phase 4 picks it up automatically if it is present.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3 - MAC spoofing control")
    parser.add_argument("--interface", help="adapter name (default: shared/config.py)")
    parser.add_argument("--yes", action="store_true",
                        help="do not ask before restarting the adapter, and "
                             "skip the live-rescan pause in 'demo'")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("view", help="show adapters and their MACs")

    demo_p = sub.add_parser("demo", help="automated before -> spoof -> verify -> restore")
    demo_p.add_argument("--mac", help="MAC to spoof to (default: random, locally-administered)")

    sub.add_parser("report", help="print the before/after log")
    sub.add_parser("restart-adapter", help="disable + re-enable the adapter")

    spoof_p = sub.add_parser("spoof", help="change the MAC via registry + restart, no prompts")
    spoof_p.add_argument("--mac", help="MAC to spoof to (default: random, locally-administered)")

    sub.add_parser("restore", help="clear the MAC override via registry + restart")

    snap = sub.add_parser("snapshot", help="record the current MAC")
    snap.add_argument("--stage", choices=STAGES, default="adhoc")
    snap.add_argument("--note")

    check = sub.add_parser("verify", help="compare current MAC to an expected one")
    check.add_argument("--expected", help="MAC to expect (default: shared/config.py)")

    args = parser.parse_args()
    interface = args.interface or config.spoof_interface()
    command = args.command or "view"

    if command == "view":
        banner("PHASE 3 - ADAPTER VIEW")
        adapters = read_adapters()
        show_adapters(adapters, highlight=interface)
        target = find_adapter(adapters, interface)
        if target:
            info(f"configured spoof target: {target['interface']} "
                 f"(MAC {target.get('mac')})")
        else:
            warn(f"adapter {interface!r} not in the list - update "
                 f"SPOOF_INTERFACE in shared/config.py")
        return 0

    if command == "snapshot":
        banner("PHASE 3 - SNAPSHOT")
        snapshot(args.stage, note=args.note, interface=interface)
        return 0

    if command == "verify":
        banner("PHASE 3 - VERIFY")
        return verify(args.expected, interface)

    if command == "restart-adapter":
        banner("PHASE 3 - RESTART ADAPTER")
        return 0 if restart_adapter(interface, assume_yes=args.yes) else 1

    if command == "spoof":
        banner("PHASE 3 - SPOOF")
        snapshot("before", note="pre-spoof (via 'spoof' command)", interface=interface)
        result = spoof_mac(interface, new_mac=getattr(args, "mac", None))
        snapshot("after", note="manual spoof", interface=interface)
        return 0 if result["changed"] else 1

    if command == "restore":
        banner("PHASE 3 - RESTORE")
        result = restore_mac(interface)
        snapshot("restored", note="manual restore", interface=interface)
        return 0 if result.get("restored") is not False else 1

    if command == "report":
        banner("PHASE 3 - MAC LOG")
        return print_report()

    if command == "demo":
        return demo(interface, assume_yes=args.yes, new_mac=getattr(args, "mac", None))

    parser.print_help()
    return 1


if __name__ == "__main__":
    if sys.platform != "win32":
        warn("this script uses Windows tools (getmac / ipconfig / netsh / "
             "the registry) and only runs on Windows")
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        raise SystemExit(130)
