# Phase 3 — MAC Spoofing (Member 3)

Change your laptop's hardware address, prove the network accepts the new
identity, then put it back. The point is not the trick — it is the conclusion:
**a MAC address is not an authentication credential, and anything that treats it
as one is broken.**

## What you install

Nothing extra. `mac_control.py` is Python standard library only — it spoofs by
writing the adapter's `NetworkAddress` override directly into the Windows
registry and restarting the adapter, then restores by deleting that value. This
is the same mechanism third-party MAC-spoofing tools use under the hood; the
script just skips the GUI in front of it, so the whole cycle runs unattended
instead of needing someone to click through a tool live in front of the class.

You do need **Administrator**: writing to `HKLM` and restarting an adapter both
require it.

## Before you automate anything: understand the layers

Run this and look at what comes back:

```bash
getmac /v
ipconfig /all
```

The **physical address** is burned into the network card, but Windows lets a
registry value (`NetworkAddress`, under the adapter's driver key) override it —
that's the entire mechanism, no more and no less. Meanwhile the **IP address**
is assigned by DHCP and is a completely separate identity. Being clear about
which layer you are changing (layer 2, not layer 3) is the difference between
explaining this well and hand-waving.

Set `SPOOF_INTERFACE` in `shared/config.py` to your adapter name — run
`python mac_control.py view` to see the exact names.

## How to run it

The main event is the automated demo, which walks the whole cycle and logs
every stage, with no manual step in the middle:

```bash
python mac_control.py demo
```

It will: snapshot your real MAC → write a new one to the registry and restart
the adapter → verify the change actually took → pause for the live Nmap
re-scan → clear the override and restart again → verify you are back to the
original.

| Command | What it does |
|---|---|
| `python mac_control.py view` | List adapters with their MACs and IPs |
| `python mac_control.py demo` | **The presentation script.** Automated before → spoof → verify → restore |
| `python mac_control.py spoof` | Just the spoof (registry write + restart), no prompts. `--mac AA-BB-CC-DD-EE-FF` to pick a specific address |
| `python mac_control.py restore` | Just the restore (clear the override + restart), no prompts |
| `python mac_control.py snapshot --stage before` | Record current state (stages: `before`, `after`, `restored`, `adhoc`) |
| `python mac_control.py verify --expected AA-BB-CC-DD-EE-FF` | Check the adapter against an expected MAC |
| `python mac_control.py restart-adapter` | Disable + re-enable the adapter (needs Administrator; asks to confirm unless `--yes`) |
| `python mac_control.py report` | Print the before/after table from the log |

**Run from an Administrator terminal.** Everything above that touches the
registry or restarts the adapter needs it; without elevation the script fails
fast with a clear message instead of doing something halfway.

### The address it spoofs to

If you don't pass `--mac`, the script generates a random address with the
**locally-administered bit set** (the second hex digit of the first octet is
2/6/A/E) and the multicast bit clear. That's not an arbitrary choice — it's the
standard way to mark an address as *not* a real vendor's burned-in MAC, and
it's the same convention Android/iOS/Windows Wi-Fi privacy features use for
per-network random addresses. It also means you're not gambling on picking a
fake vendor prefix that happens to collide with a real device on the network.
Worth a sentence on the slide.

## What it produces

Both in `outputs/`.

| File | What it is |
|---|---|
| `mac_log.json` | Full snapshots at every stage: timestamp, interface, MAC, IPv4, whether the shell was elevated, plus every other adapter for cross-checking |
| `mac_log.csv` | Flat before/after/restored log — this is your slide table |

Phase 4 picks `mac_log.json` up automatically if it exists and turns a
successful before→after change into a finding about MAC-based access control.

## The presentation moment

This is the bit that ties the whole project together:

1. You run `python mac_control.py demo` — it changes your MAC in a couple of
   seconds, no clicking required.
2. **Member 1 immediately re-runs** `python phase1_discovery/scan.py --discovery-only`.
3. Your laptop shows up under a different hardware address — from Nmap's point
   of view, a device that was never there before.
4. `demo` pauses right at this point waiting for Enter, so you control the
   timing — restore happens the moment you continue.

Have Member 1's command already typed into a terminal so it is one keypress.
Since there's no GUI step to fumble, the whole handoff is just: run `demo`,
wait for the pause, nod at Member 1, hit Enter.

## When it does not work

**"this needs an Administrator shell".** Re-open the terminal as Administrator
— every registry write and adapter restart requires it, and the script checks
this upfront rather than failing halfway through.

**The MAC does not change.** Second most common cause after not being
elevated: the driver refuses `NetworkAddress` overrides outright. Some Wi-Fi
drivers — Intel ones especially — do this; Realtek and MediaTek generally
accept it. If yours refuses, try the Ethernet adapter instead (`--interface
Ethernet`), or use a teammate's laptop for the demo and explain the driver
restriction. That restriction is itself worth a sentence in the report.

**You lose network access after spoofing.** Expected for a few seconds while
the adapter restarts and DHCP re-leases. `spoof_mac`/`restore_mac` poll for the
adapter to come back rather than trusting a fixed delay, so the script itself
waits this out; if it's still down after ~25s, something's wrong — check
`ipconfig` directly.

**`getmac` and `ipconfig` disagree.** The log records both when they differ.
Usually means the adapter hasn't been restarted since a registry change, so it
hasn't taken effect yet.

**You cannot get back to the original.** Run `python mac_control.py restore` —
it deletes the registry override outright (not "write back the old value"),
which is the clean way back to the hardware MAC regardless of what's currently
set. `python mac_control.py report` tells you plainly whether you're back.

**Before you run anything on a laptop you haven't spoofed from before**, it's
worth checking there isn't already a leftover override sitting on the
adapter's registry key from an earlier tool or test — `mac_control.py view`
shows the *live* MAC, which only reflects a pending override after a restart,
so a stale value can be invisible until something restarts the adapter. If in
doubt, run `restore` once before your first `demo` to start from a clean slate.

## Scope and ethics

You are changing your own laptop's address, sitting in front of it, and putting
it back when you are done — that is the whole exercise. Spoofing a MAC to
impersonate another device, get past a filter you were not given access to, or
evade logging on a network you do not own is a different act with different
consequences, and it is not what this project does. Say the boundary out loud
during the presentation; it is part of the marks for understanding the risk.

**Always restore before you finish.** `python mac_control.py report` will tell
you plainly whether you did.
