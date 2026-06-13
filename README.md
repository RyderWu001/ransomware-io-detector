# Ransomware Dynamic Defender — Pixel Art EDR Sandbox

An interactive browser-based simulation that visualises how Endpoint Detection & Response (EDR) systems detect and respond to ransomware, and where they fall short.

Built as a single-file `index.html` — no server, no dependencies to install. Open and run.

![Stage Select](https://img.shields.io/badge/Stages-5-blueviolet) ![Single File](https://img.shields.io/badge/Single%20File-HTML-orange)

---

## What It Demonstrates

The simulation walks through five attack/defense scenarios, each building on the last:

| Stage | Name | Concept |
|---|---|---|
| 1 | **NO DEFENSE** | Ransomware with zero EDR — all 12 files encrypted, game over |
| 2 | **CRYPTODROP** | Behavioral detection: bulk write + entropy spike triggers guard |
| 3 | **FALSE POSITIVE** | Legit compression tool looks identical to ransomware — CoW backups + overwrite-rate check prevent a false block |
| 4A | **HONEYFILE** | Decoy files planted by the manager; attacker touches one → instant trap |
| 4B | **STEALTH EXFIL** | Read-only exfiltration bypasses all EDR signals — entropy stays flat, I/O stays low, guard sees nothing |

---

## Stage 4B — Attacker Wins

Stage 4B lets the player **choose the attack skill** by clicking the Pepe character:

- 👻 **Ghost Sweep** — instant full-scan with afterimage visual effect
- 🐢 **Slow Crawl** — desk-by-desk walk, mimicking a slow legitimate process
- ⌨️ **Keylogger Drop** — installs credential harvesters on every workstation

All three bypass the EDR. The conclusion: **Network DLP is required** to catch read-only exfiltration.

---

## Key Technologies Simulated

- **CryptoDrop** (Scaife et al., 2016) — 3-rule behavioral detection: bulk writes, high entropy, file-type funneling
- **ShieldFS** (Continella et al., 2017) — CoW-based file protection, ML confidence scoring, false-positive mitigation
- **Honeyfile / Deception Defense** — zero-trust decoy trap
- **Stealth Exfiltration** — read-only attack that produces no write footprint

---

## How to Run

```
# Just open the file in any modern browser
open index.html
```

No build step. No npm. No server required.

---

## Controls

- **Click a Stage button** (left panel) to start a scenario
- **Click any file icon** on the canvas to inspect its forensic data
- **Click Pepe** in Stage 4B to open the skill selection menu
- **⚡ 3× SPEED** — toggle fast mode
- **⟳ Reset** — restart the current scenario

---

## Academic References

- Scaife, N. et al. (2016). *CryptoDrop: Detecting Ransomware via Behavioral Analysis.* IEEE ICDCS.
- Continella, A. et al. (2017). *ShieldFS: A Self-Healing, Ransomware-Aware Filesystem.* ACSAC.
