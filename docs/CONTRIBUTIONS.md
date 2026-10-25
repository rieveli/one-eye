# Team contributions & AI-assisted development


## Team

| Member | Role | Main contributions |
|---|---|---|
| ✏️ Veli | ✏️ creator | ✏️ |

## What the team did

These decisions came from the creator; the AI assistant implemented and refined them.

- **Problem and idea:** a free, local security tool that shows which apps and connections use the PC, spots
  unusual behavior, and lets the user act. It started as "antivirus + performance checker + IP analyzer + firewall".
- **Scope :** one app with focused modules instead of a full antivirus or firewall driver.
- **Native desktop app (PySide6) instead of a web UI:** chosen for a lower footprint and a smaller attack surface
  (see [DECISIONS.md](DECISIONS.md) §1).
- **"AI is advisory only":** the AI may explain but never change the system.
- **Machine learning:** asked whether ML was needed, then chose live-trained anomaly detection over a downloaded model.
- **Plugins from GitHub:** proposed; refined into *data-only plugins* (YARA rules, threat lists) plus separate engines
  (ClamAV), never downloaded code, for supply-chain safety.
- **Simple / Advanced mode**, **built-in demo tools** so testers without Python can try it, and the question
  "how does it know a game or render is safe?", which led to code signing, Trust and Focus mode.
- **Response actions:** quarantine, freezing/ending processes, blocking network access.
- **Daily threat-feed updates.**
- **Name, logo, and visual identity:** "One Eye", the eye logo, and the red / dark grey / white theme.
- **Open source** under MIT.
- **Testing on real hardware** and reviewing results and screenshots.

## How AI was used

- **Tool:** Claude Code (Anthropic), used as a pair programmer during development.
- **What it did:**
  - wrote/helped of the source code, tests and documentation from the team's requirements
  - profiled and fixed problems
  - ran the automated tests and GUI screenshot tours
- **Problems found during AI-assisted testing and fixed** :
  - sampling took 2.5 s because of an O(n²) process lookup; replaced with one Windows API call (0.07 s)
  - the first ML version flagged big normal apps; redesigned with per-app baselines
  - an admin-mode privilege-escalation risk (a pickle file in a user-writable folder); replaced with JSON
  - startup took 20 s; heavy libraries now load lazily
- **The local AI inside the app** (Ollama / Claude) is a product feature, separate from development help.


## Third-party code and data

All libraries and threat-data sources are listed with their licenses in the [README](../README.md#credits--licenses).
No third-party source code was copied into this repository.
