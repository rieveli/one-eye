# Demo video script (about 7 minutes)

Built for the CDU IT Code Fair rules: **public YouTube video, max 10 minutes, about 20% intro & problem,
at least 80% live demo**, plus architecture, limitations and future work. Explain the architecture *while the app
runs*, not on slides.

**Record:** Windows Snipping Tool (**Win + Shift + R**) or OBS Studio. Edit in Clipchamp (built into Windows 11).
Upload to YouTube as **Public** (not Unlisted/Private) and put the link in the README.

**Before recording:**
- Close private tabs.
- Run Learning once so it's already in *Protect mode*, or cut the 2-minute wait.
- Start as administrator if you want to show firewall blocking.
- Use 100–125% display scaling.

## Part 1: Intro & problem (≈1:20, ~20%)

| Time | On screen | Say |
|---|---|---|
| 0:00 | Start `OneEye.exe`: animated splash | "This is One Eye, a free, open-source endpoint security tool. One eye sees all; you stay in control." |
| 0:15 | System Health, idle | "The problem: most people can't see what's running on their PC, what it connects to, or when something behaves like malware. A cryptominer, for example, hides as a normal process and just burns your CPU." |
| 0:45 | Sidebar and pages | "Antivirus says 'clean' or 'infected'. One Eye shows you *why*: apps, connections, behavior. And you decide what to do. Nothing happens without your click." |

## Part 2: Live demo (≈5:00, ~75%)

| Time | On screen | Say (and architecture to mention) |
|---|---|---|
| 1:20 | Health: cards, top apps, Publisher column | "Every app is grouped. Chrome's 30 processes are one row. We read all processes in one Windows call, which made sampling 35× faster than our first version." |
| 1:50 | Point at "One Eye itself: … MB" | "It measures itself. A security tool shouldn't be the thing slowing you down." |
| 2:00 | Publisher column (Microsoft, Mozilla, Unsigned) | "We check code signatures. A signed app from a real publisher is lower risk; an unsigned app from Temp is high risk." |
| 2:20 | Settings → **Run demo threat** | "Now a harmless fake cryptominer. It only uses CPU and stops by itself." |
| 2:30 | Health: red row, eye pulsing, HIGH alerts | "Two engines catch it. Rules see sustained CPU from an unsigned, unknown app. Machine learning learned what's normal for *this* PC, each app against its own baseline, and scores this 0.99." |
| 3:05 | Right-click → **Freeze** → **End process** | "Incident response: contain first. Freeze keeps it for investigation, then end it." |
| 3:25 | **Analyze with AI** → answer; **Show data sent** | "The AI explains in plain English. It gets a redacted snapshot, with no username or PC name, and it can't press any button. A test proves it has no access to the action code." |
| 4:00 | Connections page | "Every connection: which app, which IP, which country, and risk from threat feeds that update daily, all checked locally." |
| 4:25 | Settings → **Create demo files** → Scanner → **Quick scan: Downloads** | "The scanner matches SHA-256 hashes against MalwareBazaar's list of recent malware, plus heuristics like a double extension." |
| 4:50 | Select MALICIOUS → **Quarantine** → show Restore / Delete | "Quarantine is reversible: the file is scrambled so it can't run." |
| 5:10 | Response page: action log (and Block IP `203.0.113.66` if admin) | "Every action is logged, an audit trail. Firewall rules only touch One Eye's own rules." |
| 5:35 | Health → **Focus mode**; right-click → **Trust** | "Gaming or rendering? Focus mode pauses performance alerts; security alerts stay on. Trusted apps are matched by name *and* path." |
| 5:55 | Settings: Simple / Advanced toggle | "Simple mode for everyone, Advanced for people who want engines and tuning." |

## Part 3: Architecture, limitations, future (≈1:00)

| Time | On screen | Say |
|---|---|---|
| 6:15 | README architecture diagram (scroll on GitHub) | "Core logic is separate from the UI and unit-tested. Monitoring runs in a background thread. Data stays on the PC." |
| 6:35 | README limitations | "Honest limits: it's not a replacement for antivirus, it has no real-time driver, it's Windows only, the ML needs a learning period, and the app isn't code-signed yet." |
| 6:55 | README future work | "Next: a background service, startup-persistence checks, scheduled scans and signed releases." |
| 7:10 | Splash / GitHub page | "It's free and open source on GitHub. Thanks for watching." |

Tips: keep the mouse still while talking, zoom in on small details, and cut waiting time when editing.
Mention briefly that AI assistance was used and that docs/CONTRIBUTIONS.md explains who did what.
