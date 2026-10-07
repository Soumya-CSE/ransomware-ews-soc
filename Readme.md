# 🛡️ Ransomware Early-Warning Simulator

A **safe** blue-team project that simulates file-system activity, detects ransomware-like behaviour in real time, scores the risk per host, raises alerts, simulates containment, and records everything in a live **SOC dashboard** with incident history.

> ⚠️ **Safety disclaimer:** This is a *simulator*, not ransomware. All file events are generated in memory. No real files are read, modified, renamed, or encrypted. It is built for learning, detection engineering practice, and portfolio demonstration.

## 🎛️ Dashboard



---

## ✨ Features

- **Simulated file activity** across 5 hosts (workstations and file servers) with realistic background noise
- **Two scenarios**
  - 🔴 Ransomware attack (mass modification → rapid renames → extension changes → ransom note)
  - 🟡 Benign backup burst, used to test false positives
- **Sliding-window detection** per host with adjustable thresholds
- **Weighted risk scoring** (0–100) with Low / Medium / High / Critical levels
- **Explainable alerts**: every alert lists the exact reasons that triggered it
- **Simulated auto-containment**: Critical hosts are isolated and the attack stops
- **Live SOC dashboard** built with Streamlit and Plotly
- **Incident history** stored in SQLite, with filtering, charts and CSV export
- **Metrics**: time-to-detect (TTD) and number of files affected before containment

---

## 🧠 How it works

```
Simulated file events
        ↓
Sliding window (last N seconds, per host)
        ↓
Indicators: modifications · renames · suspicious extensions · entropy · ransom note
        ↓
Weighted risk score (0–100)
        ↓
Level escalation → 🚨 ALERT → incident saved to SQLite
        ↓
Critical → host isolated (simulated)
```

### Risk score

| Indicator (per host, within the window) | Max points |
|---|---|
| Mass file modifications | 25 |
| Rapid rename operations | 25 |
| Renames to suspicious extensions (`.locked`, `.enc`, `.crypt`, …) | 25 |
| High write entropy (encrypted data looks random) | 15 |
| Ransom-note filename created (e.g. `README_DECRYPT.txt`) | 10 |

| Score | Level |
|---|---|
| < 30 | 🟢 Low |
| 30 – 59 | 🟡 Medium |
| 60 – 79 | 🟠 High |
| ≥ 80 | 🔴 Critical |

Each indicator is `min(observed / threshold, 1) × weight`, so no single signal can reach 100 on its own. A backup job produces many modifications but low entropy and no suspicious extensions, so it stays at Medium, while ransomware lights up every indicator together.

An alert fires on every **escalation** (for example Low → Medium → Critical) and re-arms when the score falls below 30, which avoids alert fatigue.

---

## 🚀 Getting started

**Requirements:** Python 3.9+

```bash
git clone https://github.com/<your-username>/ransomware-early-warning-simulator.git
cd ransomware-early-warning-simulator

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

Then open the URL Streamlit prints (usually `http://localhost:8501`) and press **▶ Start / continue** in the sidebar.

---

## 🎛️ Using the dashboard

| Control | What it does |
|---|---|
| Ransomware attack scenario | Turns the simulated attack on or off |
| Attack target host / start time | Chooses which host is hit and when |
| Benign backup burst | Adds a harmless high-activity job to test false positives |
| Sliding window | How many seconds of history the detector looks at |
| Detection thresholds | Modifications, renames, extension changes, entropy |
| Auto-contain on Critical | Isolates the host when the score reaches Critical |
| Run length / tick delay | How long and how fast the simulation runs |

**Dashboard panels:** key metrics, host risk bars, risk-score timeline, alert feed, per-host score breakdown, and recent file events. The **Incident History** tab shows every saved alert with filters, charts and CSV export. The **Detection Logic** tab documents the scoring model.

### Experiments to try

- **Raise the thresholds**: detection gets slower and more files are hit (sensitivity vs. speed).
- **Lower them too far**: the backup burst starts triggering High or Critical (false positive).
- **Turn off auto-contain**: the attack continues and the score stays near 100.
- **Shorten the window**: the score reacts faster but becomes noisier.

---

## 🗂️ Project structure

```
ransomware-early-warning-simulator/
├── app.py            # simulator, detector, scoring, alerting, dashboard
├── requirements.txt
├── .gitignore
├── README.md
└── screenshots/      # dashboard images for this README
```

`incidents.db` is created automatically on first run and is git-ignored.

---

## 🧩 MITRE ATT&CK mapping

| Technique | Relevance |
|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | Mass modification, high entropy, extension changes |
| [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery | Ransom-note and recovery-related behaviour (planned detection) |

---

## 🔭 Roadmap

- [ ] Monitor a real **test folder** with `watchdog` and feed events into the same detector
- [ ] Ingest **Sysmon** events (Event ID 11 file create, 23 file delete)
- [ ] Per-process and per-host **baselining** instead of fixed thresholds
- [ ] **Canary / honeypot files** that alert on first touch
- [ ] Email / Slack alert notifications
- [ ] Detection of shadow-copy deletion (T1490)
- [ ] Unit tests for the scoring function

---

## 🛠️ Tech stack

Python · Streamlit · Pandas · Plotly · SQLite

---

## 📄 License

Released under the MIT License. For educational and defensive security use only.

---

## 👤 Author

**Soumya Kanti Hazra**, B.Tech Computer Science Engineering student and aspiring SOC Analyst.