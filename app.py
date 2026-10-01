"""
Ransomware Early-Warning Simulator  (SAFE: events are simulated in memory only,
no real files are read, modified or encrypted).

Pipeline:  simulated file events -> sliding-window detector -> risk score
           -> alerts -> auto-containment (simulated) -> SQLite incident history
Run:  streamlit run app.py
"""
import random, sqlite3, time
from collections import deque
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

DB = "incidents.db"
HOSTS = ["WS-HR-01", "WS-DEV-02", "WS-FIN-03", "FILESRV-01", "FILESRV-02"]
USERS = ["alice", "bob", "carol", "dave", "svc_backup"]
DOC_EXT = [".docx", ".xlsx", ".pdf", ".jpg", ".txt", ".pptx"]
SUSP_EXT = {".locked", ".enc", ".crypt", ".xyz", ".wncry", ".encrypted"}
NOTE_NAMES = {"README_DECRYPT.txt", "HOW_TO_RECOVER.html", "RESTORE_FILES.txt"}
LEVELS = ["Low", "Medium", "High", "Critical"]
RANK = {l: i for i, l in enumerate(LEVELS)}
COLORS = {"Low": "#2ecc71", "Medium": "#f1c40f", "High": "#e67e22", "Critical": "#e74c3c"}


# ----------------------------------------------------------------- storage
def db_init():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, host TEXT, level TEXT,
            score REAL, reasons TEXT, files_affected INTEGER, ttd_seconds INTEGER,
            action TEXT)""")


def db_add(row):
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO incidents(ts,host,level,score,reasons,files_affected,"
                  "ttd_seconds,action) VALUES(?,?,?,?,?,?,?,?)", row)


def db_all():
    with sqlite3.connect(DB) as c:
        return pd.read_sql("SELECT * FROM incidents ORDER BY id DESC", c)


def db_clear():
    with sqlite3.connect(DB) as c:
        c.execute("DELETE FROM incidents")


# ----------------------------------------------------------------- engine
class Engine:
    def __init__(self):
        self.t, self.total = 0, 0
        self.t0 = datetime.now().replace(microsecond=0)
        self.win = {h: deque() for h in HOSTS}
        self.state = {h: dict(score=0.0, level="Low", status="Healthy", alerted=0,
                              parts={}) for h in HOSTS}
        self.events, self.timeline, self.alerts = [], [], []
        self.attack_host = self.attack_start = None
        self.affected, self.detected_at = 0, None

    def ts(self):
        return (self.t0 + timedelta(seconds=self.t)).strftime("%H:%M:%S")

    def ev(self, host, user, proc, act, path, old="", new="", ent=4.0, mal=False):
        return dict(t=self.t, time=self.ts(), host=host, user=user, process=proc,
                    action=act, path=path, old_ext=old, new_ext=new,
                    entropy=round(ent, 2), _mal=mal)

    # ---- simulated activity generators
    def gen(self, opts):
        out = []
        for h in HOSTS:                                   # normal background noise
            for _ in range(random.choice([0, 1, 1, 2, 3])):
                e = random.choice(DOC_EXT)
                out.append(self.ev(h, random.choice(USERS[:4]),
                                   random.choice(["winword.exe", "excel.exe", "explorer.exe"]),
                                   random.choice(["MODIFY", "MODIFY", "CREATE"]),
                                   f"C:/Users/docs/file{random.randint(1,999)}{e}", e, e,
                                   random.uniform(3.0, 5.5)))
        if opts["backup"] and opts["backup_start"] <= self.t < opts["backup_start"] + 25:
            h = "FILESRV-02"                              # benign burst (false-positive test)
            for i in range(random.randint(22, 32)):
                out.append(self.ev(h, "svc_backup", "backup_agent.exe", "MODIFY",
                                   f"D:/shares/data{random.randint(1,999)}.dat", ".dat", ".dat",
                                   random.uniform(4.5, 6.0)))
            for i in range(random.randint(3, 6)):
                out.append(self.ev(h, "svc_backup", "backup_agent.exe", "RENAME",
                                   f"D:/backup/old{i}.bak", ".bak", ".old", random.uniform(4.5, 6.0)))
        if opts["attack"] and self.t >= opts["attack_start"]:
            h = opts["target"]
            if self.attack_host is None:
                self.attack_host, self.attack_start = h, self.t
            if self.state[h]["status"] != "ISOLATED":
                el = self.t - self.attack_start
                n = min(10 + 4 * el, 45)
                for i in range(n):
                    old = random.choice(DOC_EXT)
                    p = f"C:/Users/finance/doc{random.randint(1,9999)}"
                    ent = random.uniform(7.4, 7.99)
                    if el >= 3 and i % 2:                 # phase 2: rename + extension change
                        out.append(self.ev(h, "bob", "svch0st.exe", "RENAME", p + old,
                                           old, random.choice(sorted(SUSP_EXT)), ent, True))
                    else:                                  # phase 1: mass modification
                        out.append(self.ev(h, "bob", "svch0st.exe", "MODIFY", p + old,
                                           old, old, ent, True))
                if el >= 6:                                # phase 3: ransom note drop
                    out.append(self.ev(h, "bob", "svch0st.exe", "CREATE",
                                       "C:/Users/finance/" + random.choice(sorted(NOTE_NAMES)),
                                       "", ".txt", 3.5, True))
        return out

    # ---- detector: sliding window + weighted risk score (0-100)
    def score(self, host, c):
        w = self.win[host]
        mods = sum(e["action"] == "MODIFY" for e in w)
        rens = sum(e["action"] == "RENAME" for e in w)
        extc = sum(e["action"] == "RENAME" and e["new_ext"] in SUSP_EXT for e in w)
        ents = [e["entropy"] for e in w if e["action"] in ("MODIFY", "RENAME")]
        ment = sum(ents) / len(ents) if ents else 0
        note = any(e["action"] == "CREATE" and e["path"].split("/")[-1] in NOTE_NAMES for e in w)
        parts = {
            "mods": min(mods / c["mod_thr"], 1) * 25,
            "renames": min(rens / c["ren_thr"], 1) * 25,
            "ext_change": min(extc / c["ext_thr"], 1) * 25,
            "entropy": max(0, min((ment - 5) / 3, 1)) * 15 if ment >= c["ent_thr"] - 1.5 else 0,
            "ransom_note": 10 if note else 0,
        }
        why = []
        if mods >= c["mod_thr"]: why.append(f"{mods} file modifications in {c['window']}s (thr {c['mod_thr']})")
        if rens >= c["ren_thr"]: why.append(f"{rens} rapid renames (thr {c['ren_thr']})")
        if extc >= c["ext_thr"]: why.append(f"{extc} changes to suspicious extensions (thr {c['ext_thr']})")
        if ment >= c["ent_thr"]: why.append(f"high write entropy {ment:.2f} (encryption-like)")
        if note: why.append("ransom-note filename created")
        return round(sum(parts.values()), 1), parts, why

    def step(self, opts, c):
        self.t += 1
        for e in self.gen(opts):
            self.win[e["host"]].append(e)
            self.events.append(e)
            self.total += 1
            if e["_mal"] and e["action"] in ("MODIFY", "RENAME"):
                self.affected += 1
        self.events = self.events[-400:]
        for h in HOSTS:
            w = self.win[h]
            while w and w[0]["t"] <= self.t - c["window"]:
                w.popleft()
            s, parts, why = self.score(h, c)
            lvl = "Critical" if s >= 80 else "High" if s >= 60 else "Medium" if s >= 30 else "Low"
            st_ = self.state[h]
            st_.update(score=s, level=lvl, parts=parts)
            if s < 30:
                st_["alerted"] = 0
            if RANK[lvl] > st_["alerted"] and RANK[lvl] >= 1:     # escalation -> alert
                st_["alerted"] = RANK[lvl]
                action = "Monitor"
                if lvl in ("High", "Critical"):
                    action = "Analyst review"
                ttd = None
                if h == self.attack_host and self.detected_at is None:
                    self.detected_at = self.t
                    ttd = self.t - self.attack_start
                if lvl == "Critical" and c["auto_contain"]:
                    st_["status"] = "ISOLATED"
                    action = "Host isolated (simulated)"
                db_add((self.ts(), h, lvl, s, "; ".join(why) or "score threshold", 
                        self.affected if h == self.attack_host else 0, ttd, action))
                self.alerts.insert(0, dict(time=self.ts(), host=h, level=lvl, score=s,
                                           why="; ".join(why), action=action))
            self.timeline.append(dict(t=self.t, host=h, score=s, events=len(w)))


# ----------------------------------------------------------------- UI
st.set_page_config("Ransomware Early-Warning Simulator", "🛡️", layout="wide")
st.markdown("<style>.block-container{padding-top:1.2rem}</style>", unsafe_allow_html=True)
db_init()
if "eng" not in st.session_state:
    st.session_state.eng = Engine()

with st.sidebar:
    st.title("🛡️ Controls")
    st.caption("Safe simulation – no real files touched.")
    attack = st.checkbox("Ransomware attack scenario", True)
    target = st.selectbox("Attack target host", HOSTS, index=2)
    attack_start = st.slider("Attack starts at (s)", 3, 40, 10)
    backup = st.checkbox("Benign backup burst (false-positive test)", True)
    backup_start = st.slider("Backup starts at (s)", 3, 40, 5)
    st.subheader("Detection thresholds")
    cfg = dict(
        window=st.slider("Sliding window (s)", 5, 30, 10),
        mod_thr=st.slider("File modifications", 10, 100, 30),
        ren_thr=st.slider("Rapid renames", 5, 60, 15),
        ext_thr=st.slider("Suspicious ext. changes", 3, 40, 10),
        ent_thr=st.slider("Entropy threshold", 6.0, 8.0, 7.0, 0.1),
        auto_contain=st.checkbox("Auto-contain on Critical", True),
    )
    duration = st.slider("Run length (s)", 10, 90, 45)
    speed = st.slider("Tick delay (s)", 0.05, 1.0, 0.3, 0.05)
    run = st.button("▶ Start / continue", type="primary", use_container_width=True)
    if st.button("⟲ Reset simulation", use_container_width=True):
        st.session_state.eng = Engine()
        st.rerun()

eng: Engine = st.session_state.eng
opts = dict(attack=attack, target=target, attack_start=attack_start,
            backup=backup, backup_start=backup_start)

st.title("🛡️ Ransomware Early-Warning Simulator")
tab_live, tab_hist, tab_logic = st.tabs(["📡 Live SOC Dashboard", "🗂️ Incident History", "🧠 Detection Logic"])

with tab_live:
    ph = st.empty()


def render():
    with ph.container():
        s = eng.state
        m = st.columns(6)
        m[0].metric("Sim time", f"T+{eng.t}s")
        m[1].metric("Events processed", eng.total)
        m[2].metric("High/Critical hosts", sum(RANK[v["level"]] >= 2 for v in s.values()))
        m[3].metric("Peak risk score", max(v["score"] for v in s.values()))
        m[4].metric("Isolated hosts", sum(v["status"] == "ISOLATED" for v in s.values()))
        ttd = (eng.detected_at - eng.attack_start) if eng.detected_at else None
        m[5].metric("Time-to-detect", f"{ttd}s" if ttd is not None else "—",
                    f"{eng.affected} files hit" if eng.attack_host else None, delta_color="inverse")
        a, b = st.columns([3, 2])
        hosts = pd.DataFrame([dict(host=h, score=v["score"], level=v["level"], status=v["status"])
                              for h, v in s.items()])
        f1 = px.bar(hosts, x="score", y="host", color="level", color_discrete_map=COLORS,
                    orientation="h", range_x=[0, 100], text="score", title="Host risk score")
        f1.add_vline(x=30, line_dash="dot"); f1.add_vline(x=60, line_dash="dot"); f1.add_vline(x=80, line_dash="dot")
        f1.update_layout(height=300, margin=dict(l=0, r=0, t=40, b=0), showlegend=False)
        a.plotly_chart(f1, use_container_width=True, key=f"bar{eng.t}")
        tl = pd.DataFrame(eng.timeline[-600:])
        if not tl.empty:
            f2 = px.line(tl, x="t", y="score", color="host", title="Risk score timeline",
                         range_y=[0, 100])
            f2.update_layout(height=300, margin=dict(l=0, r=0, t=40, b=0))
            b.plotly_chart(f2, use_container_width=True, key=f"line{eng.t}")
        c1, c2 = st.columns([2, 3])
        with c1:
            st.subheader("🚨 Alert feed")
            for al in eng.alerts[:6]:
                txt = f"**{al['time']} · {al['host']} · {al['level']} ({al['score']})**  \n{al['why']}  \n➡ {al['action']}"
                (st.error if RANK[al["level"]] >= 2 else st.warning)(txt)
            if not eng.alerts:
                st.success("No alerts – all hosts healthy.")
        with c2:
            st.subheader("Score breakdown per host")
            br = pd.DataFrame({h: v["parts"] for h, v in s.items()}).T.fillna(0).round(1)
            br["status"] = [s[h]["status"] for h in br.index]
            st.dataframe(br, use_container_width=True)
            st.subheader("Recent file events")
            ev = pd.DataFrame(eng.events[-12:]).drop(columns=["_mal", "t"], errors="ignore")
            st.dataframe(ev.iloc[::-1], use_container_width=True, hide_index=True)


if run:
    for _ in range(duration):
        eng.step(opts, cfg)
        render()
        time.sleep(speed)
else:
    render()

with tab_hist:
    df = db_all()
    if df.empty:
        st.info("No incidents yet – run the simulation.")
    else:
        k = st.columns(4)
        k[0].metric("Total incidents", len(df))
        k[1].metric("High / Critical", int(df.level.isin(["High", "Critical"]).sum()))
        k[2].metric("Hosts affected", df.host.nunique())
        k[3].metric("Best TTD (s)", df.ttd_seconds.min() if df.ttd_seconds.notna().any() else "—")
        lv = st.multiselect("Filter by level", LEVELS, LEVELS)
        view = df[df.level.isin(lv)]
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.plotly_chart(px.histogram(view, x="host", color="level", color_discrete_map=COLORS,
                                     title="Incidents by host"), use_container_width=True)
        st.download_button("⬇ Export CSV", view.to_csv(index=False), "incidents.csv")
    if st.button("🗑 Clear history"):
        db_clear(); st.rerun()

with tab_logic:
    st.markdown("""
**Pipeline:** `File events → sliding window → indicators → risk score → alert → containment → incident DB`

| Indicator (per host, last *N* seconds) | Max weight |
|---|---|
| Mass file modifications | 25 |
| Rapid rename operations | 25 |
| Renames to suspicious extensions (`.locked`, `.enc`, `.crypt` …) | 25 |
| High write entropy (encrypted data looks random, ~7.5–8 bits/byte) | 15 |
| Ransom-note filename created | 10 |

**Levels:** Low < 30 ≤ Medium < 60 ≤ High < 80 ≤ Critical. An alert fires on every *escalation*
and re-arms once the score drops below 30. Critical triggers simulated host isolation.

**Why the backup burst matters:** it generates lots of modifications but low entropy and no
suspicious extensions, so it stays at Medium instead of Critical – a false-positive check.

**Ideas to extend:** map alerts to MITRE ATT&CK (T1486 Data Encrypted for Impact, T1490 Inhibit
System Recovery), add per-process baselining, honeypot "canary" files, and email/Slack alerting.
""")
