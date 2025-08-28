# ============================================================
# Engineering Workflow System (Login + Logo + Roadmap + APQP/PPAP)
# PHASE 1/2: Imports, DB schema, seeds, utilities, domain logic
# Paste this at the TOP of app.py
# ============================================================

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, date, timedelta
from contextlib import contextmanager
from typing import Iterable, Optional
import os, hashlib, base64, hmac, re, time

# Optional charts for Roadmap (falls back to tables if missing)
try:
    import altair as alt
except Exception:
    alt = None

DB_PATH = "workflow.db"

# ----------------------- DB Helpers -----------------------
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()

def load_table(query: str, params: Iterable = ()) -> pd.DataFrame:
    with get_conn() as conn:
        return pd.read_sql_query(query, conn, params=params)

def init_db():
    with get_conn() as conn:
        c = conn.cursor()

        # ---- Core entities ----
        c.execute("""CREATE TABLE IF NOT EXISTS clients(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            contact TEXT,
            email TEXT,
            notes TEXT
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS services(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            default_rate_per_hour REAL NOT NULL
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS projects(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            client_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            start_date TEXT,
            due_date TEXT,
            pricing_model TEXT DEFAULT 'T&M',        -- 'T&M' or 'Fixed'
            fixed_price REAL,
            status TEXT DEFAULT 'Planned',
            FOREIGN KEY(client_id) REFERENCES clients(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS requirements(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            service_id INTEGER NOT NULL,
            requirement_text TEXT NOT NULL,
            priority TEXT DEFAULT 'Medium',          -- Low/Medium/High
            complexity INTEGER DEFAULT 2,            -- 1-5
            estimate_hours REAL DEFAULT 0,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(service_id) REFERENCES services(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS team_members(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT,
            skills TEXT,                              -- comma-separated tags
            rate_per_hour REAL NOT NULL,
            weekly_capacity_hours REAL DEFAULT 40,
            active INTEGER DEFAULT 1
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS tasks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            requirement_id INTEGER,
            service_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            assignee_id INTEGER,
            planned_hours REAL DEFAULT 0,
            status TEXT DEFAULT 'Not Started',
            start_date TEXT,
            due_date TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(requirement_id) REFERENCES requirements(id),
            FOREIGN KEY(service_id) REFERENCES services(id),
            FOREIGN KEY(assignee_id) REFERENCES team_members(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS time_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            member_id INTEGER NOT NULL,
            log_date TEXT NOT NULL,
            hours REAL NOT NULL,
            note TEXT,
            FOREIGN KEY(task_id) REFERENCES tasks(id),
            FOREIGN KEY(member_id) REFERENCES team_members(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS deliverables(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'Planned',
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS invoices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            period_start TEXT,
            period_end TEXT,
            amount REAL NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );""")

        # ---- Users (auth) ----
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin','user')),
            team_member_id INTEGER,
            active INTEGER DEFAULT 1,
            FOREIGN KEY(team_member_id) REFERENCES team_members(id) ON DELETE SET NULL
        );""")

        # ---- APQP ----
        c.execute("""CREATE TABLE IF NOT EXISTS apqp_stages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            phase INTEGER NOT NULL,                 -- 1..5
            name TEXT NOT NULL,
            owner_member_id INTEGER,
            start_date TEXT, due_date TEXT,
            status TEXT DEFAULT 'Not Started',
            percent_complete REAL DEFAULT 0,
            notes TEXT,
            UNIQUE(project_id, phase),
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(owner_member_id) REFERENCES team_members(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS apqp_deliverables(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            stage_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            required INTEGER DEFAULT 1,
            owner_member_id INTEGER,
            due_date TEXT,
            status TEXT DEFAULT 'Not Started',     -- Not Started / In Progress / Done / N/A
            file_path TEXT,
            notes TEXT,
            updated_at TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(stage_id) REFERENCES apqp_stages(id),
            FOREIGN KEY(owner_member_id) REFERENCES team_members(id)
        );""")

        # ---- PPAP ----
        c.execute("""CREATE TABLE IF NOT EXISTS ppap_info(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL UNIQUE,
            level INTEGER NOT NULL,                -- 1..5
            submission_date TEXT,
            approve_status TEXT DEFAULT 'Draft',   -- Draft/In Review/Submitted/Approved/Rejected
            customer TEXT,
            notes TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );""")

        c.execute("""CREATE TABLE IF NOT EXISTS ppap_elements(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            status TEXT DEFAULT 'Not Started',     -- Not Started/In Progress/Complete/N/A
            owner_member_id INTEGER,
            file_path TEXT,
            updated_at TEXT,
            notes TEXT,
            required INTEGER DEFAULT 1,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(owner_member_id) REFERENCES team_members(id)
        );""")

        # Helpful indexes
        c.execute("CREATE INDEX IF NOT EXISTS ix_tasks_project ON tasks(project_id);")
        c.execute("CREATE INDEX IF NOT EXISTS ix_logs_member ON time_logs(member_id);")
        c.execute("CREATE INDEX IF NOT EXISTS ix_apqp_deliv_project ON apqp_deliverables(project_id);")
        c.execute("CREATE INDEX IF NOT EXISTS ix_ppap_elem_project ON ppap_elements(project_id);")

# ----------------------- Seeds & Imports -----------------------
def seed_services():
    """Default service catalog used by Requirements/Tasks."""
    default_services = [
        ("Mechanical Component Design", "Concept to detail design of mechanical parts", 2000),
        ("PCB Enclosure Design", "Design robust enclosures for PCBs", 1800),
        ("Die Design", "Progressive and transfer die design", 2200),
        ("Part Design", "Plastic/Sheet-metal part design with DFM/DFA", 1800),
        ("Mold Flow Simulation", "Injection molding flow and cooling analysis", 2500),
        ("Assembly & GD&T", "Assembly modeling and GD&T annotations", 2000),
        ("Fabrication Drawings", "Manufacturing-ready drawings", 1800),
        ("Thermal Simulation (PCB)", "Board-level thermal simulation", 2400),
        ("Thermal Simulation (PCB+Enclosure)", "Coupled thermal analysis", 2600),
        ("Reliability - Random Vibration", "PCB component reliability via random vibration", 2600),
        ("Project Management", "PM/Reviews/Documentation", 1500),
    ]
    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM services;")
        if (cur.fetchone()[0] or 0) == 0:
            conn.executemany(
                "INSERT INTO services(name,description,default_rate_per_hour) VALUES(?,?,?);",
                default_services
            )

def import_team_csv_if_empty(csv_path: str = "sample_data.csv") -> int:
    """If team_members is empty and sample_data.csv exists, import it. Returns rows inserted."""
    if not os.path.exists(csv_path):
        return 0
    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM team_members;")
        if (cur.fetchone()[0] or 0) > 0:
            return 0
        try:
            df = pd.read_csv(csv_path)
        except Exception:
            return 0
        required = {"name","role","skills","rate_per_hour","weekly_capacity_hours","active"}
        if not required.issubset(set(df.columns)):
            return 0
        rows = df[["name","role","skills","rate_per_hour","weekly_capacity_hours","active"]].values.tolist()
        conn.executemany("""INSERT INTO team_members(name, role, skills, rate_per_hour, weekly_capacity_hours, active)
                            VALUES(?,?,?,?,?,?);""", rows)
        return len(rows)

# ----------------------- Auth (stdlib crypto) -----------------------
def _hash_password(password: str, salt_b: bytes | None = None) -> tuple[str, str]:
    if salt_b is None:
        salt_b = os.urandom(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt_b, n=2**14, r=8, p=1)
    return base64.b64encode(key).decode("ascii"), base64.b64encode(salt_b).decode("ascii")

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    try:
        salt_b = base64.b64decode(stored_salt.encode("ascii"))
        calc_hash, _ = _hash_password(password, salt_b)
        return hmac.compare_digest(calc_hash, stored_hash)
    except Exception:
        return False

def create_user(username: str, password: str, role: str = "user", team_member_id: int | None = None):
    ph, salt = _hash_password(password)
    with get_conn() as conn:
        conn.execute("""INSERT INTO users(username,password_hash,salt,role,team_member_id,active)
                        VALUES(?,?,?,?,?,1);""", (username.strip(), ph, salt, role, team_member_id))

def seed_default_users():
    with get_conn() as conn:
        n = (conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0] or 0)
        if n == 0:
            ph1, s1 = _hash_password("admin123")
            ph2, s2 = _hash_password("user123")
            conn.executemany(
                "INSERT INTO users(username,password_hash,salt,role,team_member_id,active) VALUES(?,?,?,?,?,1);",
                [("admin", ph1, s1, "admin", None), ("user", ph2, s2, "user", None)]
            )

def authenticate(username: str, password: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND active=1;", (username.strip(),)).fetchone()
        if not row:
            return None
        if verify_password(password, row["password_hash"], row["salt"]):
            return dict(row)
        return None

# ----------------------- Branding / Files -----------------------
def get_logo_path() -> Optional[str]:
    for p in ["assets/logo.png", "assets/logo.jpg", "assets/logo.jpeg", "logo.png", "logo.jpg", "logo.jpeg", "static/logo.png"]:
        if os.path.exists(p):
            return p
    return None

def _safe_filename(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return name or f"file_{int(time.time())}"

def save_uploaded_file(file, subdir: str) -> Optional[str]:
    """Store an uploaded file under uploads/<subdir>/ and return its path."""
    if not file:
        return None
    os.makedirs(os.path.join("uploads", subdir), exist_ok=True)
    fname = _safe_filename(file.name)
    path = os.path.join("uploads", subdir, f"{int(time.time())}_{fname}")
    with open(path, "wb") as f:
        f.write(file.getbuffer())
    return path

# ----------------------- Domain Logic -----------------------
def tag_match_score(req_text: str, member_skills: Optional[str]) -> int:
    if not member_skills:
        return 0
    tags = [t.strip().lower() for t in member_skills.split(",") if t.strip()]
    words = set([w.strip(",.!?;:").lower() for w in req_text.split() if w.strip()])
    return sum(1 for t in tags if t in words)

def find_capacity_left(conn: sqlite3.Connection, member_id: int, start: date, end: date) -> float:
    c = conn.cursor()
    planned = c.execute("""SELECT COALESCE(SUM(planned_hours),0) FROM tasks
                           WHERE assignee_id=? AND status IN ('Not Started','In Progress');""", (member_id,)).fetchone()[0] or 0.0
    row = c.execute("SELECT weekly_capacity_hours FROM team_members WHERE id=?;", (member_id,)).fetchone()
    weekly = (row[0] if row else 40.0) or 40.0
    days = max((end - start).days + 1, 1)
    total_capacity = weekly * (days / 7.0)
    return max(total_capacity - planned, 0.0)

def auto_allocate_tasks(project_id: int, horizon_days: int = 21) -> list[int]:
    today = date.today()
    end = today + timedelta(days=horizon_days)
    with get_conn() as conn:
        c = conn.cursor()
        reqs = c.execute("""SELECT id, requirement_text, estimate_hours, service_id, priority, complexity
                            FROM requirements WHERE project_id=?;""", (project_id,)).fetchall()
        team = c.execute("SELECT id, name, skills FROM team_members WHERE active=1;").fetchall()
        created = []
        for r in reqs:
            if (c.execute("SELECT COUNT(*) FROM tasks WHERE requirement_id=?;", (r["id"],)).fetchone()[0] or 0) > 0:
                continue
            best_member = None
            best_score = -1e9
            for m in team:
                score = tag_match_score(r["requirement_text"], m["skills"])
                cap = find_capacity_left(conn, m["id"], today, end)
                effective = score * 10 + cap / 10.0
                if effective > best_score:
                    best_score = effective
                    best_member = m
            planned_hours = r["estimate_hours"] if r["estimate_hours"] else (r["complexity"] or 2) * 6
            c.execute("""INSERT INTO tasks(project_id, requirement_id, service_id, name, description,
                        assignee_id, planned_hours, status, start_date, due_date)
                        VALUES(?,?,?,?,?,?,?,?,?,?);""",
                      (project_id, r["id"], r["service_id"], f"Work on: {r['requirement_text'][:60]}",
                       r["requirement_text"], best_member["id"] if best_member else None, planned_hours,
                       "Not Started", today.isoformat(), end.isoformat()))
            created.append(c.lastrowid)
        return created

def compute_invoice_amount(conn: sqlite3.Connection, project_id: int, start: date, end: date) -> float:
    pricing_model, fixed_price = conn.execute(
        "SELECT pricing_model, fixed_price FROM projects WHERE id=?;", (project_id,)
    ).fetchone() or ("T&M", None)
    if pricing_model == "Fixed":
        return fixed_price or 0.0
    total = 0.0
    for hrs, rate in conn.execute("""SELECT tl.hours, tm.rate_per_hour
                                     FROM time_logs tl
                                     JOIN tasks t ON t.id = tl.task_id
                                     JOIN team_members tm ON tm.id = tl.member_id
                                     WHERE t.project_id=? AND date(tl.log_date) BETWEEN date(?) AND date(?);""",
                                  (project_id, start.isoformat(), end.isoformat())).fetchall():
        total += float(hrs or 0.0) * float(rate or 0.0)
    return total

def upsert_client(name: str, contact: str, email: str, notes: str):
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO clients(name,contact,email,notes) VALUES(?,?,?,?);", (name, contact, email, notes))
        conn.execute("UPDATE clients SET contact=?, email=?, notes=? WHERE name=?;", (contact, email, notes, name))

# ----------------------- Delete Helpers -----------------------
def delete_time_log(log_id: int) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM time_logs WHERE id=?;", (log_id,))
        return True

def delete_task(task_id: int) -> bool:
    with get_conn() as conn:
        conn.execute("DELETE FROM time_logs WHERE task_id=?;", (task_id,))
        conn.execute("DELETE FROM tasks WHERE id=?;", (task_id,))
        return True

def delete_requirement(req_id: int) -> bool:
    with get_conn() as conn:
        tids = [r[0] for r in conn.execute("SELECT id FROM tasks WHERE requirement_id=?;", (req_id,)).fetchall()]
        if tids:
            conn.executemany("DELETE FROM time_logs WHERE task_id=?;", [(t,) for t in tids])
            conn.execute("DELETE FROM tasks WHERE requirement_id=?;", (req_id,))
        conn.execute("DELETE FROM requirements WHERE id=?;", (req_id,))
        return True

def delete_service(service_id: int) -> tuple[bool, str]:
    with get_conn() as conn:
        used_r = conn.execute("SELECT COUNT(*) FROM requirements WHERE service_id=?;", (service_id,)).fetchone()[0]
        used_t = conn.execute("SELECT COUNT(*) FROM tasks WHERE service_id=?;", (service_id,)).fetchone()[0]
        if used_r or used_t:
            return False, "Service is referenced by requirements/tasks. Reassign or delete those first."
        conn.execute("DELETE FROM services WHERE id=?;", (service_id,))
        return True, "Service deleted."

def delete_member(member_id: int) -> tuple[bool, str]:
    with get_conn() as conn:
        has_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE assignee_id=?;", (member_id,)).fetchone()[0]
        has_logs  = conn.execute("SELECT COUNT(*) FROM time_logs WHERE member_id=?;", (member_id,)).fetchone()[0]
        if has_tasks or has_logs:
            conn.execute("UPDATE team_members SET active=0 WHERE id=?;", (member_id,))
            return False, "Member has tasks/logs. Marked as inactive instead."
        conn.execute("DELETE FROM team_members WHERE id=?;", (member_id,))
        return True, "Member deleted."

# ----------------------- APQP / PPAP Templates -----------------------
def apqp_init_template(project_id: int):
    """Create 5 APQP phases + core deliverables if not present."""
    phases = {
        1: ("Plan & Define", ["Voice of Customer (VoC)", "Project Charter", "Statement of Work (SOW)"]),
        2: ("Product Design & Development", ["DFMEA", "Design Verification Plan & Report (DVP&R)", "Design Review"]),
        3: ("Process Design & Development", ["Process Flow Diagram", "PFMEA", "Control Plan", "Work Instructions", "MSA Plan"]),
        4: ("Product & Process Validation", ["Run at Rate", "Capability Study (Cp/Cpk)", "MSA Studies", "Initial Process Studies (SPC)"]),
        5: ("Feedback, Assessment & Corrective Action", ["Corrective Action Plan", "Lessons Learned"]),
    }
    today = date.today()
    with get_conn() as conn:
        c = conn.cursor()
        for ph, (name, items) in phases.items():
            row = c.execute("SELECT id FROM apqp_stages WHERE project_id=? AND phase=?;", (project_id, ph)).fetchone()
            if row:
                stage_id = row["id"]
            else:
                c.execute("""INSERT INTO apqp_stages(project_id, phase, name, start_date, due_date, status, percent_complete)
                             VALUES(?,?,?,?,?,?,?);""",
                          (project_id, ph, name, today.isoformat(), (today + timedelta(days=14*ph)).isoformat(),
                           "Not Started", 0.0))
                stage_id = c.lastrowid
            for it in items:
                if not c.execute("""SELECT 1 FROM apqp_deliverables
                                    WHERE project_id=? AND stage_id=? AND name=?;""",
                                 (project_id, stage_id, it)).fetchone():
                    c.execute("""INSERT INTO apqp_deliverables(project_id, stage_id, name, required, status, updated_at)
                                 VALUES(?,?,?,?,?,datetime('now'));""",
                              (project_id, stage_id, it, 1, "Not Started"))

def ppap_init_template(project_id: int, level: int = 3):
    """Insert PPAP header + 18 standard elements if not present."""
    elements = [
        "Design Records","Authorized Engineering Change Documents","Customer Engineering Approval (if required)",
        "DFMEA","Process Flow Diagram","PFMEA","Control Plan","Measurement System Analysis (MSA)",
        "Dimensional Results","Records of Material / Performance Tests","Initial Process Studies (SPC)",
        "Qualified Laboratory Documentation","Appearance Approval Report (if applicable)","Sample Production Parts",
        "Master Sample","Checking Aids / Gauges","Customer-Specific Requirements","Part Submission Warrant (PSW)"
    ]
    with get_conn() as conn:
        c = conn.cursor()
        if not c.execute("SELECT 1 FROM ppap_info WHERE project_id=?;", (project_id,)).fetchone():
            c.execute("""INSERT INTO ppap_info(project_id, level, approve_status, notes)
                         VALUES(?,?, 'Draft', 'Initialized');""", (project_id, level))
        for name in elements:
            if not c.execute("SELECT 1 FROM ppap_elements WHERE project_id=? AND name=?;", (project_id, name)).fetchone():
                c.execute("""INSERT INTO ppap_elements(project_id, name, required, status, updated_at)
                             VALUES(?, ?, 1, 'Not Started', datetime('now'));""", (project_id, name))

# ----------------------- Misc Utils -----------------------
def week_bounds(any_date: date) -> tuple[date, date]:
    start = any_date - timedelta(days=any_date.weekday())
    end = start + timedelta(days=6)
    return start, end
# ============================================================
# PHASE 2/2: Streamlit UI (login, navigation, all pages)
# Paste this immediately AFTER Phase 1 in the same app.py
# ============================================================

st.set_page_config(page_title="Engineering Workflow System", layout="wide")

# ---------- Login helpers ----------
def login_page():
    logo = get_logo_path()
    if logo:
        st.image(logo, width=160)
    st.title("🔐 Sign In")
    st.caption("Default accounts: **admin/admin123**, **user/user123** (change later in Admin → User Management).")
    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        ok = st.form_submit_button("Login")
        if ok:
            row = authenticate(u, p)
            if row:
                st.session_state["auth"] = True
                st.session_state["user"] = {"id": row["id"], "username": row["username"], "role": row["role"], "team_member_id": row["team_member_id"]}
                st.success("Logged in! Redirecting…")
                st.rerun()
            else:
                st.error("Invalid credentials or inactive user.")

def require_login():
    if "auth" not in st.session_state or not st.session_state["auth"]:
        login_page()
        st.stop()

def assert_admin():
    if st.session_state.get("user", {}).get("role") != "admin":
        st.warning("Admin only page.")
        st.stop()

def sidebar_userbox():
    with st.sidebar:
        logo = get_logo_path()
        if logo:
            st.image(logo, use_container_width=True)
        u = st.session_state.get("user", {})
        st.markdown(f"**User:** {u.get('username','?')}")
        st.markdown(f"**Role:** {u.get('role','?')}")
        if st.button("Logout", use_container_width=True):
            st.session_state.clear()
            st.rerun()

def nav_pages_for(role: str):
    if role == "admin":
        return [
            "Requirement Capture","Projects & Scope","Service Catalog","Team & Capacity",
            "Auto Allocation","Task Board","Tasks & Time Tracking","Timesheet","Roadmap",
            "APQP","PPAP","Billing & Invoices","Reports","Admin"
        ]
    return ["Task Board","Timesheet","Roadmap","APQP","PPAP","Reports"]

# ---------- Initialize DB & seeds ----------
init_db()
seed_services()
seed_default_users()
imported = import_team_csv_if_empty()
if imported:
    st.toast(f"Imported {imported} team member(s) from sample_data.csv", icon="✅")

# ---------- Auth gate ----------
require_login()
sidebar_userbox()
role = st.session_state.get("user", {}).get("role", "user")
page = st.sidebar.selectbox("Navigate", nav_pages_for(role))

# ============================================================
# Pages
# ============================================================

if page == "Requirement Capture":
    assert_admin()
    st.header("1) Requirement Capture")
    col1, col2 = st.columns(2)

    # Client create/update/delete
    with col1:
        st.subheader("Client")
        cname = st.text_input("Client Name")
        ccontact = st.text_input("Contact (Phone)")
        cemail = st.text_input("Email")
        cnotes = st.text_area("Notes")
        if st.button("Save/Update Client"):
            if not cname.strip():
                st.error("Client name is required")
            else:
                upsert_client(cname.strip(), ccontact.strip(), cemail.strip(), cnotes.strip())
                st.success("Client saved/updated")

        st.markdown("---")
        del_clients = load_table("SELECT id, name FROM clients ORDER BY name;")
        if not del_clients.empty:
            sel_del_client = st.selectbox("Delete client", ["--"] + del_clients["name"].tolist())
            if sel_del_client != "--" and st.button("Confirm Delete"):
                cid = int(del_clients[del_clients["name"] == sel_del_client]["id"].iloc[0])
                ok, msg = delete_service(cid) if False else (False, "Use Projects page to manage client relationships.")
                st.warning("Clients with projects cannot be deleted safely. Manage projects first.")

    # Project & Requirements
    with col2:
        st.subheader("New Project")
        clients = load_table("SELECT id, name FROM clients ORDER BY name;")
        if clients.empty:
            st.info("Add a client first on the left.")
        else:
            client_map = dict(zip(clients["name"], clients["id"]))
            sel_client = st.selectbox("Client", clients["name"].tolist())
            pname = st.text_input("Project Name")
            pcode = st.text_input("Project Code (unique)")
            pstart = st.date_input("Start Date", date.today())
            pdue = st.date_input("Due Date", date.today() + timedelta(days=30))
            pricing = st.selectbox("Pricing Model", ["T&M", "Fixed"])
            fixed = st.number_input("Fixed Price (if Fixed)", min_value=0.0, step=1000.0, value=0.0)
            if st.button("Create Project"):
                with get_conn() as conn:
                    conn.execute("""INSERT INTO projects(code,client_id,name,start_date,due_date,pricing_model,fixed_price)
                                    VALUES(?,?,?,?,?,?,?);""",
                                 (pcode.strip() or None, client_map[sel_client], pname.strip() or (sel_client + " Project"),
                                  pstart.isoformat(), pdue.isoformat(), pricing, fixed if pricing=="Fixed" else None))
                st.success("Project created")

    st.divider()
    st.subheader("Add Requirements")
    projects = load_table("""SELECT p.id, p.name, c.name AS client FROM projects p JOIN clients c ON c.id=p.client_id ORDER BY p.id DESC;""")
    if projects.empty:
        st.info("Create a project first.")
    else:
        proj_map = {f"{r['name']} ({r['client']})": r["id"] for _, r in projects.iterrows()}
        sel_proj = st.selectbox("Project", list(proj_map.keys()))
        services = load_table("SELECT id, name FROM services ORDER BY name;")
        s_map = dict(zip(services["name"], services["id"]))
        sel_service = st.selectbox("Service", services["name"].tolist())
        req_text = st.text_area("Requirement / Statement of Work")
        priority = st.selectbox("Priority", ["Low", "Medium", "High"], index=1)
        complexity = st.slider("Complexity (1-5)", 1, 5, 2)
        est_hours = st.number_input("Estimated Hours (optional)", min_value=0.0, step=1.0)
        if st.button("Add Requirement"):
            with get_conn() as conn:
                conn.execute("""INSERT INTO requirements(project_id,service_id,requirement_text,priority,complexity,estimate_hours)
                                VALUES(?,?,?,?,?,?);""",
                             (proj_map[sel_proj], s_map[sel_service], req_text.strip(), priority, int(complexity),
                              est_hours if est_hours > 0 else None))
            st.success("Requirement added")

    st.subheader("Current Requirements")
    st.dataframe(load_table(
        """SELECT r.id, c.name AS client, p.name AS project, s.name AS service, r.priority, r.complexity,
                  r.estimate_hours, r.requirement_text
           FROM requirements r JOIN projects p ON p.id=r.project_id
           JOIN clients c ON c.id=p.client_id JOIN services s ON s.id=r.service_id
           ORDER BY r.id DESC;"""), use_container_width=True)

elif page == "Projects & Scope":
    assert_admin()
    st.header("2) Projects, Status & Deliverables")
    st.subheader("Projects")
    st.dataframe(load_table(
        """SELECT p.id, p.code, c.name as client, p.name, p.status, p.start_date, p.due_date,
                  p.pricing_model, p.fixed_price
           FROM projects p JOIN clients c ON c.id=p.client_id ORDER BY p.id DESC;"""), use_container_width=True)

    st.subheader("Create Deliverables / Milestones")
    projs = load_table("SELECT id, name FROM projects ORDER BY id DESC;")
    if projs.empty:
        st.info("No projects yet.")
    else:
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        dname = st.text_input("Deliverable Name")
        ddesc = st.text_area("Description")
        ddue = st.date_input("Due Date", date.today() + timedelta(days=14))
        if st.button("Add Deliverable"):
            with get_conn() as conn:
                conn.execute("INSERT INTO deliverables(project_id, name, description, due_date) VALUES(?,?,?,?);",
                             (p_map[sel_p], dname.strip() or "Deliverable", ddesc.strip(), ddue.isoformat()))
            st.success("Deliverable added")

    st.subheader("Deliverables")
    st.dataframe(load_table(
        """SELECT d.id, p.name AS project, d.name, d.description, d.due_date, d.status
           FROM deliverables d JOIN projects p ON p.id=d.project_id ORDER BY d.due_date;"""),
        use_container_width=True)

elif page == "Service Catalog":
    assert_admin()
    st.header("3) Service Catalog")
    name = st.text_input("Service Name")
    desc = st.text_area("Description")
    rate = st.number_input("Default Rate per Hour (INR)", min_value=0.0, step=100.0, value=2000.0)
    if st.button("Add/Update Service"):
        with get_conn() as conn:
            conn.execute("INSERT OR IGNORE INTO services(name, description, default_rate_per_hour) VALUES(?,?,?);",
                         (name.strip(), desc.strip(), rate))
            conn.execute("UPDATE services SET description=?, default_rate_per_hour=? WHERE name=?;",
                         (desc.strip(), rate, name.strip()))
        st.success("Service saved/updated")

    st.subheader("Current Services")
    df = load_table("SELECT id, name, description, default_rate_per_hour FROM services ORDER BY name;")
    st.dataframe(df, use_container_width=True)

    st.subheader("Delete Service (safe if unused)")
    if not df.empty:
        sid = st.selectbox("Service", df["id"].tolist(), format_func=lambda x: df[df["id"]==x]["name"].iloc[0])
        if st.button("Delete Service"):
            ok, msg = delete_service(int(sid))
            (st.success if ok else st.warning)(msg)

elif page == "Team & Capacity":
    assert_admin()
    st.header("4) Team & Capacity")
    st.write("Define team members, skills (comma-separated), and capacity. Optionally import from sample_data.csv.")
    t_name = st.text_input("Member Name")
    t_role = st.text_input("Role")
    t_skills = st.text_input("Skills (comma-separated: 'thermal, pcb, gd&t, moldflow')")
    t_rate = st.number_input("Rate per Hour (INR)", min_value=0.0, step=100.0, value=1500.0)
    t_capacity = st.number_input("Weekly Capacity (hours)", min_value=1.0, step=1.0, value=40.0)
    active_m = st.checkbox("Active", value=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Add Member"):
            with get_conn() as conn:
                conn.execute("""INSERT INTO team_members(name, role, skills, rate_per_hour, weekly_capacity_hours, active)
                                VALUES(?,?,?,?,?,?);""",
                             (t_name.strip(), t_role.strip(), t_skills.strip(), t_rate, t_capacity, 1 if active_m else 0))
            st.success("Team member added")
    with c2:
        if st.button("Import from sample_data.csv"):
            n = import_team_csv_if_empty()
            st.success(f"Imported {n} member(s)" if n else "Nothing imported (file missing or table not empty).")

    st.subheader("Team")
    tdf = load_table("SELECT id, name, role, skills, rate_per_hour, weekly_capacity_hours, active FROM team_members ORDER BY id DESC;")
    st.dataframe(tdf, use_container_width=True)

    st.subheader("Delete / Inactivate Member")
    if not tdf.empty:
        mid = st.selectbox("Member", tdf["id"].tolist(), format_func=lambda x: tdf[tdf["id"]==x]["name"].iloc[0])
        if st.button("Delete / Inactivate"):
            ok, msg = delete_member(int(mid))
            (st.success if ok else st.warning)(msg)

elif page == "Auto Allocation":
    assert_admin()
    st.header("5) Auto Allocation")
    projs = load_table("SELECT id, name FROM projects ORDER BY id DESC;")
    if projs.empty:
        st.info("Create a project and add requirements first.")
    else:
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        horizon = st.slider("Planning Horizon (days)", 7, 60, 21)
        if st.button("Auto-Create & Allocate Tasks"):
            created = auto_allocate_tasks(p_map[sel_p], horizon_days=int(horizon))
            st.success(f"Created {len(created)} task(s).")

        st.subheader("Tasks")
        st.dataframe(load_table(
            """SELECT t.id, p.name AS project, s.name AS service, t.name, t.status, t.planned_hours, tm.name AS assignee,
                      t.start_date, t.due_date
               FROM tasks t JOIN projects p ON p.id=t.project_id
               JOIN services s ON s.id=t.service_id
               LEFT JOIN team_members tm ON tm.id=t.assignee_id
               WHERE t.project_id=? ORDER BY t.id DESC;""", (p_map[sel_p],)), use_container_width=True)

elif page == "Task Board":
    st.header("Task Board — Project Task Tracking")
    u = st.session_state.get("user", {})
    my_member_id = u.get("team_member_id")
    if role == "admin":
        projs = load_table("SELECT id, name FROM projects ORDER BY id DESC;")
        if projs.empty:
            st.info("Create a project first.")
            st.stop()
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        tasks = load_table("""SELECT t.id, t.name, t.status, t.due_date, tm.name AS assignee
                              FROM tasks t LEFT JOIN team_members tm ON tm.id=t.assignee_id
                              WHERE t.project_id=? ORDER BY t.due_date;""", (p_map[sel_p],))
    else:
        tasks = load_table("""SELECT t.id, t.name, t.status, t.due_date, p.name AS project
                              FROM tasks t JOIN projects p ON p.id=t.project_id
                              WHERE t.assignee_id=? ORDER BY t.due_date;""", (int(my_member_id) if my_member_id else -1,))
        st.caption("Showing tasks assigned to you.")

    if tasks.empty:
        st.info("No tasks to show.")
    else:
        cols = st.columns(4)
        statuses = ["Not Started","In Progress","Blocked","Done"]
        for i, s in enumerate(statuses):
            with cols[i]:
                st.subheader(s)
                sub = tasks[tasks["status"] == s]
                for _, r in sub.iterrows():
                    due = f" _(due {r['due_date']})_" if pd.notna(r['due_date']) else ""
                    who = f" — {r.get('assignee')}" if "assignee" in r and pd.notna(r['assignee']) else ""
                    st.markdown(f"- **#{r['id']}** {r['name']}{who}{due}")
        st.divider()
        st.subheader("Quick Update")
        tid = st.selectbox("Task ID", tasks["id"].tolist())
        new_status = st.selectbox("New Status", statuses)
        if st.button("Apply Status"):
            with get_conn() as conn:
                conn.execute("UPDATE tasks SET status=? WHERE id=?;", (new_status, int(tid)))
            st.success("Updated")

elif page == "Tasks & Time Tracking":
    st.header("6) Tasks & Time Tracking")
    projs = load_table("SELECT id, name FROM projects ORDER BY id DESC;")
    if projs.empty:
        st.info("Create a project and tasks first.")
    else:
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())

        st.subheader("Update Task & Delete")
        tasks = load_table("""SELECT t.id, t.name, t.status, tm.name AS assignee, t.planned_hours
                              FROM tasks t LEFT JOIN team_members tm ON tm.id=t.assignee_id
                              WHERE t.project_id=? ORDER BY t.id DESC;""", (p_map[sel_p],))
        st.dataframe(tasks, use_container_width=True)

        if not tasks.empty:
            task_id = st.selectbox("Task", tasks["id"].tolist())
            row = load_table("SELECT * FROM tasks WHERE id=?;", (int(task_id),)).iloc[0]
            new_status = st.selectbox("Status", ["Not Started","In Progress","Blocked","Done"],
                                      index=["Not Started","In Progress","Blocked","Done"].index(row["status"]))
            members = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
            m_map = dict(zip(members["name"], members["id"])) if not members.empty else {}
            cur_name = load_table("SELECT name FROM team_members WHERE id=?;", (row["assignee_id"],)).squeeze() if row["assignee_id"] else None
            new_ass = st.selectbox("Assign to", members["name"].tolist() if not members.empty else ["-- none --"],
                                   index=(members["name"].tolist().index(cur_name) if cur_name in members["name"].tolist() else 0) if not members.empty else 0)
            plan_hrs = st.number_input("Planned Hours", min_value=0.0, step=0.5, value=float(row["planned_hours"] or 0.0))
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Apply Task Changes"):
                    with get_conn() as conn:
                        conn.execute("UPDATE tasks SET status=?, assignee_id=?, planned_hours=? WHERE id=?;",
                                     (new_status, m_map.get(new_ass), float(plan_hrs), int(task_id)))
                    st.success("Task updated")
            with c2:
                if st.button("Delete Task"):
                    delete_task(int(task_id))
                    st.warning("Task deleted (and its time logs)")

        st.subheader("Log Time")
        tasks2 = load_table("SELECT t.id, t.name FROM tasks t WHERE t.project_id=? ORDER BY t.id DESC;", (p_map[sel_p],))
        members2 = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
        if tasks2.empty or members2.empty:
            st.info("Need at least one task and one active member.")
        else:
            t_map = dict(zip(tasks2["name"], tasks2["id"]))
            m_map2 = dict(zip(members2["name"], members2["id"]))
            t_sel = st.selectbox("Task", tasks2["name"].tolist())
            m_sel = st.selectbox("Member", members2["name"].tolist())
            ldate = st.date_input("Date", date.today())
            hours = st.number_input("Hours", min_value=0.25, step=0.25, value=1.0)
            note = st.text_input("Note")
            if st.button("Add Time Log"):
                with get_conn() as conn:
                    conn.execute("""INSERT INTO time_logs(task_id, member_id, log_date, hours, note)
                                    VALUES(?,?,?,?,?);""", (t_map[t_sel], m_map2[m_sel], ldate.isoformat(), float(hours), note.strip()))
                st.success("Time logged")

elif page == "Timesheet":
    st.header("Timesheet")
    u = st.session_state.get("user", {})
    my_member_id = u.get("team_member_id")
    if role == "admin":
        members = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
        if members.empty:
            st.info("Add a team member first."); st.stop()
        sel_member = st.selectbox("Team Member", members["name"].tolist())
        member_id = int(members[members["name"]==sel_member]["id"].iloc[0])
    else:
        if not my_member_id:
            st.warning("Your user is not linked to a team member yet. Ask admin to link it in Admin."); st.stop()
        member_id = int(my_member_id)
        me = load_table("SELECT name FROM team_members WHERE id=?;", (member_id,)).squeeze()
        st.caption(f"Member: **{me}**")

    week_of = st.date_input("Week of", value=date.today())
    week_start, week_end = week_bounds(week_of)
    st.write(f"Week: **{week_start} → {week_end}**")

    logs = load_table("""SELECT tl.id, tl.task_id, tl.member_id, tl.log_date, tl.hours, t.name AS task
                         FROM time_logs tl JOIN tasks t ON t.id=tl.task_id
                         WHERE tl.member_id=? AND date(tl.log_date) BETWEEN date(?) AND date(?)
                         ORDER BY tl.log_date;""", (member_id, week_start.isoformat(), week_end.isoformat()))
    if logs.empty:
        st.info("No logs this week yet.")
    else:
        df = logs.copy()
        df["log_date"] = pd.to_datetime(df["log_date"]).dt.date
        pivot = df.pivot_table(index="task", columns="log_date", values="hours", aggfunc="sum", fill_value=0.0)
        pivot["Total"] = pivot.sum(axis=1)
        st.dataframe(pivot, use_container_width=True)
        st.metric("Weekly Total", f"{df['hours'].sum():.2f} h")
        st.download_button("Download Timesheet CSV", pivot.to_csv().encode("utf-8"),
                           file_name=f"timesheet_{member_id}_{week_start}.csv", mime="text/csv")

    st.subheader("Quick add entry")
    opts = load_table("SELECT id, name FROM tasks WHERE assignee_id=? ORDER BY id DESC;", (member_id,)) if role!="admin" \
           else load_table("SELECT id, name FROM tasks ORDER BY id DESC LIMIT 500;")
    if opts.empty:
        st.info("No tasks to log time on.")
    else:
        tmap = dict(zip(opts["name"], opts["id"]))
        tname = st.selectbox("Task", list(tmap.keys()))
        dt = st.date_input("Date", value=min(date.today(), week_end), min_value=week_start, max_value=week_end)
        hrs = st.number_input("Hours", min_value=0.25, step=0.25, value=1.0)
        note = st.text_input("Note")
        if st.button("Add Entry"):
            with get_conn() as conn:
                conn.execute("""INSERT INTO time_logs(task_id, member_id, log_date, hours, note)
                                VALUES(?,?,?,?,?);""", (int(tmap[tname]), member_id, dt.isoformat(), float(hrs), note.strip()))
            st.success("Added")

elif page == "Roadmap":
    st.header("Roadmap — Portfolio Timeline")
    st.caption("Gantt-like bars for tasks and deliverables. Install `altair` for charts: `pip install altair`.")
    scope = st.radio("Show", ["All Projects", "Single Project"], horizontal=True)
    if scope == "Single Project":
        projs = load_table("SELECT id, name FROM projects ORDER BY name;")
        if projs.empty: st.info("No projects found."); st.stop()
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        pid = p_map[sel_p]
        tasks = load_table("""SELECT t.name, t.status, t.start_date, t.due_date, tm.name AS assignee
                              FROM tasks t LEFT JOIN team_members tm ON tm.id=t.assignee_id
                              WHERE t.project_id=?;""", (pid,))
        dels = load_table("""SELECT d.name, d.due_date, d.status, p.start_date as project_start
                             FROM deliverables d JOIN projects p ON p.id=d.project_id
                             WHERE d.project_id=?;""", (pid,))
    else:
        tasks = load_table("""SELECT p.name AS project, t.name, t.status, t.start_date, t.due_date, tm.name AS assignee
                              FROM tasks t JOIN projects p ON p.id=t.project_id
                              LEFT JOIN team_members tm ON tm.id=t.assignee_id;""")
        dels = load_table("""SELECT p.name AS project, d.name, d.due_date, d.status, p.start_date as project_start
                             FROM deliverables d JOIN projects p ON p.id=d.project_id;""")

    def parse_d(d):
        try: return pd.to_datetime(d).date()
        except Exception: return None

    if not tasks.empty:
        tdf = tasks.copy()
        tdf["start"] = tdf["start_date"].apply(parse_d)
        tdf["end"] = tdf["due_date"].apply(parse_d)
        tdf["label"] = tdf["name"] + tdf.get("assignee","").fillna("").apply(lambda s: f" — {s}" if s else "")
        st.subheader("Tasks Timeline")
        if alt is None:
            st.info("Install `altair` to see the chart. Showing table instead.")
            st.dataframe(tdf[["name","assignee","status","start","end"]].sort_values("start"), use_container_width=True)
        else:
            chart = alt.Chart(tdf.dropna(subset=["start","end"])).mark_bar().encode(
                x="start:T", x2="end:T", y=alt.Y("label:N", sort="-x", title="Task"),
                color="status:N", tooltip=["name","assignee","status","start","end"]).properties(height=min(500, 24*len(tdf)), width=900)
            st.altair_chart(chart, use_container_width=True)

    if not dels.empty:
        ddf = dels.copy()
        ddf["due"] = ddf["due_date"].apply(parse_d)
        def deliv_start(row):
            ps = parse_d(row.get("project_start"))
            due = parse_d(row.get("due_date"))
            if due is None: return None
            return ps or (due - timedelta(days=14))
        ddf["start"] = ddf.apply(deliv_start, axis=1)
        ddf["end"] = ddf["due"]
        ddf["label"] = (ddf.get("project","").fillna("") + " — ").where(ddf.get("project").notna(), "") + ddf["name"]
        st.subheader("Deliverables Timeline")
        if alt is None:
            st.info("Install `altair` to see the chart. Showing table instead.")
            st.dataframe(ddf[["label","status","start","end"]].sort_values("end"), use_container_width=True)
        else:
            chart2 = alt.Chart(ddf.dropna(subset=["start","end"])).mark_bar().encode(
                x="start:T", x2="end:T", y=alt.Y("label:N", sort="-x", title="Deliverable"),
                color="status:N", tooltip=["label","status","start","end"]).properties(height=min(500, 24*len(ddf)), width=900)
            st.altair_chart(chart2, use_container_width=True)

elif page == "APQP":
    st.header("APQP — Advanced Product Quality Planning")
    st.caption("5 phases with core deliverables. Admins can initialize a template per project and attach evidence files.")
    projs = load_table("SELECT id, name FROM projects ORDER BY name;")
    if projs.empty: st.info("No projects yet."); st.stop()
    pmap = dict(zip(projs["name"], projs["id"]))
    selp = st.selectbox("Project", projs["name"].tolist()); pid = int(pmap[selp])

    if role == "admin" and st.button("Initialize/Update APQP Template for this Project"):
        apqp_init_template(pid); st.success("APQP template ensured.")

    stages = load_table("""SELECT s.id, s.phase, s.name, s.start_date, s.due_date, s.status, s.percent_complete, tm.name as owner
                           FROM apqp_stages s LEFT JOIN team_members tm ON tm.id=s.owner_member_id
                           WHERE s.project_id=? ORDER BY s.phase;""", (pid,))
    if stages.empty: st.warning("No APQP stages yet. Click the Initialize button above."); st.stop()
    st.subheader("Stages"); st.dataframe(stages, use_container_width=True)

    if role == "admin":
        st.markdown("**Edit Stage**")
        sid = st.selectbox("Stage", stages["id"].tolist(),
                           format_func=lambda x: f"Phase {int(stages[stages['id']==x]['phase'].iloc[0])} — {stages[stages['id']==x]['name'].iloc[0]}")
        srow = load_table("SELECT * FROM apqp_stages WHERE id=?;", (int(sid),)).iloc[0]
        members = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
        owner_map = {"-- none --": None}
        if not members.empty: owner_map.update({r["name"]: int(r["id"]) for _, r in members.iterrows()})
        owner_idx = 0
        if srow["owner_member_id"] and srow["owner_member_id"] in owner_map.values():
            owner_idx = list(owner_map.values()).index(int(srow["owner_member_id"]))
        owner_name = st.selectbox("Owner", list(owner_map.keys()), index=owner_idx)
        s_status = st.selectbox("Status", ["Not Started","In Progress","Done"],
                                index=["Not Started","In Progress","Done"].index(srow["status"]))
        s_pc = st.slider("Percent Complete", 0, 100, int(srow["percent_complete"] or 0))
        if st.button("Apply Stage Changes"):
            with get_conn() as conn:
                conn.execute("UPDATE apqp_stages SET owner_member_id=?, status=?, percent_complete=? WHERE id=?;",
                             (owner_map.get(owner_name), s_status, float(s_pc), int(sid)))
            st.success("Stage updated")

    st.divider(); st.subheader("Deliverables")
    sid2 = st.selectbox("Stage (deliverables)", stages["id"].tolist(),
                        format_func=lambda x: f"Phase {int(stages[stages['id']==x]['phase'].iloc[0])} — {stages[stages['id']==x]['name'].iloc[0]}",
                        key="deliv_stage")
    delivs = load_table("""SELECT d.id, d.name, d.required, d.status, tm.name AS owner, d.due_date, d.file_path, d.updated_at
                           FROM apqp_deliverables d LEFT JOIN team_members tm ON tm.id=d.owner_member_id
                           WHERE d.project_id=? AND d.stage_id=? ORDER BY d.id;""", (pid, int(sid2)))
    if delivs.empty:
        st.info("No deliverables for this stage.")
    else:
        st.dataframe(delivs, use_container_width=True)
        st.markdown("**Update Deliverable**")
        did = st.selectbox("Deliverable", delivs["id"].tolist(), format_func=lambda x: delivs[delivs["id"]==x]["name"].iloc[0])
        drow = load_table("SELECT * FROM apqp_deliverables WHERE id=?;", (int(did),)).iloc[0]
        d_status = st.selectbox("Status", ["Not Started","In Progress","Done","N/A"],
                                index=["Not Started","In Progress","Done","N/A"].index(drow["status"]))
        mems = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
        d_owner_map = {"-- none --": None}
        if not mems.empty: d_owner_map.update({r["name"]: int(r["id"]) for _, r in mems.iterrows()})
        owner_idx = 0
        if drow["owner_member_id"] and int(drow["owner_member_id"]) in d_owner_map.values():
            owner_idx = list(d_owner_map.values()).index(int(drow["owner_member_id"]))
        d_owner = st.selectbox("Owner", list(d_owner_map.keys()), index=owner_idx)
        d_due = st.date_input("Due Date", value=date.fromisoformat(drow["due_date"]) if drow["due_date"] else date.today())
        d_note = st.text_input("Notes", value=drow["notes"] or "")
        up = st.file_uploader("Attach/replace file (optional)", type=["pdf","xlsx","xls","csv","docx","jpg","png","zip","txt"])
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Save Deliverable"):
                path = save_uploaded_file(up, subdir="apqp") if up else drow["file_path"]
                with get_conn() as conn:
                    conn.execute("""UPDATE apqp_deliverables
                                    SET status=?, owner_member_id=?, due_date=?, notes=?, file_path=?, updated_at=datetime('now')
                                    WHERE id=?;""",
                                 (d_status, d_owner_map.get(d_owner), d_due.isoformat() if d_due else None,
                                  d_note.strip(), path, int(did)))
                st.success("Deliverable updated")
        with c2:
            if role == "admin" and st.button("Toggle Required"):
                with get_conn() as conn:
                    conn.execute("UPDATE apqp_deliverables SET required = CASE required WHEN 1 THEN 0 ELSE 1 END WHERE id=?;", (int(did),))
                st.success("Required flag toggled")

    st.divider(); st.subheader("Summary")
    s = load_table("""SELECT
                        SUM(CASE WHEN status='Done' THEN 1 ELSE 0 END) AS done,
                        SUM(CASE WHEN status='In Progress' THEN 1 ELSE 0 END) AS wip,
                        SUM(CASE WHEN status='Not Started' THEN 1 ELSE 0 END) AS todo,
                        COUNT(*) AS total
                      FROM apqp_deliverables WHERE project_id=?;""", (pid,))
    if not s.empty:
        d, w, t, tot = int(s['done'][0] or 0), int(s['wip'][0] or 0), int(s['todo'][0] or 0), int(s['total'][0] or 0)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Done", d); c2.metric("In Progress", w); c3.metric("Not Started", t); c4.metric("Total", tot)

elif page == "PPAP":
    st.header("PPAP — Production Part Approval Process")
    st.caption("Set PPAP level and manage the 18-element checklist with attachments.")
    projs = load_table("SELECT id, name FROM projects ORDER BY name;")
    if projs.empty: st.info("No projects yet."); st.stop()
    pmap = dict(zip(projs["name"], projs["id"]))
    selp = st.selectbox("Project", projs["name"].tolist()); pid = int(pmap[selp])

    info = load_table("SELECT * FROM ppap_info WHERE project_id=?;", (pid,))
    if info.empty:
        level = st.selectbox("PPAP Level", [1,2,3,4,5], index=2)
        if role == "admin" and st.button("Initialize PPAP for this Project"):
            ppap_init_template(pid, level); st.success("PPAP initialized."); st.rerun()
        st.stop()
    else:
        row = info.iloc[0]
        c1, c2, c3 = st.columns(3)
        with c1:
            level = st.selectbox("Level", [1,2,3,4,5], index=[1,2,3,4,5].index(int(row["level"])))
        with c2:
            approve = st.selectbox("Approval Status", ["Draft","In Review","Submitted","Approved","Rejected"],
                                   index=["Draft","In Review","Submitted","Approved","Rejected"].index(row["approve_status"]))
        with c3:
            sub_date = st.date_input("Submission Date", value=date.fromisoformat(row["submission_date"]) if row["submission_date"] else date.today())
        customer = st.text_input("Customer", value=row["customer"] or "")
        notes = st.text_area("Notes", value=row["notes"] or "")
        if role == "admin" and st.button("Update PPAP Header"):
            with get_conn() as conn:
                conn.execute("""UPDATE ppap_info SET level=?, approve_status=?, submission_date=?, customer=?, notes=? WHERE id=?;""",
                             (int(level), approve, sub_date.isoformat() if sub_date else None, customer.strip(), notes.strip(), int(row["id"])))
            st.success("PPAP header updated")

    st.subheader("Elements (Checklist)")
    elems = load_table("""SELECT e.id, e.name, e.status, tm.name AS owner, e.file_path, e.updated_at
                          FROM ppap_elements e LEFT JOIN team_members tm ON tm.id=e.owner_member_id
                          WHERE e.project_id=? ORDER BY e.id;""", (pid,))
    st.dataframe(elems, use_container_width=True)

    if not elems.empty:
        st.markdown("**Update Element**")
        eid = st.selectbox("Element", elems["id"].tolist(), format_func=lambda x: elems[elems["id"]==x]["name"].iloc[0])
        erow = load_table("SELECT * FROM ppap_elements WHERE id=?;", (int(eid),)).iloc[0]
        stat = st.selectbox("Status", ["Not Started","In Progress","Complete","N/A"],
                            index=["Not Started","In Progress","Complete","N/A"].index(erow["status"]))
        mems = load_table("SELECT id, name FROM team_members WHERE active=1 ORDER BY name;")
        mapm = {"-- none --": None}
        if not mems.empty: mapm.update({r["name"]: int(r["id"]) for _, r in mems.iterrows()})
        idx = 0
        if erow["owner_member_id"] and int(erow["owner_member_id"]) in mapm.values():
            idx = list(mapm.values()).index(int(erow["owner_member_id"]))
        owner = st.selectbox("Owner", list(mapm.keys()), index=idx)
        enote = st.text_input("Notes", value=erow["notes"] or "")
        up = st.file_uploader("Attach/replace file (optional)", type=["pdf","xlsx","xls","csv","docx","jpg","png","zip","txt"])
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Save Element"):
                path = save_uploaded_file(up, subdir="ppap") if up else erow["file_path"]
                with get_conn() as conn:
                    conn.execute("""UPDATE ppap_elements
                                    SET status=?, owner_member_id=?, notes=?, file_path=?, updated_at=datetime('now')
                                    WHERE id=?;""", (stat, mapm.get(owner), enote.strip(), path, int(eid)))
                st.success("Element updated")
        with c2:
            if role == "admin" and st.button("Toggle Required (Yes/No)"):
                with get_conn() as conn:
                    conn.execute("UPDATE ppap_elements SET required = CASE required WHEN 1 THEN 0 ELSE 1 END WHERE id=?;", (int(eid),))
                st.success("Required flag toggled")

    st.divider(); st.subheader("Summary")
    s = load_table("""SELECT
                        SUM(CASE WHEN status='Complete' THEN 1 ELSE 0 END) AS complete,
                        SUM(CASE WHEN status='In Progress' THEN 1 ELSE 0 END) AS wip,
                        SUM(CASE WHEN status='Not Started' THEN 1 ELSE 0 END) AS todo,
                        SUM(CASE WHEN status='N/A' THEN 1 ELSE 0 END) AS na,
                        COUNT(*) AS total
                      FROM ppap_elements WHERE project_id=?;""", (pid,))
    if not s.empty:
        comp, wip, todo, na, tot = [int(s[col][0] or 0) for col in ["complete","wip","todo","na","total"]]
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Complete", comp); c2.metric("In Progress", wip); c3.metric("Not Started", todo); c4.metric("N/A", na); c5.metric("Total", tot)

elif page == "Billing & Invoices":
    assert_admin()
    st.header("7) Billing & Invoices")
    projs = load_table("SELECT id, name FROM projects ORDER BY id DESC;")
    if projs.empty:
        st.info("Create a project first.")
    else:
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        period_start = st.date_input("Period Start", date.today().replace(day=1))
        period_end = st.date_input("Period End", date.today())
        if st.button("Compute & Create Invoice"):
            with get_conn() as conn:
                amount = compute_invoice_amount(conn, p_map[sel_p], period_start, period_end)
                conn.execute("""INSERT INTO invoices(project_id, period_start, period_end, amount, notes, created_at)
                                VALUES(?,?,?,?,?,?);""",
                             (p_map[sel_p], period_start.isoformat(), period_end.isoformat(), amount,
                              f"Auto-generated on {datetime.now().isoformat(timespec='seconds')}",
                              datetime.now().isoformat(timespec='seconds')))
            st.success(f"Invoice created for INR {amount:,.2f}")

        st.subheader("Invoices")
        st.dataframe(load_table("""SELECT i.id, p.name AS project, i.period_start, i.period_end, i.amount, i.created_at, i.notes
                                   FROM invoices i JOIN projects p ON p.id=i.project_id
                                   ORDER BY i.id DESC;"""), use_container_width=True)

elif page == "Reports":
    st.header("8) Reports")
    st.subheader("Planned vs Logged Hours (per project)")
    projs = load_table("SELECT id, name FROM projects ORDER BY name;")
    if projs.empty:
        st.info("No projects yet.")
    else:
        p_map = dict(zip(projs["name"], projs["id"]))
        sel_p = st.selectbox("Project", projs["name"].tolist())
        tasks_df = load_table("SELECT id, planned_hours, name FROM tasks WHERE project_id=?;", (p_map[sel_p],))
        planned = tasks_df["planned_hours"].sum() if not tasks_df.empty else 0.0
        if tasks_df.empty:
            logged = 0.0
        else:
            with get_conn() as conn:
                placeholders = ",".join(["?"]*len(tasks_df))
                q = f"SELECT COALESCE(SUM(hours),0) FROM time_logs WHERE task_id IN ({placeholders});"
                logged = conn.execute(q, tasks_df["id"].tolist()).fetchone()[0] or 0.0
        c1, c2 = st.columns(2); c1.metric("Planned Hours", f"{planned:.1f}"); c2.metric("Logged Hours", f"{logged:.1f}")
        st.subheader("Task Timeline (simple)")
        st.dataframe(load_table("""SELECT t.id, t.name, tm.name AS assignee, t.status, t.start_date, t.due_date, t.planned_hours
                                   FROM tasks t LEFT JOIN team_members tm ON tm.id=t.assignee_id
                                   WHERE t.project_id=? ORDER BY date(t.due_date);""", (p_map[sel_p],)),
                     use_container_width=True)

elif page == "Admin":
    assert_admin()
    st.header("Admin — User Management & Branding")
    st.caption("Create users, set roles, link to team members, and upload a logo shown on login & sidebar.")

    st.subheader("Branding — Logo")
    up = st.file_uploader("Upload PNG/JPG", type=["png","jpg","jpeg"])
    c1, c2 = st.columns(2)
    with c1:
        if up and st.button("Save Logo"):
            os.makedirs("assets", exist_ok=True)
            with open("assets/logo.png", "wb") as f:
                f.write(up.getbuffer())
            st.success("Logo saved. Reloading…"); st.rerun()
    with c2:
        if get_logo_path() and st.button("Remove Logo"):
            try: os.remove(get_logo_path())
            except Exception: pass
            st.warning("Logo removed. Reloading…"); st.rerun()
    if get_logo_path(): st.image(get_logo_path(), width=220, caption="Current logo")

    st.divider()
    st.subheader("Create New User")
    u_name = st.text_input("Username")
    u_pass = st.text_input("Password", type="password")
    role_sel = st.selectbox("Role", ["user","admin"])
    members = load_table("SELECT id, name FROM team_members ORDER BY name;")
    member_map = {"-- none --": None}
    if not members.empty: member_map.update({r["name"]: int(r["id"]) for _, r in members.iterrows()})
    link_member = st.selectbox("Link to Team Member (optional)", list(member_map.keys()))
    if st.button("Create User"):
        try:
            create_user(u_name.strip(), u_pass, role_sel, member_map.get(link_member))
            st.success("User created")
        except sqlite3.IntegrityError:
            st.error("Username already exists")

    st.subheader("Existing Users")
    users_df = load_table("""SELECT u.id, u.username, u.role, u.active, tm.name AS team_member
                             FROM users u LEFT JOIN team_members tm ON tm.id=u.team_member_id
                             ORDER BY u.username;""")
    st.dataframe(users_df, use_container_width=True)

    if not users_df.empty:
        sel_u = st.selectbox("Select User to Edit", users_df["username"].tolist())
        row = load_table("SELECT * FROM users WHERE username=?;", (sel_u,)).iloc[0]
        new_role = st.selectbox("Role", ["user","admin"], index=["user","admin"].index(row["role"]))
        new_active = st.checkbox("Active", value=bool(row["active"]))
        # link member:
        idx = 0
        if not members.empty:
            name_to_id = {"-- none --": None}
            name_to_id.update({r["name"]: int(r["id"]) for _, r in members.iterrows()})
            id_to_name = {v:k for k,v in name_to_id.items()}
            current_name = id_to_name.get(row["team_member_id"], "-- none --")
            idx = list(name_to_id.keys()).index(current_name)
        new_member = st.selectbox("Link Member", list(member_map.keys()), index=idx)
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("Apply User Changes"):
                with get_conn() as conn:
                    conn.execute("UPDATE users SET role=?, active=?, team_member_id=? WHERE id=?;",
                                 (new_role, 1 if new_active else 0, member_map.get(new_member), int(row["id"])))
                st.success("User updated")
        with c2:
            new_pw = st.text_input("New Password", type="password", key="resetpw")
            if st.button("Reset Password"):
                if not new_pw:
                    st.warning("Enter a new password")
                else:
                    ph, salt = _hash_password(new_pw)
                    with get_conn() as conn:
                        conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?;", (ph, salt, int(row["id"])))
                    st.success("Password reset")
        with c3:
            st.caption("Delete user not exposed to keep history. Deactivate instead.")
