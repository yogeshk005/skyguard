import sqlite3
from datetime import datetime, timezone
from .config import DB_PATH

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def connect():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,user_id TEXT,name TEXT NOT NULL,description TEXT DEFAULT '',project_type TEXT DEFAULT 'application',primary_language TEXT DEFAULT '',root_label TEXT,token_hash TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,files_scanned INTEGER NOT NULL DEFAULT 0,findings_count INTEGER NOT NULL DEFAULT 0,scan_type TEXT NOT NULL DEFAULT 'full',status TEXT NOT NULL DEFAULT 'completed',FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,fingerprint TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,category TEXT NOT NULL,message TEXT NOT NULL,file_path TEXT,line INTEGER,column_no INTEGER,analyzer TEXT,code_snippet TEXT,status TEXT NOT NULL DEFAULT 'open',explanation TEXT,user_message TEXT,suggested_fix TEXT,created_at TEXT NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,UNIQUE(project_id,fingerprint));
        CREATE TABLE IF NOT EXISTS runtime_logs(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL,stack_trace TEXT,file_path TEXT,line INTEGER,occurred_at TEXT NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS project_context_files(project_id TEXT NOT NULL,file_path TEXT NOT NULL,content TEXT NOT NULL,sha256 TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(project_id,file_path),FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS project_context_state(project_id TEXT PRIMARY KEY,complete INTEGER NOT NULL DEFAULT 0,manifest_files INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id,started_at);
        """)
        # Upgrade databases from the unauthenticated MVP without losing their records.
        cols={r[1] for r in c.execute("PRAGMA table_info(projects)")}
        for name, definition in [("user_id","TEXT"),("description","TEXT DEFAULT ''"),("project_type","TEXT DEFAULT 'application'"),("primary_language","TEXT DEFAULT ''"),("token_hash","TEXT")]:
            if name not in cols: c.execute(f"ALTER TABLE projects ADD COLUMN {name} {definition}")
        c.execute("DELETE FROM findings WHERE rowid NOT IN (SELECT MIN(rowid) FROM findings GROUP BY project_id,fingerprint)")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_project_fingerprint ON findings(project_id,fingerprint)")

def now(): return datetime.now(timezone.utc).isoformat()
