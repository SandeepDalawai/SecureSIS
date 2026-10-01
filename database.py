import sqlite3
import os
from werkzeug.security import generate_password_hash
from config import Config

def get_db():
    os.makedirs('database', exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def close_db(e=None):
    pass

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    lastrowid = cur.lastrowid
    conn.close()
    return lastrowid

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    cur.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','faculty','student')),
    student_id TEXT,
    status TEXT DEFAULT 'active' CHECK(status IN ('active','locked','disabled')),
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    department TEXT NOT NULL,
    semester INTEGER NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    dob TEXT,
    address TEXT,
    marks INTEGER CHECK(marks >= 0 AND marks <= 100),
    attendance INTEGER CHECK(attendance >= 0 AND attendance <= 100),
    academic_status TEXT DEFAULT 'Active',
    classification TEXT DEFAULT 'CONFIDENTIAL' CHECK(classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','HIGHLY CONFIDENTIAL')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS integrity_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    last_verified TEXT,
    status TEXT DEFAULT 'VERIFIED',
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    user_id INTEGER,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    ip_address TEXT,
    result TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO' CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    username TEXT,
    description TEXT,
    status TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    created_by TEXT,
    size INTEGER,
    status TEXT DEFAULT 'VALID'
);
    """)
    conn.commit()
    
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        import os
        # Demo passwords are loaded from environment variables.
        # Set DEMO_ADMIN_PASSWORD, DEMO_FACULTY_PASSWORD, DEMO_STUDENT_PASSWORD in your .env file.
        # If not set, a random secure password is generated and printed once to the console.
        import secrets as _s
        def _demo_pwd(env_var, label):
            val = os.environ.get(env_var)
            if not val:
                val = _s.token_urlsafe(16)
                print(f"  [SecureSIS] No {env_var} set — generated demo {label} password: {val}")
                print(f"  [SecureSIS] Set {env_var}=<your-password> in .env to use a fixed password.")
            return val
        _admin_pwd   = _demo_pwd('DEMO_ADMIN_PASSWORD',   'admin')
        _faculty_pwd = _demo_pwd('DEMO_FACULTY_PASSWORD', 'faculty')
        _student_pwd = _demo_pwd('DEMO_STUDENT_PASSWORD', 'student')
        users = [
            ('admin',     generate_password_hash(_admin_pwd),   'admin',   None),
            ('faculty',   generate_password_hash(_faculty_pwd), 'faculty', None),
            ('student01', generate_password_hash(_student_pwd), 'student', 'STU001'),
        ]
        cur.executemany("INSERT INTO users (username, password_hash, role, student_id) VALUES (?, ?, ?, ?)", users)
        
        students = [
            ('STU001', 'Aarav Sharma', 'Computer Science', 5, 'aarav.sharma@university.edu', '+91-9876543210', '2004-03-15', '123 MG Road, Bangalore', 85, 92, 'Excellent', 'HIGHLY CONFIDENTIAL'),
            ('STU002', 'Priya Patel', 'Computer Science', 5, 'priya.patel@university.edu', '+91-9876543211', '2004-04-16', '124 MG Road, Bangalore', 78, 88, 'Good', 'CONFIDENTIAL'),
            ('STU003', 'Rahul Kumar', 'Electronics', 3, 'rahul.kumar@university.edu', '+91-9876543212', '2005-05-17', '125 MG Road, Bangalore', 92, 95, 'Excellent', 'CONFIDENTIAL'),
            ('STU004', 'Sneha Reddy', 'Computer Science', 5, 'sneha.reddy@university.edu', '+91-9876543213', '2004-06-18', '126 MG Road, Bangalore', 65, 75, 'Good', 'CONFIDENTIAL'),
            ('STU005', 'Arjun Singh', 'Mechanical', 7, 'arjun.singh@university.edu', '+91-9876543214', '2003-07-19', '127 MG Road, Bangalore', 71, 82, 'Good', 'INTERNAL'),
            ('STU006', 'Kavya Nair', 'Computer Science', 3, 'kavya.nair@university.edu', '+91-9876543215', '2005-08-20', '128 MG Road, Bangalore', 88, 90, 'Excellent', 'CONFIDENTIAL'),
            ('STU007', 'Mohammed Ali', 'Civil', 5, 'mohammed.ali@university.edu', '+91-9876543216', '2004-09-21', '129 MG Road, Bangalore', 73, 68, 'Good', 'CONFIDENTIAL'),
            ('STU008', 'Ananya Gupta', 'Computer Science', 5, 'ananya.gupta@university.edu', '+91-9876543217', '2004-10-22', '130 MG Road, Bangalore', 95, 97, 'Excellent', 'HIGHLY CONFIDENTIAL'),
            ('STU009', 'Vikram Joshi', 'Electronics', 7, 'vikram.joshi@university.edu', '+91-9876543218', '2003-11-23', '131 MG Road, Bangalore', 60, 72, 'Good', 'INTERNAL'),
            ('STU010', 'Deepika Menon', 'Computer Science', 3, 'deepika.menon@university.edu', '+91-9876543219', '2005-12-24', '132 MG Road, Bangalore', 82, 85, 'Excellent', 'CONFIDENTIAL'),
        ]
        cur.executemany("""
            INSERT INTO students (student_id, name, department, semester, email, phone, dob, address, marks, attendance, academic_status, classification)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, students)
        
        conn.commit()
    conn.close()
