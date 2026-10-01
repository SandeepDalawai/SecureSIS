from database import execute_db, query_db
from datetime import datetime

def log_audit(username, role, action, resource, result, description, ip_address=None):
    now = datetime.now().isoformat()
    query = """
        INSERT INTO audit_logs (timestamp, username, role, action, resource, result, description, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    execute_db(query, (now, username, role, action, resource, result, description, ip_address))

def log_security_event(event_type, severity, username, description):
    now = datetime.now().isoformat()
    query = """
        INSERT INTO security_events (timestamp, event_type, severity, username, description)
        VALUES (?, ?, ?, ?, ?)
    """
    execute_db(query, (now, event_type, severity, username, description))

def get_audit_logs(limit=100, action_filter=None, user_filter=None):
    query = "SELECT * FROM audit_logs"
    args = []
    conditions = []
    if action_filter:
        conditions.append("action LIKE ?")
        args.append(f"{action_filter}%")
    if user_filter:
        conditions.append("username = ?")
        args.append(user_filter)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    return query_db(query, tuple(args))

def get_security_events(limit=50, severity_filter=None):
    query = "SELECT * FROM security_events"
    args = []
    if severity_filter:
        query += " WHERE severity = ?"
        args.append(severity_filter)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    return query_db(query, tuple(args))
