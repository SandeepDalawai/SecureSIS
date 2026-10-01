from flask import Blueprint, render_template, jsonify
from database import query_db
from rbac import role_required
from datetime import datetime, timedelta

security_bp = Blueprint('security_bp', __name__, url_prefix='/security')

def get_security_stats():
    total_users = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
    total_students = query_db('SELECT COUNT(*) as count FROM students', one=True)['count']
    
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    
    failed_logins = query_db("SELECT COUNT(*) as count FROM audit_logs WHERE action = 'LOGIN' AND result = 'FAILURE' AND timestamp > ?", (yesterday,), one=True)['count']
    unauth_attempts = query_db("SELECT COUNT(*) as count FROM security_events WHERE event_type = 'UNAUTHORIZED_ACCESS' AND timestamp > ?", (yesterday,), one=True)['count']
    integrity_violations = query_db("SELECT COUNT(*) as count FROM integrity_records WHERE status = 'VIOLATED'", one=True)['count']
    
    backups = query_db('SELECT * FROM backups ORDER BY created_at DESC LIMIT 1', one=True)
    last_backup_time = backups['created_at'] if backups else None
    backups_available = query_db('SELECT COUNT(*) as count FROM backups WHERE status = "VALID"', one=True)['count']
    
    last_integ = query_db('SELECT MAX(last_verified) as dt FROM integrity_records', one=True)
    last_integrity_check = last_integ['dt'] if last_integ and last_integ['dt'] else None
    
    return {
        'total_users': total_users,
        'total_students': total_students,
        'failed_logins': failed_logins,
        'unauthorized_attempts': unauth_attempts,
        'integrity_violations': integrity_violations,
        'backups_available': backups_available,
        'last_backup_time': last_backup_time,
        'last_integrity_check': last_integrity_check
    }

def get_recommendations(stats):
    recs = []
    if stats['failed_logins'] > 5:
        recs.append("Review authentication attempts and consider implementing multi-factor authentication.")
    if stats['integrity_violations'] > 0:
        recs.append("Investigate unauthorized data modifications and restore verified data from backup.")
    
    if not stats['last_backup_time']:
        recs.append("Create a new database backup to ensure data availability.")
    else:
        last_backup = datetime.fromisoformat(stats['last_backup_time'])
        if (datetime.now() - last_backup).total_seconds() > 86400:
            recs.append("Create a new database backup to ensure data availability.")
            
    if stats['unauthorized_attempts'] > 3:
        recs.append("Review RBAC permissions and strengthen access control policies.")
        
    if not recs:
        recs.append("All security controls are functioning normally. Continue monitoring.")
        
    return recs

@security_bp.route('/')
@role_required('admin')
def security_index():
    stats = get_security_stats()
    recs = get_recommendations(stats)
    events = query_db('SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 50')
    return render_template('security_events.html', stats=stats, recommendations=recs, events=events)

@security_bp.route('/api/stats')
@role_required('admin')
def api_stats():
    stats = get_security_stats()
    return jsonify(stats)
