import os
import shutil
from datetime import datetime
from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from database import query_db, execute_db
from config import Config
from rbac import role_required
from audit import log_audit, log_security_event

backup_bp = Blueprint('backup_bp', __name__, url_prefix='/backup')


def create_backup(username):
    """Create a backup of the database file."""
    os.makedirs(Config.BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"backup_{timestamp}.db"
    filepath = os.path.join(Config.BACKUP_DIR, filename)

    try:
        shutil.copy2(Config.DATABASE_PATH, filepath)
        size = os.path.getsize(filepath)
        execute_db('INSERT INTO backups (filename, created_by, size) VALUES (?, ?, ?)',
                   (filename, username, size))
        return {'status': 'SUCCESS', 'filename': filename, 'size': size}
    except Exception as e:
        log_security_event('BACKUP_FAILED', 'HIGH', username, str(e))
        return {'status': 'FAILURE', 'error': str(e)}


def list_backups():
    """List all backups from database."""
    return query_db('SELECT * FROM backups ORDER BY created_at DESC')


def restore_from_backup(backup_id, username):
    """Restore database from a backup file."""
    backup = query_db('SELECT * FROM backups WHERE id = ?', (backup_id,), one=True)
    if not backup:
        return False

    filepath = os.path.join(Config.BACKUP_DIR, backup['filename'])
    if not os.path.exists(filepath):
        execute_db("UPDATE backups SET status = 'INVALID' WHERE id = ?", (backup_id,))
        return False

    try:
        shutil.copy2(filepath, Config.DATABASE_PATH)
        log_audit(username, session.get('role'), 'BACKUP_RESTORE', 'DATABASE',
                  'SUCCESS', f"Restored from backup {backup['filename']}", request.remote_addr)
        log_security_event('BACKUP_RESTORE', 'INFO', username,
                           f"Database restored from {backup['filename']}")
        return True
    except Exception as e:
        log_security_event('RESTORE_FAILED', 'CRITICAL', username, str(e))
        return False


# ── Routes ────────────────────────────────────────────────────────────────

@backup_bp.route('/')
@role_required('admin')
def backup_index():
    backups = list_backups()
    students_list = query_db('SELECT * FROM students ORDER BY student_id')
    return render_template('backup.html', backups=backups, students_list=students_list)


@backup_bp.route('/create', methods=['POST'])
@role_required('admin')
def create_backup_route():
    result = create_backup(session.get('username'))
    if result['status'] == 'SUCCESS':
        log_audit(session.get('username'), session.get('role'), 'BACKUP_CREATE',
                  'DATABASE', 'SUCCESS',
                  f"Created backup {result['filename']} ({result['size']} bytes)",
                  request.remote_addr)
        flash(f"Backup created successfully: {result['filename']}", 'success')
    else:
        flash(f"Backup failed: {result.get('error')}", 'danger')
    return redirect(url_for('backup_bp.backup_index'))


@backup_bp.route('/restore/<int:backup_id>', methods=['POST'])
@role_required('admin')
def restore_backup_route(backup_id):
    if restore_from_backup(backup_id, session.get('username')):
        flash('Database restored successfully from backup!', 'success')
    else:
        flash('Failed to restore database', 'danger')
    return redirect(url_for('backup_bp.backup_index'))


@backup_bp.route('/availability-demo')
@role_required('admin')
def availability_demo():
    backups = list_backups()
    students_list = query_db('SELECT * FROM students ORDER BY student_id')
    demo_student = None
    demo_result = None

    student_id = request.args.get('student_id')
    if student_id:
        demo_student = query_db('SELECT * FROM students WHERE student_id = ?',
                                (student_id,), one=True)
        if not demo_student:
            demo_result = f'Record {student_id} NOT Found! Data Availability Compromised!'

    return render_template('backup.html', backups=backups, students_list=students_list,
                           demo=True, demo_student=demo_student, demo_result=demo_result)


@backup_bp.route('/demo/delete', methods=['POST'])
@role_required('admin')
def demo_delete():
    student_id = request.form.get('student_id')
    execute_db('DELETE FROM students WHERE student_id = ?', (student_id,))
    log_audit(session.get('username'), session.get('role'), 'DEMO_DELETE',
              f'Student:{student_id}', 'SUCCESS',
              'Simulated data loss for availability demonstration', request.remote_addr)
    log_security_event('AVAILABILITY_INCIDENT', 'HIGH', session.get('username'),
                       f'Record {student_id} deleted (availability demo)')
    flash(f'Record {student_id} deleted for availability demonstration', 'warning')
    return redirect(url_for('backup_bp.availability_demo', student_id=student_id))


@backup_bp.route('/demo/verify', methods=['POST', 'GET'])
@role_required('admin')
def demo_verify():
    student_id = request.form.get('student_id') or request.args.get('student_id')
    student = query_db('SELECT * FROM students WHERE student_id = ?', (student_id,), one=True)
    if student:
        flash(f'Record {student_id} exists! Availability: ✓ CONFIRMED', 'success')
    else:
        flash(f'Record {student_id} NOT FOUND! Availability: ⚠ COMPROMISED', 'danger')
    return redirect(url_for('backup_bp.availability_demo', student_id=student_id))
