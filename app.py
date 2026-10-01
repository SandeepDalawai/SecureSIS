import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, session, request, flash, g, jsonify
from werkzeug.security import generate_password_hash

from config import Config
from database import init_db, get_db, close_db, query_db, execute_db
from auth import auth_bp, login_required, get_current_user
from rbac import role_required, can_access_classification, get_menu_items
from integrity import integrity_bp, verify_all_integrity, generate_integrity_hash, compute_hash, verify_student_integrity
from backup import backup_bp, list_backups
from security_events import security_bp, get_security_stats, get_recommendations
from audit import log_audit, log_security_event, get_audit_logs, get_security_events
from validators import (validate_student_id, validate_email, validate_marks,
                         validate_attendance, validate_role, validate_classification, sanitize_input)

app = Flask(__name__)
app.config.from_object(Config)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(integrity_bp)
app.register_blueprint(backup_bp)
app.register_blueprint(security_bp)


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=Config.SESSION_LIFETIME)

    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    # CSRF check on POST (skip login since user doesn't have a session yet)
    if request.method == 'POST' and request.endpoint and request.endpoint != 'auth.login':
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            log_audit(session.get('username', 'unknown'), session.get('role'), 'CSRF_VIOLATION',
                      request.path, 'FAILURE', 'CSRF token mismatch', request.remote_addr)
            flash('Security validation failed. Please try again.', 'danger')
            return redirect(request.referrer or url_for('dashboard'))


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)


@app.context_processor
def inject_globals():
    user = get_current_user()
    return {
        'current_user': user,
        'menu_items': get_menu_items(session.get('role')) if 'role' in session else [],
        'csrf_token': session.get('csrf_token', '')
    }


# ── Helper: compute CIA status from real system data ──────────────────────

def compute_cia_status():
    """Compute CIA status from actual system conditions."""
    # Confidentiality: always protected if auth system is running
    users_count = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
    conf_status = 'SECURE'

    # Integrity: check for violations
    violations = query_db("SELECT COUNT(*) as count FROM integrity_records WHERE status = 'VIOLATED'", one=True)['count']
    total_records = query_db("SELECT COUNT(*) as count FROM integrity_records", one=True)['count']
    integ_status = 'VERIFIED' if violations == 0 else 'VIOLATION DETECTED'

    # Availability: check database accessible and backups exist
    backups_available = query_db("SELECT COUNT(*) as count FROM backups WHERE status = 'VALID'", one=True)['count']
    db_accessible = True
    try:
        query_db('SELECT 1', one=True)
    except Exception:
        db_accessible = False
    avail_status = 'AVAILABLE' if db_accessible else 'DEGRADED'

    overall = 'SECURE' if (conf_status == 'SECURE' and integ_status == 'VERIFIED' and avail_status == 'AVAILABLE') else 'ATTENTION REQUIRED'

    return {
        'confidentiality': {
            'status': conf_status,
            'users_count': users_count,
        },
        'integrity': {
            'status': integ_status,
            'records_verified': total_records - violations,
            'violations': violations,
        },
        'availability': {
            'status': avail_status,
            'backups_available': backups_available,
            'db_accessible': db_accessible,
        },
        'overall': overall
    }


# ── Routes ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    cia_status = compute_cia_status()

    stats = {}
    student_info = None

    if user['role'] in ('admin', 'faculty'):
        stats = get_security_stats()
        # Add a count of security events for the dashboard
        events_count = query_db("SELECT COUNT(*) as count FROM security_events", one=True)['count']
        stats['security_events_count'] = events_count

    if user['role'] == 'student' and user.get('student_id'):
        student_info = query_db('SELECT * FROM students WHERE student_id = ?',
                                (user['student_id'],), one=True)

    recent_events = query_db('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 5')

    return render_template('dashboard.html',
                           cia_status=cia_status,
                           stats=stats,
                           student_info=student_info,
                           recent_events=recent_events)


@app.route('/students')
@login_required
def students():
    user = get_current_user()

    if user['role'] == 'student':
        # Students can only see their own record
        if user.get('student_id'):
            return redirect(url_for('student_detail', student_id=user['student_id']))
        flash('No student record associated with your account.', 'warning')
        return redirect(url_for('dashboard'))

    log_audit(user['username'], user['role'], 'RECORD_VIEW', 'Students List',
              'SUCCESS', 'Viewed students list', request.remote_addr)

    students_list = query_db('SELECT * FROM students ORDER BY student_id')
    return render_template('students.html', students=students_list)


@app.route('/students/<student_id>')
@login_required
def student_detail(student_id):
    user = get_current_user()
    student = query_db('SELECT * FROM students WHERE student_id = ?', (student_id,), one=True)

    if not student:
        flash('Student record not found.', 'danger')
        return render_template('404.html'), 404

    # Students can only see their own record
    if user['role'] == 'student' and user.get('student_id') != student_id:
        log_audit(user['username'], user['role'], 'ACCESS_DENIED',
                  f'Student:{student_id}', 'FAILURE',
                  'Student tried to access another student record', request.remote_addr)
        log_security_event('UNAUTHORIZED_ACCESS', 'MEDIUM', user['username'],
                           f"Student tried to access record of {student_id}")
        return redirect(url_for('access_denied'))

    log_audit(user['username'], user['role'], 'RECORD_VIEW',
              f'Student:{student_id}', 'SUCCESS', 'Viewed student details', request.remote_addr)

    # Integrity info
    integrity_info = None
    record = query_db('SELECT * FROM integrity_records WHERE student_id = ?', (student_id,), one=True)
    if record:
        current_hash = compute_hash(student)
        integrity_info = {
            'stored_hash': record['record_hash'],
            'current_hash': current_hash,
            'status': record['status'],
            'last_verified': record['last_verified']
        }

    # Determine editable fields
    can_edit = user['role'] in ('admin', 'faculty')
    edit_fields = []
    if user['role'] == 'admin':
        edit_fields = ['name', 'department', 'semester', 'email', 'phone', 'dob',
                       'address', 'marks', 'attendance', 'academic_status', 'classification']
    elif user['role'] == 'faculty':
        edit_fields = ['marks', 'attendance']

    return render_template('student_detail.html', student=student,
                           integrity_info=integrity_info,
                           can_edit=can_edit, edit_fields=edit_fields)


@app.route('/students/add', methods=['GET', 'POST'])
@role_required('admin')
def add_student():
    if request.method == 'POST':
        student_id = sanitize_input(request.form.get('student_id', ''))
        name = sanitize_input(request.form.get('name', ''))
        dept = sanitize_input(request.form.get('department', ''))
        sem = request.form.get('semester', '5')
        email = sanitize_input(request.form.get('email', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        dob = sanitize_input(request.form.get('dob', ''))
        address = sanitize_input(request.form.get('address', ''))
        marks = request.form.get('marks', '0')
        att = request.form.get('attendance', '0')
        cls = request.form.get('classification', 'CONFIDENTIAL')
        academic_status = 'Excellent' if int(marks) >= 80 else 'Good' if int(marks) >= 60 else 'Average' if int(marks) >= 40 else 'At Risk'

        errors = []
        if not validate_student_id(student_id):
            errors.append('Invalid Student ID (must be STU followed by 3 digits)')
        if not validate_email(email):
            errors.append('Invalid email format')
        if not validate_marks(marks):
            errors.append('Marks must be 0-100')
        if not validate_attendance(att):
            errors.append('Attendance must be 0-100')
        if not validate_classification(cls):
            errors.append('Invalid classification')

        if errors:
            for e in errors:
                flash(e, 'danger')
        else:
            existing = query_db('SELECT id FROM students WHERE student_id = ?', (student_id,), one=True)
            if existing:
                flash('Student ID already exists', 'danger')
            else:
                execute_db("""
                    INSERT INTO students (student_id, name, department, semester, email, phone, dob, address, marks, attendance, academic_status, classification)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (student_id, name, dept, sem, email, phone, dob, address, marks, att, academic_status, cls))

                generate_integrity_hash(student_id)
                log_audit(session['username'], session['role'], 'RECORD_CREATE',
                          f'Student:{student_id}', 'SUCCESS', 'Added new student', request.remote_addr)
                flash('Student added successfully', 'success')
                return redirect(url_for('students'))

    return render_template('add_student.html')


@app.route('/students/update/<student_id>', methods=['POST'])
@login_required
def update_student(student_id):
    user = get_current_user()

    # Students cannot update records
    if user['role'] == 'student':
        log_audit(user['username'], user['role'], 'MODIFY_DENIED',
                  f'Student:{student_id}', 'FAILURE',
                  'Student attempted to modify records', request.remote_addr)
        log_security_event('UNAUTHORIZED_MODIFICATION', 'HIGH', user['username'],
                           f"Student attempted to modify record {student_id}")
        flash('You are not authorized to modify records.', 'danger')
        return redirect(url_for('access_denied'))

    if user['role'] == 'faculty':
        marks = request.form.get('marks')
        att = request.form.get('attendance')
        if validate_marks(marks) and validate_attendance(att):
            execute_db("UPDATE students SET marks = ?, attendance = ?, updated_at = ? WHERE student_id = ?",
                       (marks, att, datetime.now().isoformat(), student_id))
            generate_integrity_hash(student_id)
            log_audit(user['username'], user['role'], 'RECORD_UPDATE',
                      f'Student:{student_id}', 'SUCCESS',
                      'Updated student marks/attendance', request.remote_addr)
            flash('Student record updated successfully', 'success')
        else:
            flash('Invalid marks or attendance value (must be 0-100)', 'danger')

    elif user['role'] == 'admin':
        name = sanitize_input(request.form.get('name', ''))
        dept = sanitize_input(request.form.get('department', ''))
        sem = request.form.get('semester', '5')
        email = sanitize_input(request.form.get('email', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        dob = sanitize_input(request.form.get('dob', ''))
        address = sanitize_input(request.form.get('address', ''))
        marks = request.form.get('marks', '0')
        att = request.form.get('attendance', '0')
        cls = request.form.get('classification', 'CONFIDENTIAL')
        academic_status = request.form.get('academic_status', 'Active')

        if validate_marks(marks) and validate_attendance(att):
            execute_db("""UPDATE students SET name=?, department=?, semester=?, email=?, phone=?,
                          dob=?, address=?, marks=?, attendance=?, academic_status=?,
                          classification=?, updated_at=? WHERE student_id=?""",
                       (name, dept, sem, email, phone, dob, address, marks, att,
                        academic_status, cls, datetime.now().isoformat(), student_id))
            generate_integrity_hash(student_id)
            log_audit(user['username'], user['role'], 'RECORD_UPDATE',
                      f'Student:{student_id}', 'SUCCESS',
                      'Updated student record (full)', request.remote_addr)
            flash('Student record updated successfully', 'success')
        else:
            flash('Invalid marks or attendance value (must be 0-100)', 'danger')

    return redirect(url_for('student_detail', student_id=student_id))


@app.route('/students/delete/<student_id>', methods=['POST'])
@role_required('admin')
def delete_student(student_id):
    execute_db('DELETE FROM students WHERE student_id = ?', (student_id,))
    execute_db('DELETE FROM integrity_records WHERE student_id = ?', (student_id,))
    log_audit(session['username'], session['role'], 'RECORD_DELETE',
              f'Student:{student_id}', 'SUCCESS', 'Deleted student', request.remote_addr)
    flash('Student deleted successfully', 'success')
    return redirect(url_for('students'))


@app.route('/cia')
@login_required
def cia():
    cia_status = compute_cia_status()
    stats = get_security_stats()
    recommendations = get_recommendations(stats)
    return render_template('cia.html',
                           cia_status=cia_status,
                           overall_status=cia_status['overall'],
                           recommendations=recommendations)


@app.route('/audit')
@role_required('admin', 'faculty')
def audit_logs():
    action_filter = request.args.get('action_type', '')
    user_filter = request.args.get('username', '')
    logs = get_audit_logs(limit=200, action_filter=action_filter or None,
                          user_filter=user_filter or None)
    return render_template('audit.html', logs=logs,
                           action_filter=action_filter, user_filter=user_filter)


@app.route('/users', methods=['GET', 'POST'])
@role_required('admin')
def manage_users():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        role = request.form.get('role', 'student')
        student_id = sanitize_input(request.form.get('student_id', '')) or None

        if username and password and validate_role(role):
            existing = query_db('SELECT id FROM users WHERE username = ?', (username,), one=True)
            if existing:
                flash('Username already exists', 'danger')
            else:
                execute_db("INSERT INTO users (username, password_hash, role, student_id) VALUES (?, ?, ?, ?)",
                           (username, generate_password_hash(password), role, student_id))
                log_audit(session['username'], session['role'], 'USER_CREATE',
                          f'User:{username}', 'SUCCESS', f'Created user with role {role}', request.remote_addr)
                flash('User added successfully', 'success')
        else:
            flash('Invalid input. Please provide username, password, and valid role.', 'danger')

    all_users = query_db('SELECT * FROM users ORDER BY id')
    return render_template('users.html', users=all_users)


@app.route('/users/update/<int:user_id>', methods=['POST'])
@role_required('admin')
def update_user(user_id):
    role = request.form.get('role')
    status = request.form.get('status')
    if validate_role(role) and status in ('active', 'locked', 'disabled'):
        execute_db("UPDATE users SET role = ?, status = ? WHERE id = ?", (role, status, user_id))
        log_audit(session['username'], session['role'], 'USER_UPDATE',
                  f'User ID:{user_id}', 'SUCCESS', f'Updated user role={role} status={status}', request.remote_addr)
        flash('User updated successfully', 'success')
    else:
        flash('Invalid role or status', 'danger')
    return redirect(url_for('manage_users'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    if user_id != session.get('user_id'):
        execute_db("DELETE FROM users WHERE id = ?", (user_id,))
        log_audit(session['username'], session['role'], 'USER_DELETE',
                  f'User ID:{user_id}', 'SUCCESS', 'Deleted user', request.remote_addr)
        flash('User deleted successfully', 'success')
    else:
        flash('Cannot delete your own account', 'danger')
    return redirect(url_for('manage_users'))


@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    user_db = query_db('SELECT * FROM users WHERE id = ?', (user['user_id'],), one=True)
    student_info = None
    if user.get('student_id'):
        student_info = query_db('SELECT * FROM students WHERE student_id = ?',
                                (user['student_id'],), one=True)
    return render_template('profile.html', user=user_db, student_info=student_info)


@app.route('/access-denied')
def access_denied():
    return render_template('access_denied.html'), 403


# ── Error handlers ────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs('database', exist_ok=True)
    os.makedirs('backups', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    init_db()

    # Generate integrity hashes for all students on first run
    with app.app_context():
        students_list = query_db('SELECT student_id FROM students')
        for s in students_list:
            existing = query_db('SELECT id FROM integrity_records WHERE student_id = ?',
                                (s['student_id'],), one=True)
            if not existing:
                generate_integrity_hash(s['student_id'])

    print("\n" + "=" * 60)
    print("  SecureSIS - CIA-Based Student Information System")
    print("=" * 60)
    print("  URL:   http://localhost:5000")
    print("  Auth:  Demo credentials are configured via .env")
    print("         See .env.example for setup instructions.")
    print("=" * 60 + "\n")

    app.run(debug=True, port=5000)
