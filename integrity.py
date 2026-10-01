import json
import hashlib
from flask import Blueprint, render_template, request, session, jsonify, redirect, url_for, flash
from database import query_db, execute_db
from rbac import role_required
from audit import log_audit, log_security_event
from datetime import datetime

integrity_bp = Blueprint('integrity_bp', __name__, url_prefix='/integrity')


def compute_hash(student_record):
    """Compute SHA-256 hash of critical student record fields."""
    fields = {
        'student_id': student_record['student_id'],
        'name': student_record['name'],
        'department': student_record['department'],
        'semester': student_record['semester'],
        'email': student_record['email'],
        'marks': student_record['marks'],
        'attendance': student_record['attendance']
    }
    serialized = json.dumps(fields, sort_keys=True)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def generate_integrity_hash(student_id):
    """Generate and store integrity hash for a student record."""
    student = query_db('SELECT * FROM students WHERE student_id = ?', (student_id,), one=True)
    if not student:
        return
    record_hash = compute_hash(student)

    existing = query_db('SELECT id FROM integrity_records WHERE student_id = ?', (student_id,), one=True)
    now = datetime.now().isoformat()
    if existing:
        execute_db('UPDATE integrity_records SET record_hash = ?, last_verified = ?, status = ? WHERE student_id = ?',
                   (record_hash, now, 'VERIFIED', student_id))
    else:
        execute_db('INSERT INTO integrity_records (student_id, record_hash, last_verified, status) VALUES (?, ?, ?, ?)',
                   (student_id, record_hash, now, 'VERIFIED'))


def verify_student_integrity(student_id):
    """Verify integrity of a single student record."""
    student = query_db('SELECT * FROM students WHERE student_id = ?', (student_id,), one=True)
    record = query_db('SELECT * FROM integrity_records WHERE student_id = ?', (student_id,), one=True)

    if not student or not record:
        return {'student_id': student_id, 'name': 'Unknown', 'status': 'NOT FOUND',
                'stored_hash': 'N/A', 'current_hash': 'N/A'}

    current_hash = compute_hash(student)
    stored_hash = record['record_hash']

    now = datetime.now().isoformat()
    if current_hash == stored_hash:
        execute_db("UPDATE integrity_records SET last_verified = ?, status = 'VERIFIED' WHERE student_id = ?",
                   (now, student_id))
        return {
            'student_id': student_id,
            'name': student['name'],
            'stored_hash': stored_hash,
            'current_hash': current_hash,
            'status': 'VERIFIED',
            'last_verified': now
        }
    else:
        execute_db("UPDATE integrity_records SET last_verified = ?, status = 'VIOLATED' WHERE student_id = ?",
                   (now, student_id))
        log_security_event('INTEGRITY_VIOLATION', 'CRITICAL', 'SYSTEM',
                           f'Integrity violation detected for student {student_id}')
        return {
            'student_id': student_id,
            'name': student['name'],
            'stored_hash': stored_hash,
            'current_hash': current_hash,
            'status': 'VIOLATED',
            'last_verified': now
        }


def verify_all_integrity():
    """Verify integrity of all student records."""
    students = query_db('SELECT student_id FROM students')
    results = []
    for s in students:
        results.append(verify_student_integrity(s['student_id']))
    return results


# ── Routes ────────────────────────────────────────────────────────────────

@integrity_bp.route('/')
@role_required('admin', 'faculty')
def integrity_index():
    results = verify_all_integrity()
    log_audit(session.get('username'), session.get('role'), 'INTEGRITY_CHECK',
              'All Records', 'SUCCESS', f'Verified {len(results)} records', request.remote_addr)
    return render_template('integrity.html', results=results)


@integrity_bp.route('/check', methods=['POST'])
@role_required('admin', 'faculty')
def integrity_check():
    """POST endpoint to run verification and redirect back."""
    results = verify_all_integrity()
    violations = sum(1 for r in results if r['status'] == 'VIOLATED')
    log_audit(session.get('username'), session.get('role'), 'INTEGRITY_CHECK',
              'All Records', 'SUCCESS',
              f'Verified {len(results)} records, {violations} violations found', request.remote_addr)
    if violations > 0:
        flash(f'Integrity verification complete: {violations} violation(s) detected!', 'danger')
    else:
        flash(f'Integrity verification complete: All {len(results)} records verified ✓', 'success')
    return redirect(url_for('integrity_bp.integrity_index'))


@integrity_bp.route('/verify/<student_id>', methods=['POST'])
@role_required('admin', 'faculty')
def verify_single(student_id):
    result = verify_student_integrity(student_id)
    log_audit(session.get('username'), session.get('role'), 'INTEGRITY_CHECK',
              f'Student:{student_id}', result['status'], 'Performed integrity verification',
              request.remote_addr)
    return jsonify(result)


@integrity_bp.route('/lab')
@role_required('admin')
def integrity_lab():
    students = query_db('SELECT * FROM students ORDER BY student_id')
    selected_id = request.args.get('student_id')
    result = None
    tamper_result = None

    if selected_id:
        student = query_db('SELECT * FROM students WHERE student_id = ?', (selected_id,), one=True)
        record = query_db('SELECT * FROM integrity_records WHERE student_id = ?', (selected_id,), one=True)
        if student and record:
            current_hash = compute_hash(student)
            result = {
                'student_id': student['student_id'],
                'name': student['name'],
                'marks': student['marks'],
                'stored_hash': record['record_hash'],
                'current_hash': current_hash,
                'status': record['status']
            }
            # Check if there's an active tamper (stored hash != current hash)
            if current_hash != record['record_hash']:
                tamper_result = {
                    'student_id': student['student_id'],
                    'old_hash': record['record_hash'],
                    'new_hash': current_hash,
                    'status': 'VIOLATED'
                }

    return render_template('integrity_lab.html', students=students,
                           result=result, tamper_result=tamper_result)


@integrity_bp.route('/lab/tamper', methods=['POST'])
@role_required('admin')
def tamper_record():
    student_id = request.form.get('student_id')
    tampered_marks = request.form.get('new_marks') or request.form.get('tampered_marks')

    student = query_db('SELECT marks FROM students WHERE student_id = ?', (student_id,), one=True)
    if student:
        # Store original marks in session for later restoration
        session[f'original_marks_{student_id}'] = student['marks']

        # Tamper WITHOUT updating the integrity hash (this is the key!)
        execute_db('UPDATE students SET marks = ? WHERE student_id = ?', (tampered_marks, student_id))
        log_audit(session.get('username'), session.get('role'), 'DATA_TAMPER',
                  f'Student:{student_id}', 'SUCCESS',
                  f'Simulated data tampering: marks changed from {student["marks"]} to {tampered_marks}',
                  request.remote_addr)
        log_security_event('DATA_TAMPER_SIMULATION', 'HIGH', session.get('username'),
                           f'Marks for {student_id} tampered: {student["marks"]} → {tampered_marks}')
        flash(f'Tamper simulation applied! Marks changed from {student["marks"]} to {tampered_marks}. Run integrity verification to detect.', 'warning')
    else:
        flash('Student not found', 'danger')

    return redirect(url_for('integrity_bp.integrity_lab', student_id=student_id))


@integrity_bp.route('/lab/restore', methods=['POST'])
@role_required('admin')
def restore_record():
    student_id = request.form.get('student_id')

    original_key = f'original_marks_{student_id}'
    if original_key in session:
        original_marks = session[original_key]
        execute_db('UPDATE students SET marks = ? WHERE student_id = ?', (original_marks, student_id))
        generate_integrity_hash(student_id)
        del session[original_key]
        log_audit(session.get('username'), session.get('role'), 'DATA_RESTORE',
                  f'Student:{student_id}', 'SUCCESS',
                  f'Restored original data (marks={original_marks}) and regenerated hash',
                  request.remote_addr)
        flash(f'Original record restored successfully! Marks restored to {original_marks}. Integrity hash regenerated ✓', 'success')
    else:
        flash('No original data found in session. Record may already be restored.', 'warning')

    return redirect(url_for('integrity_bp.integrity_lab', student_id=student_id))
