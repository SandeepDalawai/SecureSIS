from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from database import query_db, execute_db
from werkzeug.security import check_password_hash
from functools import wraps
from config import Config
from datetime import datetime, timedelta
from audit import log_audit, log_security_event
from validators import sanitize_input

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return {
            'user_id': session['user_id'],
            'username': session['username'],
            'role': session['role'],
            'student_id': session.get('student_id')
        }
    return None

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
        
        if user:
            # Check lockout
            if user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
                flash('Account is locked. Try again later.', 'danger')
                return render_template('login.html')
            
            if check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['student_id'] = user['student_id']
                
                # Reset failed attempts and set last login
                execute_db("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?", (datetime.now().isoformat(), user['id']))
                log_audit(username, user['role'], 'LOGIN', 'SYSTEM', 'SUCCESS', 'User logged in successfully', request.remote_addr)
                
                return redirect(url_for('dashboard'))
            else:
                attempts = user['failed_attempts'] + 1
                locked_until = None
                if attempts >= Config.MAX_LOGIN_ATTEMPTS:
                    locked_until = (datetime.now() + timedelta(seconds=Config.LOCKOUT_DURATION)).isoformat()
                    log_security_event('LOGIN_LOCKOUT', 'HIGH', username, f'Account locked after {attempts} failed attempts')
                
                execute_db("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (attempts, locked_until, user['id']))
                log_audit(username, None, 'LOGIN', 'SYSTEM', 'FAILURE', 'Invalid credentials', request.remote_addr)
                flash('Invalid username or password', 'danger')
        else:
            log_audit(username, None, 'LOGIN', 'SYSTEM', 'FAILURE', 'User not found', request.remote_addr)
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    if 'username' in session:
        log_audit(session['username'], session['role'], 'LOGOUT', 'SYSTEM', 'SUCCESS', 'User logged out', request.remote_addr)
    session.clear()
    return redirect(url_for('auth.login'))
