from functools import wraps
from flask import session, redirect, url_for, request
from audit import log_audit, log_security_event


def role_required(*roles):
    """Decorator to enforce role-based access control on routes."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login'))
            user_role = session.get('role')
            if user_role not in roles:
                username = session.get('username')
                log_audit(username, user_role, 'ACCESS_DENIED', request.path,
                          'FAILURE', f'Unauthorized access attempt to {request.path}',
                          request.remote_addr)
                log_security_event('UNAUTHORIZED_ACCESS', 'MEDIUM', username,
                                   f'Role {user_role} attempted to access {request.path}')
                return redirect(url_for('access_denied'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def can_access_classification(user_role, classification):
    """Check if a role can access a given classification level."""
    if user_role == 'admin':
        return True
    if user_role == 'faculty':
        return classification in ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY CONFIDENTIAL')
    if user_role == 'student':
        return True  # Handled at record ownership level
    return False


def get_menu_items(role):
    """Return navigation menu items for a given role."""
    if role == 'admin':
        return [
            {'name': 'Dashboard', 'url': 'dashboard', 'icon': '🏠'},
            {'name': 'Students', 'url': 'students', 'icon': '👥'},
            {'name': 'CIA Center', 'url': 'cia', 'icon': '🛡️'},
            {'name': 'Integrity', 'url': 'integrity_bp.integrity_index', 'icon': '🔒'},
            {'name': 'Integrity Lab', 'url': 'integrity_bp.integrity_lab', 'icon': '🧪'},
            {'name': 'Backup Center', 'url': 'backup_bp.backup_index', 'icon': '💾'},
            {'name': 'Audit Logs', 'url': 'audit_logs', 'icon': '📋'},
            {'name': 'Security Events', 'url': 'security_bp.security_index', 'icon': '⚠️'},
            {'name': 'Users', 'url': 'manage_users', 'icon': '👤'},
            {'name': 'Profile', 'url': 'profile', 'icon': '📊'},
        ]
    elif role == 'faculty':
        return [
            {'name': 'Dashboard', 'url': 'dashboard', 'icon': '🏠'},
            {'name': 'Students', 'url': 'students', 'icon': '👥'},
            {'name': 'CIA Center', 'url': 'cia', 'icon': '🛡️'},
            {'name': 'Integrity', 'url': 'integrity_bp.integrity_index', 'icon': '🔒'},
            {'name': 'Audit Logs', 'url': 'audit_logs', 'icon': '📋'},
            {'name': 'Profile', 'url': 'profile', 'icon': '📊'},
        ]
    elif role == 'student':
        return [
            {'name': 'Dashboard', 'url': 'dashboard', 'icon': '🏠'},
            {'name': 'My Profile', 'url': 'profile', 'icon': '📊'},
            {'name': 'CIA Center', 'url': 'cia', 'icon': '🛡️'},
        ]
    return []
