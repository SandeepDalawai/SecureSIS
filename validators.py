import re
import html

def validate_student_id(sid):
    return bool(re.match(r'^STU\d{3}$', str(sid)))

def validate_email(email):
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', str(email)))

def validate_marks(marks):
    try:
        m = int(marks)
        return 0 <= m <= 100
    except ValueError:
        return False

def validate_attendance(att):
    try:
        a = int(att)
        return 0 <= a <= 100
    except ValueError:
        return False

def validate_role(role):
    return role in ('admin', 'faculty', 'student')

def validate_classification(cls):
    return cls in ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY CONFIDENTIAL')

def sanitize_input(text):
    if text is None:
        return None
    return html.escape(str(text).strip())
