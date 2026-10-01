# 🛡️ SecureSIS – CIA-Based Student Information System

## Project Overview
A security-centric Student Information System designed to demonstrate the practical implementation of the CIA Triad (Confidentiality, Integrity, Availability) for protecting student information. Built as an academic prototype for 5th Semester B.Tech CSE – Information Assurance.

## Problem Statement
Student information systems handle sensitive data including personal details, academic records, and contact information. Without proper security controls, this data is vulnerable to unauthorized access, tampering, and loss. This project demonstrates how the CIA Triad addresses these security challenges through practical application design and implementation.

## Objectives
1. Implement Confidentiality through authentication, RBAC, and data classification.
2. Implement Integrity through cryptographic hashing (SHA-256) for integrity verification and tamper detection.
3. Implement Availability through robust database backup and recovery mechanisms.
4. Create a unified security dashboard demonstrating all three CIA principles in action.
5. Provide a demonstrable academic prototype with clear, inspectable security controls.

## CIA Triad Mapping

| Security Principle | Implementation | Feature |
|---|---|---|
| **Confidentiality** | Password Hashing (Werkzeug) | Secure Authentication |
| **Confidentiality** | Role-Based Access Control | Admin/Faculty/Student roles |
| **Confidentiality** | Data Classification | 4-level classification system |
| **Confidentiality** | Session Management | Secure session handling |
| **Integrity** | SHA-256 Hashing | Record integrity verification |
| **Integrity** | Tamper Detection | Integrity Lab demonstration |
| **Integrity** | Audit Logging | Security event tracking |
| **Integrity** | Input Validation | Data validation controls |
| **Availability** | Database Backup | SQLite backup mechanism |
| **Availability** | Recovery System | Backup restoration |
| **Availability** | Database Verification | Health checks |

## Features
1. **Secure Authentication**: Password hashing using PBKDF2-SHA256 ensuring no plaintext passwords are saved.
2. **Role-Based Access Control**: Strict access boundaries separating Admins, Faculty, and Students.
3. **Data Classification**: Visual and programmatic data classification (Public, Internal, Confidential, Highly Confidential).
4. **Student Data Management**: Core CRUD operations mapped to proper authorization controls.
5. **Integrity Protection (SHA-256)**: Cryptographic hashing for integrity verification of sensitive student records.
6. **Tamper Detection (Integrity Lab)**: Interactive lab to demonstrate detecting unauthorized database modifications.
7. **Audit Logging**: Comprehensive logging of security events (logins, access denials, data changes).
8. **Security Event Dashboard**: Visual tracking and review of the audit logs for administrative oversight.
9. **Backup & Recovery Center**: Tools to ensure system availability through manual and automated database backups.
10. **Availability Demonstration**: Mechanism to intentionally delete and seamlessly recover data.
11. **CIA Security Center**: Central dashboard aggregating the current state of Confidentiality, Integrity, and Availability.
12. **Security Recommendation Engine**: Context-aware suggestions based on current system health.
13. **Professional Dashboard**: Clean, responsive UI for easy navigation of security controls.
14. **Security Headers & Web Security**: Implementation of standard web security headers and CSRF protection.
15. **Error Handling**: Graceful error handling avoiding stack trace exposure to end users.

## Technology Stack
| Component | Technology |
|---|---|
| Backend | Python 3, Flask 3.0 |
| Database | SQLite 3 |
| Frontend | HTML5, CSS3, JavaScript (Bootstrap 5) |
| Password Hashing | Werkzeug (PBKDF2-SHA256) |
| Integrity Hashing | SHA-256 (hashlib) |
| Session Management | Flask Sessions |

## Project Structure
```text
SecureSIS/
├── app.py                 # Main application & routing logic
├── config.py              # Application and security configuration
├── requirements.txt       # Python dependencies
├── .env.example           # Example environment variables
├── modules/
│   ├── __init__.py
│   ├── auth.py            # Authentication logic & session handling
│   ├── rbac.py            # Role-Based Access Control decorators
│   ├── integrity.py       # SHA-256 hashing and verification functions
│   ├── backup.py          # Backup and recovery implementation
│   ├── audit.py           # Event logging logic
│   ├── database.py        # Database connection & models
│   ├── security_events.py # Security monitoring and events
│   └── validators.py      # Input validation utilities
├── static/
│   ├── css/
│   │   └── style.css      # Custom styling
│   └── js/
│       └── main.js        # Frontend interactions
├── templates/
│   ├── base.html          # Base Jinja2 layout
│   ├── auth/              # Login & registration templates
│   ├── dashboard/         # Role-specific dashboards
│   ├── students/          # Student management views
│   └── security/          # Integrity Lab, Audit Logs, Backups
└── instance/
    └── securesis.db       # SQLite Database (generated on run)
```

## Database Design

### 1. `users` Table
| Column | Type | Description |
|---|---|---|
| id | INTEGER (PK) | Unique user identifier |
| username | VARCHAR(50) | User's login name |
| password_hash | VARCHAR(255) | PBKDF2-SHA256 hashed password |
| role | VARCHAR(20) | User role (admin, faculty, student) |
| is_active | BOOLEAN | Account status |

### 2. `students` Table
| Column | Type | Description |
|---|---|---|
| id | INTEGER (PK) | Unique student identifier |
| user_id | INTEGER (FK) | Link to `users` table |
| roll_number | VARCHAR(20) | Unique academic roll number |
| full_name | VARCHAR(100) | Student's full name |
| department | VARCHAR(50) | Enrolled department |

### 3. `academic_records` Table
| Column | Type | Description |
|---|---|---|
| id | INTEGER (PK) | Unique record identifier |
| student_id | INTEGER (FK) | Link to `students` table |
| semester | INTEGER | Current semester |
| marks | FLOAT | Total marks obtained |
| attendance | FLOAT | Attendance percentage |
| record_hash | VARCHAR(64) | SHA-256 hash for integrity checking |

### 4. `audit_logs` Table
| Column | Type | Description |
|---|---|---|
| id | INTEGER (PK) | Unique log identifier |
| timestamp | DATETIME | When the event occurred |
| event_type | VARCHAR(50) | Category of event (e.g., LOGIN, TAMPER) |
| user_id | INTEGER | Associated user (if any) |
| details | TEXT | Description of the event |

### 5. `backups` Table
| Column | Type | Description |
|---|---|---|
| id | INTEGER (PK) | Unique backup identifier |
| filename | VARCHAR(255) | Name of backup file |
| created_at | DATETIME | Backup creation time |
| status | VARCHAR(20) | Status (VALID, CORRUPTED) |

### 6. `data_classifications` Table
| Column | Type | Description |
|---|---|---|
| table_name | VARCHAR(50) | Name of the database table |
| classification | VARCHAR(20) | Classification level |
| description | TEXT | Reasoning for classification level |

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps
```bash
# Clone or download the project
cd SecureSIS

# Create virtual environment (recommended)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```
*Note: The database will be automatically initialized with demo data on the first run.*

### Access the Application
Open a web browser and navigate to: http://localhost:5000


## Demo Credentials

Demo account passwords are **not hardcoded** in the repository. They are configured through
environment variables before the first run. See [.env.example](.env.example) for the
required variable names.

When the database is first initialised and no environment variables are set, SecureSIS
will **generate a random password** for each demo account and print it once to the console.
Copy these values into your `.env` file to reuse them across restarts.

| Username | Role | Access Level |
|----------|------|--------------|
| `admin` | Admin | Full system access |
| `faculty` | Faculty | Academic data access |
| `student01` | Student | Own data only |


## Demonstration Procedure (5-8 minutes)
1. **Login as Admin**: Access the system and display the CIA Dashboard to highlight current security metrics.
2. **Browse Student Records**: Navigate to the student listing to showcase data classification badges (Public, Confidential, etc.).
3. **Login as Student (Confidentiality)**: Attempt unauthorized access (e.g., viewing admin panels). Show the ACCESS DENIED error and redirect.
4. **Attempt Unauthorized Modification**: As a student, attempt to modify academic marks. Show the MODIFICATION DENIED message.
5. **Open Integrity Lab (Integrity)**: As Admin, open the Integrity Lab. Simulate an unauthorized database tampering event (e.g., changing marks directly). Run the verification tool to show VIOLATION DETECTED.
6. **Restore Record (Integrity)**: Restore the original record from the Integrity Lab, re-verify, and show INTEGRITY VERIFIED.
7. **Simulate Data Loss (Availability)**: Create a fresh backup. Simulate a deletion of a crucial record. Restore from the Backup & Recovery Center and show DATA RECOVERED.
8. **Review Audit Logs**: Navigate to the Security Events page and show how all preceding actions (logins, access denials, tamper detections) were meticulously recorded.

## Test Cases
| TC ID | Description | Expected Result | CIA Principle | Status |
|---|---|---|---|---|
| TC-01 | Login with valid Admin credentials | Redirects to Admin Dashboard | Confidentiality | Pending |
| TC-02 | Login with invalid credentials | Shows "Invalid credentials" error | Confidentiality | Pending |
| TC-03 | Student attempts to access `/admin` | Returns 403 Forbidden | Confidentiality | Pending |
| TC-04 | Faculty views student list | Displays list without sensitive admin info | Confidentiality | Pending |
| TC-05 | Integrity verification on clean data | Reports "VERIFIED" | Integrity | Pending |
| TC-06 | Tamper backend data bypassing UI | System flags "HASH MISMATCH" | Integrity | Pending |
| TC-07 | Create manual backup | Backup file generated successfully | Availability | Pending |
| TC-08 | Restore from valid backup | Data is restored to previous state | Availability | Pending |
| TC-09 | Submit form without CSRF token | Request is blocked by server | Integrity/Conf. | Pending |
| TC-10 | Review audit logs for unauthorized access | Log entry exists for TC-03 | Integrity | Pending |

## Security Controls
- Robust authentication using Werkzeug's PBKDF2-SHA256 password hashing.
- Role-Based Access Control enforced on route level.
- SHA-256 cryptographic hashing for data integrity verification of academic records.
- Comprehensive security audit logging.
- Input validation and parameterized SQL queries to prevent injection attacks.
- Automated and manual local SQLite backups for availability.
- Basic security headers and CSRF protection.

## Limitations
- **Academic Prototype**: This is an academic prototype, not a production-ready system.
- **Database Scalability**: SQLite is not suitable for concurrent production use.
- **Transport Security**: No HTTPS (would require SSL certificate provisioning).
- **Authentication**: No multi-factor authentication (MFA); uses session-based auth without JWT.
- **Rate Limiting**: No rate limiting on API endpoints to prevent brute forcing.
- **Disaster Recovery**: Backups are stored locally on the same filesystem (no offsite backup).

## Future Enhancements
- Implementation of Multi-Factor Authentication (MFA).
- Full HTTPS/TLS implementation.
- Database encryption at rest (e.g., SQLCipher).
- Real-time intrusion detection and alerting.
- Email notifications for critical security events.
- Transition to a decoupled API-based architecture with JWT.
- Docker containerization for standardized deployments.

## Academic Disclaimer
This academic prototype demonstrates practical CIA Triad security controls for a Student Information System. It is designed for educational purposes and classroom demonstration. **It should not be deployed in a production environment without significant security hardening.** This software does not guarantee a system is safe from cyber threats.

## License
Academic Project – For Educational Use Only
