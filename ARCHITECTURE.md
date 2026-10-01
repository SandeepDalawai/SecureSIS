# SecureSIS Architecture

## System Overview
SecureSIS employs a layered architectural pattern typical of monolithic web applications, specifically designed to emphasize security boundaries. The architecture separates concerns into distinct layers: Presentation, Application, Security, and Data, ensuring that security controls (like RBAC and Integrity checks) act as non-bypassable middleware between user interactions and database transactions.

## Architecture Diagram

```text
+-------------------------------------------------------------------------+
|                         CLIENT LAYER (Browser)                          |
|  [HTML5 / Bootstrap 5 UI] <----> [HTTPS Requests / Web Forms / AJAX]    |
+-------------------------------------------------------------------------+
                                  |   ^
                                  v   |
+-------------------------------------------------------------------------+
|                  PRESENTATION LAYER (Jinja2 Templates)                  |
|  [Dashboard Views]   [Authentication Forms]   [Data Tables / Reports]   |
+-------------------------------------------------------------------------+
                                  |   ^
                                  v   |
+-------------------------------------------------------------------------+
|                  APPLICATION LAYER (Flask Routes/Blueprints)            |
|  [app.py]   [auth.py]   [students.py]   [backup.py]   [integrity.py]    |
+-------------------------------------------------------------------------+
                                  |   ^
                                  v   |
+-------------------------------------------------------------------------+
|   ============= SECURITY LAYER (The CIA Enforcement Zone) ===========   |
|   [Authentication (Werkzeug)]        [RBAC Decorators (rbac.py)]        |
|   [Input Validators (validators.py)] [Audit Logger (audit.py)]          |
|   [SHA-256 Hashing Engine]           [CSRF Protection]                  |
+-------------------------------------------------------------------------+
                                  |   ^
                                  v   |
+-------------------------------------------------------------------------+
|                       DATA LAYER (SQLite Database)                      |
|  [Users Table] [Students Table] [Academic Records] [Audit Logs Table]   |
+-------------------------------------------------------------------------+
                                  |   ^
                                  v   |
+-------------------------------------------------------------------------+
|                       BACKUP LAYER (File System)                        |
|  [Local Backup Archives]  <--->  [Recovery Scripts]                     |
+-------------------------------------------------------------------------+
```

## Module Descriptions

*   **`app.py`**: The main application entry point. It initializes the Flask application, registers blueprints, configures global error handlers, and sets up middleware (like CSRF protection and before-request logging).
*   **`config.py`**: Centralized configuration management. Loads environment variables, manages database URIs, sets session timeouts, and configures security header parameters.
*   **`database.py`**: Handles database connection pooling, schema initialization, and initial data seeding (inserting demo users and default roles).
*   **`auth.py`**: The Authentication blueprint. Handles login, logout, session creation, and interfaces with Werkzeug for password verification.
*   **`rbac.py`**: Implements Role-Based Access Control logic via custom Python decorators (e.g., `@login_required`, `@role_required('admin')`) applied to application routes.
*   **`integrity.py`**: The Integrity blueprint. Houses the SHA-256 integrity verification logic, serialization routines for database rows, and the Integrity Lab endpoints.
*   **`backup.py`**: The Backup and recovery blueprint. Handles creating SQLite snapshots, verifying backup integrity, and restoring the database to previous states.
*   **`audit.py`**: Audit logging functions. Provides standardized methods to write security events to the database synchronously.
*   **`security_events.py`**: Security monitoring blueprint. Provides the UI and logic for the Admin Security Dashboard, aggregating logs and system health metrics.
*   **`validators.py`**: Input validation utilities used across the application to sanitize input and prevent injection attacks.

## Data Flow

### Authentication Flow
1. User submits credentials via the Login Form.
2. Request routed to `/login` endpoint in `auth.py`.
3. System fetches user record by username from the Data Layer.
4. System uses Werkzeug's `check_password_hash` to compare the provided password against the stored PBKDF2-SHA256 hash.
5. If valid, a secure, HTTP-only session is created. If invalid, an event is sent to `audit.py`, and the user is rejected.

### Authorization Flow
1. Authenticated user requests a protected resource (e.g., `/admin/students`).
2. Flask processes the `@role_required('admin')` decorator.
3. System checks the role stored in the current Flask session against the required role matrix.
4. If authorized, the route executes. If denied, a 403 error is thrown, an ACCESS_DENIED event is logged via `audit.py`, and the user is redirected.

### Integrity Verification Flow
1. System reads a row from `academic_records`.
2. The `integrity.py` module serializes the critical fields (student_id, semester, marks).
3. The serialized string is hashed using `hashlib.sha256()`.
4. The newly computed hash is compared to the `record_hash` stored in the database.
5. If they match, the record is flagged as VERIFIED. If they differ, the record is flagged as COMPROMISED/TAMPERED.

### Backup Flow
1. Admin triggers a manual backup via the UI.
2. `backup.py` initiates a read-lock on the SQLite database.
3. The database file is safely copied to a timestamped archive file in the Backup Layer.
4. Metadata (filename, timestamp) is recorded in the `backups` table.
5. The lock is released.

### CIA Security Assessment Flow
1. The CIA Dashboard requests a system status update.
2. **C**: System checks session validity and RBAC strictness.
3. **I**: System runs a background sweep of all `academic_records` hashes to detect tampering.
4. **A**: System verifies the existence and integrity of the latest backup file.
5. An aggregated status (e.g., "SECURE", "WARNING") is presented to the user.

## Security Architecture
The system relies on a Defense-in-Depth strategy layered as follows:
1.  **Authentication Layer**: Validates identity. Prevents anonymous access.
2.  **Authorization Layer**: Validates permissions. Prevents privilege escalation and horizontal data traversal.
3.  **Data Protection Layer**: Hashes passwords at rest and hashes records to detect data manipulation.
4.  **Audit Layer**: Captures non-repudiable logs of critical system events.
5.  **Recovery Layer**: Ensures business continuity by allowing rapid restoration from untampered backups.

## Database Schema (ER Diagram Description)

*   **Users (1) --- (1) Students**: One-to-one relationship. A user account (with role 'student') maps exactly to one academic student profile.
*   **Students (1) --- (N) Academic_Records**: One-to-many relationship. A student can have multiple academic records (one per semester).
*   **Users (1) --- (N) Audit_Logs**: One-to-many relationship. A single user can generate multiple audit log events. (Note: Some audit logs may have a null user_id if they pertain to failed logins from unknown users).
*   **System --- (N) Backups**: The backups table is isolated and tracks system-level backup archives independent of user relationships.

## Blueprint Registration
The Flask application is modularized using Blueprints for maintainability and separation of security domains:
*   `/auth` - Handles login, logout, and session establishment.
*   `/integrity` - Handles all SHA-256 hash verification and the Integrity Lab simulation.
*   `/backup` - Manages database backup creation and restoration endpoints.
*   `/security` - Manages the Security Events dashboard and audit log viewing.
*   `/students` - Handles standard CRUD operations for student records.
