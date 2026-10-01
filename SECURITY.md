# SecureSIS Security Documentation

## Security Overview
This document details the specific security controls implemented in the SecureSIS academic prototype, explicitly mapped to the core components of the CIA Triad (Confidentiality, Integrity, and Availability). This documentation demonstrates how theoretical security concepts are applied practically in software development.

---

## Confidentiality Controls

### 1. Password Hashing
SecureSIS ensures that no passwords are ever stored in plaintext.
*   **Algorithm**: PBKDF2-SHA256 (Password-Based Key Derivation Function 2) implemented via the `Werkzeug.security` library.
*   **Mechanism**: Passwords are mathematically transformed into a one-way hash with a cryptographic salt. The salt protects against pre-computed rainbow table attacks.

### 2. Role-Based Access Control (RBAC)
Access to resources is strictly regulated based on user identity.
*   **Roles Implemented**: 
    *   **Admin**: Full system access, configuration, and security monitoring.
    *   **Faculty**: Access to view and manage student academic records.
    *   **Student**: Restricted access; can only view their *own* profile and records.
*   **Enforcement**: Backend enforcement on every route using Python decorators (e.g., `@requires_role('admin')`). Bypassing the UI will not bypass the RBAC check.

### 3. Data Classification
Data within the system is categorized to mandate appropriate handling and display controls.
*   **PUBLIC**: Department information, generic academic calendars.
*   **INTERNAL**: Aggregate enrollment details, faculty directories.
*   **CONFIDENTIAL**: Student contact info (Email, Phone), individual course marks.
*   **HIGHLY CONFIDENTIAL**: Complete academic transcripts, disciplinary records.
*   *Implementation*: The UI dynamically adjusts visibility and applies warning badges based on the data classification level of the information being rendered.

### 4. Session Security
Secure session management prevents session hijacking and fixation.
*   **HTTP-Only Cookies**: Prevents client-side scripts (JavaScript) from accessing the session token, mitigating XSS risks.
*   **SameSite Attribute**: Configured to `Lax` or `Strict` to prevent Cross-Site Request Forgery (CSRF).
*   **Session Timeout**: Automatic invalidation of idle sessions after a configured duration.

---

## Integrity Controls

### 1. SHA-256 Integrity Hashing
To ensure data has not been secretly tampered with in the database, SecureSIS employs cryptographic hashing for integrity verification (Note: This is hashing for integrity, NOT encryption).
*   **Algorithm**: SHA-256 (Secure Hash Algorithm 256-bit).
*   **Process**: 
    1. Critical fields (e.g., Student ID, Semester, Marks) are deterministically serialized into a string.
    2. A SHA-256 hash is computed from this string and stored alongside the record upon creation/update.
    3. During an integrity check, the application recalculates the hash from the current database values and compares it to the stored hash. A mismatch indicates unauthorized tampering.

### 2. Tamper Detection (Integrity Lab)
An interactive module designed to demonstrate integrity failures.
*   **Functionality**: Allows administrators to intentionally bypass application logic and edit database records directly (simulating an attacker modifying the raw SQLite file).
*   **Detection**: Running the Integrity Checker immediately flags the tampered row because the raw data was changed without updating the associated cryptographic hash.

### 3. Audit Trail
A comprehensive, tamper-resistant logging system for non-repudiation.
*   **Events Logged**: Logins (Success/Failure), Logouts, Authorization Failures (403), Data Modifications, Backup Creations, and Integrity Violations.
*   **Data Captured**: Timestamp, Event Type, User ID (if authenticated), IP Address, and specific event details.

### 4. Input Validation
Defending against malformed data and injection attacks.
*   **SQL Injection Prevention**: Exclusive use of parameterized queries and ORM techniques; user input is never concatenated directly into SQL statements.
*   **Input Sanitization**: HTML entity encoding to prevent stored Cross-Site Scripting (XSS).
*   **Type/Range Validation**: Ensuring inputs like "marks" or "attendance" fall within mathematically acceptable bounds (e.g., 0-100) before database insertion.

---

## Availability Controls

### 1. Database Backup
Ensuring data survives catastrophic failure or corruption.
*   **Mechanism**: Automated and manual triggers to create point-in-time snapshots of the SQLite database.
*   **Metadata**: The system tracks backup timestamps, filenames, and statuses in a dedicated registry.

### 2. Recovery System
The ability to restore operations quickly.
*   **Restore Process**: Administrators can select a historical backup from the Backup Center and restore the system to that exact state, effectively overwriting tampered or lost data.
*   **Verification**: The system runs a post-restore integrity check to ensure the restored data is valid.

### 3. Error Handling
Maintaining system uptime during unexpected faults.
*   **Graceful Degradation**: Custom error pages (404, 403, 500) prevent application crashes.
*   **Information Concealment**: Detailed stack traces are suppressed in the production environment to prevent information leakage to attackers.

---

## Additional Web Security

### Web Security Headers
SecureSIS utilizes HTTP response headers to harden the browser's interaction with the application:
*   `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
*   `X-Frame-Options: DENY`: Prevents the site from being rendered in an iframe (Clickjacking protection).
*   `X-XSS-Protection: 1; mode=block`: Instructs older browsers to block detected XSS attacks.
*   `Content-Security-Policy (CSP)`: Restricts where scripts and resources can be loaded from.
*   `Referrer-Policy: strict-origin-when-cross-origin`: Controls referral information passed to external sites.

### CSRF Protection
*   **Token-Based Prevention**: Every state-changing request (POST, PUT, DELETE) requires a unique, session-tied CSRF token.
*   **Validation**: The server rejects any request missing a valid token, preventing attackers from forging requests on behalf of authenticated users.

---

## Threat Model (Simplified)

| Threat | Attack Vector | Implemented Mitigation | CIA Focus |
|---|---|---|---|
| Unauthorized Access | Guessing URLs, bypassing UI | Authentication + Strict RBAC decorators | Confidentiality |
| Credential Theft | Database breach | PBKDF2-SHA256 Password Hashing | Confidentiality |
| Data Tampering | Direct DB edit, malicious admin | SHA-256 Record Integrity Verification | Integrity |
| SQL Injection | Malicious input in login/search | Parameterized Queries / ORM | Integrity/Conf. |
| Data Loss/Ransomware | Server crash, malicious deletion | Automated/Manual Backup System | Availability |
| Session Hijacking | Network sniffing, XSS | HTTP-Only/Secure Cookies + CSP | Confidentiality |
| Cross-Site Request Forgery | Malicious link execution | Anti-CSRF Tokens + SameSite Cookies | Integrity |

---

## Security Recommendations for Production
As this is an academic prototype, the following hardening steps are mandatory before any real-world deployment:
1.  **Migrate from SQLite to PostgreSQL/MySQL** to handle concurrent access securely.
2.  **Implement TLS/SSL (HTTPS)** to encrypt data in transit; currently, data (including passwords) is transmitted in plaintext over HTTP.
3.  **Implement Multi-Factor Authentication (MFA)** for all administrative accounts.
4.  **Implement Rate Limiting** on authentication endpoints to prevent brute-force attacks.
5.  **Establish Offsite Backups**: Local backups do not protect against complete server loss.
6.  **Implement Database Encryption at Rest** to protect data if physical server access is compromised.
