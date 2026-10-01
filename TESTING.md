# SecureSIS Testing Documentation

## Test Environment
*   **Language/Framework**: Python 3.x, Flask 3.0.x
*   **Database**: SQLite 3
*   **Operating Systems**: Compatible with Windows, Linux, and macOS
*   **Supported Browsers**: Google Chrome, Mozilla Firefox, Microsoft Edge (modern versions)

## Test Cases

### Authentication Tests (Confidentiality)

| TC ID | Test Case | Steps | Expected Result | CIA Principle | Status |
|---|---|---|---|---|---|
| TC01 | Valid Admin Login | 1. Navigate to `/login`<br>2. Enter admin credentials from .env<br>3. Submit | Login successful, redirected to Admin Dashboard. | Confidentiality | Not Run |
| TC02 | Invalid Password | 1. Navigate to `/login`<br>2. Enter admin / wrongpass<br>3. Submit | "Invalid credentials" error displayed. | Confidentiality | Not Run |
| TC03 | Non-existent User | 1. Navigate to `/login`<br>2. Enter unknown / pass<br>3. Submit | "Invalid credentials" error displayed. | Confidentiality | Not Run |
| TC04 | Account Lockout | 1. Attempt login with wrong password 5 consecutive times. | Account temporarily locked; "Account locked" error shown. | Confidentiality | Not Run |

### Authorization Tests (Confidentiality)

| TC ID | Test Case | Steps | Expected Result | CIA Principle | Status |
|---|---|---|---|---|---|
| TC05 | Student Views Own Record | 1. Login as student01<br>2. Navigate to own profile | Access granted, personal data displayed. | Confidentiality | Not Run |
| TC06 | Student Accesses All Students | 1. Login as student01<br>2. Force navigate to `/students` | Access denied. 403 Forbidden page displayed. | Confidentiality | Not Run |
| TC07 | Student Accesses Admin Panel | 1. Login as student01<br>2. Force navigate to `/users` or `/security` | Access denied. 403 Forbidden page displayed. | Confidentiality | Not Run |
| TC08 | Faculty Views Students | 1. Login as faculty<br>2. Navigate to `/students` | Access granted, student list displayed. | Confidentiality | Not Run |

### Integrity Tests

| TC ID | Test Case | Steps | Expected Result | CIA Principle | Status |
|---|---|---|---|---|---|
| TC09 | Integrity Check (Clean) | 1. Login as Admin<br>2. Go to Integrity Lab<br>3. Run Verification | All records show status VERIFIED. | Integrity | Not Run |
| TC10 | Tamper Detection | 1. Login as Admin<br>2. Use Integrity Lab to maliciously alter student marks<br>3. Run Verification | System flags the tampered record as VIOLATION DETECTED due to hash mismatch. | Integrity | Not Run |
| TC11 | Unauthorized Modification | 1. Login as student01<br>2. Attempt POST request to update own marks | Access denied (403). Transaction blocked. | Integrity | Not Run |
| TC12 | Integrity Restoration | 1. After TC10, use restore function to revert original data.<br>2. Run Verification again. | Record status returns to INTEGRITY VERIFIED. | Integrity | Not Run |

### Availability Tests

| TC ID | Test Case | Steps | Expected Result | CIA Principle | Status |
|---|---|---|---|---|---|
| TC13 | Create Backup | 1. Login as Admin<br>2. Go to Backup Center<br>3. Click "Create Backup" | Backup archive created successfully and listed in UI. | Availability | Not Run |
| TC14 | Delete and Restore | 1. Admin deletes a record.<br>2. Admin restores database from recent backup. | Record is fully recovered and accessible again. | Availability | Not Run |
| TC15 | Backup Verification | 1. Admin navigates to Backup Center.<br>2. Checks status of existing backups. | Backups show VALID status; corrupt backups flagged. | Availability | Not Run |

### Audit Tests

| TC ID | Test Case | Steps | Expected Result | CIA Principle | Status |
|---|---|---|---|---|---|
| TC16 | Login Event Logged | 1. Login as Admin.<br>2. Check Audit Logs. | LOGIN_SUCCESS event recorded with timestamp and IP. | Integrity | Not Run |
| TC17 | Denied Access Logged | 1. Login as Student.<br>2. Attempt to access `/users`.<br>3. Admin checks logs. | ACCESS_DENIED event recorded against the student's ID. | Integrity | Not Run |

## Security Testing (Penetration Test Simulations)

### SQL Injection Test
*   **Vector**: Authentication Form
*   **Test Input**: Entering `' OR '1'='1` in the username or password fields.
*   **Expected Result**: Request fails cleanly with "Invalid credentials". No database bypass possible due to the use of parameterized SQL queries.

### Unauthorized URL Access Test (Forced Browsing)
*   **Vector**: Address Bar
*   **Test Input**: While authenticated as a student, manually typing `http://localhost:5000/backup/restore`.
*   **Expected Result**: The application intercepts the request, evaluates the RBAC matrix, and returns a 403 Access Denied page without executing any backup logic.

### Session Security Test
*   **Vector**: Browser Session Management
*   **Test Input**: Log out of the application, then press the browser's "Back" button to submit a cached form.
*   **Expected Result**: The application validates the session state, identifies the user is logged out, and redirects to the login screen.

### CSRF Protection Test
*   **Vector**: Form Submission
*   **Test Input**: Using a tool like Postman to submit a POST request to `/students/update` without the embedded CSRF token.
*   **Expected Result**: The server rejects the request with a CSRF validation error, preventing state changes.

## Test Results Summary

| Category | Total Tests | Passed | Failed | Pending |
|---|---|---|---|---|
| Authentication | 4 | - | - | 4 |
| Authorization | 4 | - | - | 4 |
| Integrity | 4 | - | - | 4 |
| Availability | 3 | - | - | 3 |
| Audit | 2 | - | - | 2 |
| Security Vectors | 4 | - | - | 4 |
| **Total** | **21** | **-** | **-** | **21** |

*(Note: This table is meant to be updated with actual results upon completion of the manual or automated test suite.)*

## Demonstration Flow
The architecture is designed to map perfectly to a standard input/output processing flow, demonstrating the layered security approach:

```text
Student Data (INPUT)
        ↓
Confidentiality Check (Authentication + RBAC + Data Classification badges)
        ↓
Integrity Processing (SHA-256 Hashing + Integrity Verification + Audit Logging)
        ↓
Availability Safeguards (SQLite Backup + Recovery system)
        ↓
Security Result (OUTPUT: Unified CIA Status Dashboard)
```
