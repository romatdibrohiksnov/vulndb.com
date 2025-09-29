# Security Advisory: Unauthenticated SQL Injection allows mass deletion in delete.php
- Vulnerability Type: SQL Injection (Critical, Unauthenticated, destructive)
- Affected Project: Student-Registration-Crud-Operation
- Component: delete.php
- Severity: Critical
- CVSS v3.1 Vector (estimated): AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H (High/Critical)
- Discovery Date: 2025-09-29
- Reporter: px

## Summary

An unauthenticated SQL injection exists in `delete.php` where the `id` GET parameter is directly concatenated into a SQL DELETE statement without validation or parameterization. An attacker can execute destructive SQL, including mass deletion of all records in the `card_activation` table, by sending a crafted request without any prior authentication.

## Affected Versions

- All versions of the sample application where `delete.php` contains:
  <mcfile name="delete.php" path="c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\delete.php"></mcfile> lines 4–8

## Technical Details

- Vulnerable code:
  <mcfile name="delete.php" path="c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\delete.php"></mcfile>

  ```php c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\delete.php
  include('db.php');
  $id = $_GET['id'];
  $delete = "DELETE FROM card_activation WHERE id = $id";
  $run_data = mysqli_query($con,$delete);
  ```
  
- Root cause:
  - The untrusted `GET` parameter `id` is concatenated into a SQL command without any sanitization, validation, or parameter binding.
  - There is no authentication/authorization check, so anyone can access `delete.php`.

- Impact:
  - Mass deletion of records within `card_activation`.
  - Potential for broader SQL manipulation depending on server configuration (stacked queries, comments).
  
- Trust boundary and exposure:
  - Public unauthenticated endpoint → direct SQL execution.
  - No CSRF/authorization/role checks.

## Proof of Concept (PoC)

- Prerequisites:
  - Application deployed and accessible via browser (e.g., `http://localhost/Student-Registration-Crud-Operation/index.php`)
  - Database initialized per `card_activation.sql`, and `db.php` configured:
    <mcfile name="db.php" path="c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\db.php"></mcfile> lines 1–9

- Steps to reproduce:
  1. Navigate to `index.php` and observe the number of records listed.
  2. Send one of the following requests:
     - Raw spaces:
       `http://localhost/Student-Registration-Crud-Operation/delete.php?id=1 OR 1=1 --`
     - URL-encoded (more stable across servers):
       `http://localhost/Student-Registration-Crud-Operation/delete.php?id=1%20OR%201%3D1%20--%20`
     - If comment style differs, try:
       `http://localhost/Student-Registration-Crud-Operation/delete.php?id=1%20OR%201%3D1`
  3. After execution, the application usually redirects back to `index.php`. The list is observed to be drastically reduced or empty, demonstrating mass deletion.


## Severity and Scoring

- Prompt-based scoring:
  - Impact(I)=3 (destructive DB operations)
  - Exploitability(E)=3 (no authentication)
  - Interaction(H)=3 (no user interaction)
  - Exposure(X)=2 (public route)
  - Chainability(C)=1.5 (precondition for further attacks)
  - Score = (I×E + H + X) × C = (9 + 5) × 1.5 = 21 → P1 (Critical)
- CVSS v3.1 (estimated):
  - AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H → High/Critical

## Remediation

1. Parameterize SQL
   - Use prepared statements (`mysqli->prepare`) and bind parameters with strict typing:
     - Ensure `id` is properly validated as an integer.
2. Enforce authorization
   - Restrict destructive operations (DELETE) to authenticated administrators (RBAC).
3. Input Validation
   - Validate and type-cast `id` using `ctype_digit()` or strict integer parsing before DB usage.
4. HTTP Method and CSRF
   - Use POST for state-changing operations and enforce CSRF protections.
   
### Secure Coding Example (reference patch outline)

- File: <mcfile name="delete.php" path="c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\delete.php"></mcfile>

```php c:\Downloads\Student_Crud_Operation_In_PHP_With_Source_Code\Student-Registration-Crud-Operation\delete.php
<?php
include('db.php');

// ... existing code ...

// Authorization check placeholder (ensure user session and role)
// if (!isAdminLoggedIn()) { http_response_code(403); exit('Forbidden'); }

// Validate id strictly
if (!isset($_GET['id']) || !ctype_digit($_GET['id'])) {
    http_response_code(400);
    exit('Invalid id');
}
$id = (int)$_GET['id'];

// Use parameterized query
$stmt = $con->prepare("DELETE FROM card_activation WHERE id = ?");
$stmt->bind_param("i", $id);
$ok = $stmt->execute();

if ($ok) {
    header('location:index.php');
} else {
    http_response_code(500);
    echo "Delete failed";
}

// ... existing code ...
?>
```

## References

- Project homepage: https://code-projects.org/student-crud-operation-in-php-with-source-code/ <mcreference link="https://code-projects.org/student-crud-operation-in-php-with-source-code/" index="0">0</mcreference>
- Source download page: https://download.code-projects.org/details/c4836779-1828-4e2b-95c2-e027096314c6 <mcreference link="https://download.code-projects.org/details/c4836779-1828-4e2b-95c2-e027096314c6" index="1">1</mcreference>


## Disclosure Timeline

- 2025-09-29: Vulnerability identified and verified with PoC.
- 2025-09-29: Advisory prepared for public disclosure and CVE submission.



