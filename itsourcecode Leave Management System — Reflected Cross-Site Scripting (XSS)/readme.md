**Summary**

- A reflected XSS vulnerability exists in the password reset flow. The controller builds a client-side JavaScript redirect with unsanitized query parameters, allowing injection into the window.location string.
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Affected deployment: PHP-based Leave Management System from itsourcecode.
- Project page: itsourcecode Leave Management System - Project Page:https://itsourcecode.com/free-projects/php-project/leave-management-system-php-source-code/.

**Root Cause**
The redirect() function constructs a client-side redirect using inline JavaScript and injects the $location string directly into window.location without output encoding. When doresetpass() builds a $location value that includes the attacker-controlled id parameter, any single quote in id breaks out of the JS string and allows arbitrary script execution.

**Attack Scenario**

1. A victim is authenticated and visits a password reset page or follows an attacker-crafted link.
2. The attacker crafts a link where the id parameter contains an XSS payload that closes the JavaScript string and injects script.
3.On a failed reset attempt (e.g., incorrect current password), the application issues a JavaScript redirect using the poisoned $location string, executing the injected script in the victim’s browser.

**Proof of Concept (PoC)**
Use the following request while authenticated (replace the session cookie value as appropriate). The id parameter injects a single quote followed by a script payload:

curl " http://localhost/leavesys/module/employee/controller.php?action=reset&id= %27%3Cscript%3Ealert(document.domain)%3C/script%3E&from=emp " -H "Cookie: PHPSESSID=REPLACE_WITH_VALID_SESSION" -H "Content-Type: application/x-www-form-urlencoded" --data "CURPASS=wrong&newpass=foo&cpass=bar"

Observed Result
The server responds with a deprecation notice and an inline JavaScript snippet that performs a redirect:
 <script>
    window.location='index.php?view=reset&id='
</script>
The alert(document.domain) payload runs, confirming reflected XSS.

**Impact**
Successful exploitation allows an attacker to run arbitrary JavaScript in the context of a victim’s session. This can lead to session hijacking, credential theft, CSRF token exfiltration, DOM manipulation, or forced navigations. Because the vulnerable path requires authentication and is commonly accessible to employees, the attack can be delivered via links or injected flows in internal portals.

Severity
Proposed CVSS v3.1 Base Score: 6.1 (Medium)
Vector: AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N

Remediation

- Replace client-side redirects with server-side redirects. Use header('Location: ...', true, 302); exit; instead of printing JavaScript.
- Validate and constrain the id parameter in the password reset flow. Enforce type (e.g., numeric ID) and reject unexpected characters.
- Apply contextual output encoding to any user-controlled data. For HTML, use htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . For JavaScript contexts, avoid inline JavaScript altogether; if unavoidable, use strict encoding libraries and safe JS templating.
- Remove inline script-based navigation. Prefer HTTP-level redirects or templated anchors with sanitized HREFs.
- Modernize autoloading. Replace __autoload() with spl_autoload_register() and refactor the autoload logic accordingly to eliminate deprecation warnings.


2025-10-01: Vulnerability discovered and verified
Researcher:px