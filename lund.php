<?php
session_start();

// Redirect if user or admin is already logged in
if (isset($_SESSION["user"])) {
    header("Location: index.php");
    exit();
} elseif (isset($_SESSION["admin"])) {
    header("Location: admin_dashboard.php");
    exit();
}
require_once "dbconnection.php"; // Database connection

// Display logout message if redirected from logout.php
$logoutMessage = "";
if (isset($_GET['message']) && $_GET['message'] == 'logged_out') {
    $logoutMessage = "You have successfully logged out.";
}

// Error Reporting for debugging (can be turned off in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Handle form submissions
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST["email"];
    $password = $_POST["password"];

    // User login
    if (isset($_POST["login"])) {
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $user = mysqli_fetch_assoc($result);

            if ($user && password_verify($password, $user["password"])) {
                $_SESSION["user"] = $user["id"];
                header("Location: index.php");
                exit();
            } else {
                echo "<div class='alert alert-danger'>Email or password is incorrect.</div>";
            }
        } else {
            echo "<div class='alert alert-danger'>SQL Error: " . mysqli_error($conn) . "</div>";
        }
    }

    // Admin login
    elseif (isset($_POST["admin_login"])) {
        $sql = "SELECT * FROM admins WHERE email = ?";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $admin = mysqli_fetch_assoc($result);
            if (!$admin) {
                echo "<div class='alert alert-danger'>No admin found with this email.</div>";
            } else if ($admin && password_verify($password, $admin["password"])) {
                $_SESSION["admin"] = $admin["id"];
                $_SESSION["role"] = 'admin';
                header("Location: admin_dashboard.php");
                exit();
            } else {
                echo "<div class='alert alert-danger'>Email or password is incorrect.</div>";
            }
        } else {
            echo "<div class='alert alert-danger'>SQL Error: " . mysqli_error($conn) . "</div>";
        }
    }

    // User Registration
    elseif (isset($_POST["register"])) {
        $fullname = $_POST["fullname"];
        $password_repeat = $_POST["repeat_password"];

        if ($password !== $password_repeat) {
            echo "<div class='alert alert-danger'>Passwords do not match.</div>";
        } else {
            $password_hashed = password_hash($password, PASSWORD_DEFAULT);

            $sql = "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)";
            $stmt = mysqli_stmt_init($conn);
            if (mysqli_stmt_prepare($stmt, $sql)) {
                mysqli_stmt_bind_param($stmt, "sss", $fullname, $email, $password_hashed);
                if (mysqli_stmt_execute($stmt)) {
                    echo "<div class='alert alert-success'>Registration successful! You can now log in.</div>";
                } else {
                    echo "<div class='alert alert-danger'>Error during registration. Please try again.</div>";
                }
            }
        }
    }
}
?>