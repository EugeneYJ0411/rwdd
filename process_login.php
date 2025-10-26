<?php
// process_login.php

session_start();

// Include config file (make sure path is correct)
require_once 'config.php'; // adjust the path if needed

// If user is already logged in, redirect (optional)
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");  // or home page of the app
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Get and sanitise inputs
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Basic validation
    if (empty($email) || empty($password)) {
        $_SESSION['error'] = "Please enter both email and password.";
        header("Location: login.html");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error'] = "Please enter a valid email address.";
        header("Location: login.html");
        exit();
    }

    // Prepare SQL select
    $sql = "SELECT user_id, name, email, password_hash FROM users WHERE email = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        // If user found
        if ($stmt->num_rows == 1) {
            $stmt->bind_result($user_id, $name, $db_email, $db_password_hash);
            $stmt->fetch();

            // Verify password
            if (password_verify($password, $db_password_hash)) {
                // Password is correct – create session
                session_regenerate_id(true); // regenerate session id for security
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_name'] = $name;
                $_SESSION['user_email'] = $db_email;

                // Redirect to dashboard or home page
                header("Location: dashboard.php");
                exit();
            } else {
                // Invalid password
                $_SESSION['error'] = "Invalid email or password.";
                header("Location: login.html");
                exit();
            }
        } else {
            // No user with that email
            $_SESSION['error'] = "Invalid email or password.";
            header("Location: login.html");
            exit();
        }

        $stmt->close();
    } else {
        // SQL prepare failed (error)
        $_SESSION['error'] = "Something went wrong. Please try again later.";
        header("Location: login.html");
        exit();
    }

    $conn->close();

} else {
    // Not a POST request
    header("Location: login.html");
    exit();
}
?>
