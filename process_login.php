<?php
// process_login.php

session_start();
require_once 'config.php'; // update path if config.php is in a different folder

// If already logged in, send them to home
if (isset($_SESSION['user_id'])) {
    header("Location: EcoGlob.html");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve and sanitise inputs
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Validate basic input
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

    // Prepare SQL to fetch user record
    $sql = "SELECT user_id, name, email, password_hash FROM users WHERE email = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($user_id, $name, $db_email, $db_password_hash);
            $stmt->fetch();

            // Verify password
            if (password_verify($password, $db_password_hash)) {
                // Set session variables
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user_id;
                $_SESSION['name'] = $name;
                $_SESSION['email'] = $db_email;

                // Redirect to home page
                header("Location: EcoGlob.html");
                exit();
            } else {
                $_SESSION['error'] = "Invalid email or password.";
                header("Location: login.html");
                exit();
            }
        } else {
            $_SESSION['error'] = "Invalid email or password.";
            header("Location: login.html");
            exit();
        }

        $stmt->close();
    } else {
        $_SESSION['error'] = "Something went wrong. Please try again.";
        header("Location: login.html");
        exit();
    }

    $conn->close();
} else {
    // If not a POST request, redirect to login page
    header("Location: login.html");
    exit();
}
?>