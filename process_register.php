<?php
// process_register.php

session_start();
require_once 'config.php'; // make sure the path is correct

// Only accept POST requests
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    $_SESSION['error'] = "Invalid request method.";
    header("Location: register.html");
    exit();
}

// Collect and sanitise inputs
$name      = trim($_POST['name']    ?? '');
$email     = trim($_POST['email']   ?? '');
$password  = $_POST['password']     ?? '';
$password2 = $_POST['password2']    ?? '';
$terms     = isset($_POST['terms']) && $_POST['terms'] == '1';

if (empty($name) || empty($email) || empty($password) || empty($password2)) {
    $_SESSION['error'] = "Please fill in all required fields.";
    header("Location: register.html");
    exit();
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error'] = "Please enter a valid email address.";
    header("Location: register.html");
    exit();
}

if ($password !== $password2) {
    $_SESSION['error'] = "Passwords do not match.";
    header("Location: register.html");
    exit();
}

if (!$terms) {
    $_SESSION['error'] = "You must agree to the Terms & Conditions.";
    header("Location: register.html");
    exit();
}

// Check for existing email
$sql = "SELECT user_id FROM users WHERE email = ?";
if ($stmt = $conn->prepare($sql)) {
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $_SESSION['error'] = "An account with that email already exists.";
        $stmt->close();
        $conn->close();
        header("Location: register.html");
        exit();
    }
    $stmt->close();
} else {
    $_SESSION['error'] = "Database error (select) – please try again.";
    header("Location: register.html");
    exit();
}

// Hash the password
$password_hash = password_hash($password, PASSWORD_DEFAULT);

// Insert new user
$sql = "INSERT INTO users (name, email, password_hash, registered_date) VALUES (?, ?, ?, NOW())";
if ($stmt = $conn->prepare($sql)) {
    $stmt->bind_param("sss", $name, $email, $password_hash);
    if ($stmt->execute()) {
        $_SESSION['success'] = "Account created successfully. Please log in.";
        $stmt->close();
        $conn->close();
        header("Location: login.html");
        exit();
    } else {
        $_SESSION['error'] = "Registration failed: " . $stmt->error;
        $stmt->close();
        $conn->close();
        header("Location: register.html");
        exit();
    }
} else {
    $_SESSION['error'] = "Database error (insert) – please try again.";
    $conn->close();
    header("Location: register.html");
    exit();
}
?>
