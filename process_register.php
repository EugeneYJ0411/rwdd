<?php
// process_register.php

session_start();

// Include config file (make sure path is correct)
require_once 'config.php'; // adjust the path if needed

// Database credentials — **update** with your actual values
$DB_HOST = 'localhost';
$DB_USER = 'your_db_username';
$DB_PASS = 'your_db_password';
$DB_NAME = 'your_db_name';

// Connect to MySQL
$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Collect and sanitise inputs
    $name     = trim($_POST['name'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $password2= $_POST['password2'] ?? '';
    $terms    = isset($_POST['terms']);

    // Basic validation
    if (empty($name) || empty($email) || empty($password) || empty($password2)) {
        $_SESSION['error'] = "Please fill in all required fields.";
        header("Location: register.html");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error'] = "Invalid email address.";
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

    // Check if email already exists
    $sql = "SELECT user_id FROM users WHERE email = ?";
    $stmt = $conn->prepare($sql);
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

    // Hash password (use password_hash)
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user record
    $sql = "INSERT INTO users (name, email, password_hash, registered_date) VALUES (?, ?, ?, NOW())";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sss", $name, $email, $password_hash);

    if ($stmt->execute()) {
        // Success — redirect to login or dashboard
        $_SESSION['success'] = "Account created successfully. Please login.";
        $stmt->close();
        $conn->close();
        header("Location: login.html");
        exit();
    } else {
        // Error
        $_SESSION['error'] = "Registration failed: " . $conn->error;
        $stmt->close();
        $conn->close();
        header("Location: register.html");
        exit();
    }
} else {
    // If not a POST request, redirect back
    header("Location: register.html");
    exit();
}
?>
