<?php
// process_register_debug.php

// Enable full error reporting
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL); // Report everything. :contentReference[oaicite:1]{index=1}

session_start();

// Include database config
require_once 'config.php'; // Adjust path if needed

// Debug: Show that script started
// You can remove these echo statements later
echo "<!-- Debug: process_register_debug.php started -->\n";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    $_SESSION['error'] = "Invalid request method: " . $_SERVER["REQUEST_METHOD"];
    echo "<p>Debug: Invalid method = {$_SERVER['REQUEST_METHOD']}</p>";
    header("Location: register.html");
    exit();
}

// Get and sanitise inputs
if (isset($_POST['btnRegister'])) {
$name      = trim($_POST['name']    ?? '');
$email     = trim($_POST['email']   ?? '');
$password  = $_POST['password']     ?? '';
$password2 = $_POST['password2']    ?? '';
$terms     = isset($_POST['terms']) && $_POST['terms'] == '1';

echo "<!-- Debug: Received name={$name}, email={$email}, terms={$terms} -->\n";

if (empty($name) || empty($email) || empty($password) || empty($password2)) {
    $_SESSION['error'] = "Please fill in all required fields.";
    echo "<p>Debug: Missing field(s) — name: {$name}, email: {$email}, password blank?: " . (empty($password)?'yes':'no') . "</p>";
    header("Location: register.html");
    exit();
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error'] = "Please enter a valid email address.";
    echo "<p>Debug: Invalid email format: {$email}</p>";
    header("Location: register.html");
    exit();
}

if ($password !== $password2) {
    $_SESSION['error'] = "Passwords do not match.";
    echo "<p>Debug: Passwords mismatch — password vs password2</p>";
    header("Location: register.html");
    exit();
}

if (!$terms) {
    $_SESSION['error'] = "You must agree to the Terms & Conditions.";
    echo "<p>Debug: Terms not accepted</p>";
    header("Location: register.html");
    exit();
}

// Check for existing email
$sql = "SELECT user_id FROM users WHERE email = ?";
if ($stmt = $conn->prepare($sql)) {
    $stmt->bind_param("s", $email);
    if (!$stmt->execute()) {
        $_SESSION['error'] = "Database error (select execute) – please try again.";
        echo "<p>Debug: select execute failed — " . $stmt->error . "</p>";
        header("Location: register.html");
        exit();
    }
    $stmt->store_result();
    echo "<!-- Debug: select returned rows = " . $stmt->num_rows . " -->\n";
    if ($stmt->num_rows > 0) {
        $_SESSION['error'] = "An account with that email already exists.";
        $stmt->close();
        $conn->close();
        header("Location: register.html");
        exit();
    }
    $stmt->close();
} else {
    $_SESSION['error'] = "Database error (select prepare) – please try again.";
    echo "<p>Debug: select prepare failed — " . $conn->error . "</p>";
    header("Location: register.html");
    exit();
}

// Hash the password
$password_hash = password_hash($password, PASSWORD_DEFAULT);
echo "<!-- Debug: password_hash = {$password_hash} -->\n";

// Insert new user
$sql = "INSERT INTO users (name, email, password_hash, registered_date)
VALUES ('$name', '$email', '$password', NOW())";
if ($stmt = $conn->prepare($sql)) {
    $stmt->bind_param("sss", $name, $email, $password);
    if ($stmt->execute()) {
        $_SESSION['success'] = "Account created successfully. Please log in.";
        echo "<p>Debug: Registration success — new user_id = " . $stmt->insert_id . "</p>";
        $stmt->close();
        $conn->close();
        header("Location: login.html");
        exit();
    } else {
        $_SESSION['error'] = "Registration failed: " . $stmt->error;
        echo "<p>Debug: insert execute failed — " . $stmt->error . "</p>";
        $stmt->close();
        $conn->close();
        header("Location: register.html");
        exit();
    }
}
} else {
    $_SESSION['error'] = "Database error (insert prepare) – please try again.";
    echo "<p>Debug: insert prepare failed — " . $conn->error . "</p>";
    $conn->close();
    header("Location: register.html");
    exit();
}
?>
