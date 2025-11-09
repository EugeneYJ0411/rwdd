<?php
// process_login_debug.php

// Dev mode: Display all errors
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);  // See all kinds of notices/warnings/errors. :contentReference[oaicite:1]{index=1}

session_start();
require_once 'config.php'; // ensure correct path

echo "<!-- Debug: process_login_debug.php started -->\n";

// If already logged in
if (isset($_SESSION['user_id'])) {
    echo "<p>Debug: User already logged in (user_id = " . intval($_SESSION['user_id']) . ") — redirecting.</p>";
    header("Location: EcoGlob.html");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    $_SESSION['error'] = "Invalid request method: " . $_SERVER["REQUEST_METHOD"];
    echo "<p>Debug: Invalid request method detected: {$_SERVER['REQUEST_METHOD']}</p>";
    header("Location: login.html");
    exit();
}

// Collect and sanitise
$email    = trim($_POST['email']    ?? '');
$password = $_POST['password']     ?? '';

echo "<!-- Debug: Received email='{$email}', password blank?: " . (empty($password) ? 'yes' : 'no') . " -->\n";

if (empty($email) || empty($password)) {
    $_SESSION['error'] = "Please enter both email and password.";
    echo "<p>Debug: Validation failed — empty field(s) (email: '{$email}', password blank?: " . (empty($password) ? 'yes' : 'no') . ")</p>";
    header("Location: login.html");
    exit();
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error'] = "Please enter a valid email address.";
    echo "<p>Debug: Invalid email format: '{$email}'</p>";
    header("Location: login.html");
    exit();
}

// Prepare SELECT
$sql = "SELECT * FROM users 
WHERE email = '$email' AND password_hash = '$password'";
if ($stmt = $conn->prepare($sql)) {
    $stmt->bind_param("s", $email);
    if (!$stmt->execute()) {
        $_SESSION['error'] = "Database error (select execute) – please try again.";
        echo "<p>Debug: SELECT execute failed — stmt->error = " . htmlspecialchars($stmt->error) . "</p>";
        $stmt->close();
        $conn->close();
        header("Location: login.html");
        exit();
    }
    $stmt->store_result();
    echo "<!-- Debug: SELECT result rows = " . $stmt->num_rows . " -->\n";

    if ($stmt->num_rows == 1) {
        $stmt->bind_result($user_id, $name, $db_email, $password);
        $stmt->fetch();

        echo "<!-- Debug: Fetched user_id={$user_id}, name='{$name}', db_email='{$db_email}', db_password_hash='" . substr($db_password_hash,0,20) . "...' -->\n";

        // Verify password
        if (password_verify($password, $db_password_hash)) {
            echo "<p>Debug: password_verify returned TRUE</p>";
            session_regenerate_id(true);
            $_SESSION['user_id']    = $user_id;
            $_SESSION['user_name']  = $name;
            $_SESSION['user_email'] = $db_email;

            $stmt->close();
            $conn->close();

            header("Location: EcoGlob.html");
            exit();
        } else {
            $_SESSION['error'] = "Invalid email or password.";
            echo "<p>Debug: password_verify returned FALSE</p>";
            $stmt->close();
            $conn->close();
            header("Location: login.html");
            exit();
        }

    } else {
        $_SESSION['error'] = "Invalid email or password.";
        echo "<p>Debug: No user found for email '{$email}' (rows = {$stmt->num_rows})</p>";
        $stmt->close();
        $conn->close();
        header("Location: login.html");
        exit();
    }

} else {
    $_SESSION['error'] = "Database error (select prepare) – please try again.";
    echo "<p>Debug: SELECT prepare failed — conn->error = " . htmlspecialchars($conn->error) . "</p>";
    $conn->close();
    header("Location: login.html");
    exit();
}
?>