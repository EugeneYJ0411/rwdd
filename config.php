<?php
// Database credentials
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ecoglob');
define('DB_CHARSET', 'utf8mb4');

// Connection options — using MySQLi (you could switch to PDO if you prefer)
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Check connection
if ($conn->connect_error) {
    // In production you might log this rather than show it
    die("Database connection failed: " . $conn->connect_error);
}

// Set charset
if (!$conn->set_charset(DB_CHARSET)) {
    // Log error: failed to set charset
    // For now, silently fail or handle as you choose
}

?>