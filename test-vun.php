<?php
// Connect to MySQL
$conn = mysqli_connect("localhost", "root", "", "test_db");

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Get username from GET request (e.g., ?username=admin)
$username = $_GET['username'];

// Vulnerable query - directly using user input
$sql = "SELECT * FROM users WHERE username = '$username'";

$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    echo "User found!";
} else {
    echo "No user found.";
}

mysqli_close($conn);
?>
