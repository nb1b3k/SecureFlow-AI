<?php
// Vulnerable: classic PHP SQL injection via $_GET concatenated into mysqli_query.
// CWE-89 / OWASP A03:2021 — Injection.

$mysqli = new mysqli("localhost", "user", "pass", "app");

$user_id = $_GET['id'];
$query = "SELECT id, name, email FROM users WHERE id = " . $user_id;
$result = $mysqli->query($query);

while ($row = $result->fetch_assoc()) {
    echo htmlspecialchars($row['name']) . "\n";
}
