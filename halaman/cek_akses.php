<?php
require_once 'config.php';
require_once 'includes/security.php';
ekantin_secure_session_start(); // SR-08: cookie sesi Secure/HttpOnly/SameSite
header('Content-Type: application/json');

$response = ['blocked' => false, 'etalase' => 'buka'];

$username = $_GET['username'] ?? '';
if ($username !== '' && !ekantin_valid_npm($username)) {
    $username = '';
}

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    echo json_encode(['error' => 'Koneksi database gagal']);
    exit;
}

$result = $conn->query("SELECT status FROM status_etalase");
if ($row = $result->fetch_assoc()) {
    $response['etalase'] = $row['status'];
}

if ($username) {
    $stmt = $conn->prepare("SELECT blokir FROM akun WHERE npm = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($blokir_status);
    if ($stmt->fetch()) {
        $response['blocked'] = $blokir_status == 1;
    }
    $stmt->close();
}

$conn->close();

echo json_encode($response);
