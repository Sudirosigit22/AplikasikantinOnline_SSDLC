<?php
require_once 'config.php';
require_once 'includes/security.php';

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
  http_response_code(500);
  echo "Koneksi gagal.";
  exit;
}

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

if (empty($username) || empty($password)) {
  echo "NPM dan password harus diisi!";
  exit;
}

// SR-01: validasi format input sebelum digunakan pada query.
if (!ekantin_valid_npm($username)) {
  echo "NPM tidak ditemukan!";
  exit;
}

// SR-01: parameterized query / prepared statement dipertahankan.
$sql = "SELECT * FROM akun WHERE NPM = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
  echo "NPM tidak ditemukan!";
} else {
    $row = $result->fetch_assoc();
    if (empty($row['password'])) {
        // SR-08: hashing password menggunakan mekanisme yang direkomendasikan
        // (bcrypt via PASSWORD_DEFAULT) dipertahankan.
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $sql = "UPDATE akun SET password = ? WHERE NPM = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $hashed_password, $username);
        if ($stmt->execute()) {
            ekantin_log_event_mysqli($conn, 'register_password_created', $username, 'Password awal berhasil dibuat');
            echo "Password berhasil dibuat!";
        } else {
            echo "Gagal mendaftar.";
        }
    } else {
        echo "Password sudah dibuat!";
    }
}

$conn->close();
