<?php
/**
 * reset_password.php
 * SR-03: Memvalidasi token reset password (single-use, memiliki batas
 * waktu) dan menetapkan password baru pengguna jika token valid.
 */

require_once 'config.php';
require_once 'includes/security.php';
header('Content-Type: application/json');

$token    = $_POST['token'] ?? '';
$password = $_POST['password'] ?? '';

if (!is_string($token) || strlen($token) !== 64 || !ctype_xdigit($token) || strlen($password) < 8) {
    echo json_encode(['status' => 'error', 'message' => 'Permintaan tidak valid atau password terlalu pendek (minimal 8 karakter).']);
    exit;
}

$tokenHash = hash('sha256', $token);

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $pdo->prepare("SELECT npm, expires_at, used FROM password_resets WHERE token_hash = ?");
    $stmt->execute([$tokenHash]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || (int)$row['used'] === 1 || strtotime($row['expires_at']) < time()) {
        echo json_encode(['status' => 'error', 'message' => 'Token tidak valid, sudah digunakan, atau sudah kedaluwarsa.']);
        exit;
    }

    $npm = $row['npm'];

    $pdo->beginTransaction();
    $hashed = password_hash($password, PASSWORD_DEFAULT);

    $upd = $pdo->prepare("UPDATE akun SET password = ? WHERE NPM = ?");
    $upd->execute([$hashed, $npm]);

    $mark = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE token_hash = ?");
    $mark->execute([$tokenHash]);

    // SR-02: reset counter lockout, karena password sudah diperbarui secara sah.
    $unlock = $pdo->prepare("UPDATE akun SET gagal_login = 0, locked_until = NULL WHERE NPM = ?");
    $unlock->execute([$npm]);

    $pdo->commit();

    ekantin_log_event_pdo($pdo, 'password_reset_success', $npm, 'Password berhasil direset melalui token');

    echo json_encode(['status' => 'ok', 'message' => 'Password berhasil diperbarui. Silakan login dengan password baru.']);
} catch (PDOException $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('reset_password.php PDOException: ' . $e->getMessage());
    echo json_encode(['status' => 'error', 'message' => 'Terjadi kesalahan sistem.']);
}
