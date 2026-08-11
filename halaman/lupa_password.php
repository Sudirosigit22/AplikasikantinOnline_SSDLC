<?php
/**
 * lupa_password.php
 * SR-03: Token reset password dibangkitkan secara acak (256-bit), disimpan
 * sebagai hash SHA-256 (bukan plaintext), memiliki batas waktu (15 menit),
 * bersifat sekali pakai, dan hanya dikirim ke kanal yang telah
 * terverifikasi kepemilikannya (email terdaftar pada akun).
 *
 * CATATAN IMPLEMENTASI: aplikasi E-Kantin eksisting tidak memiliki kanal
 * kontak (email/telepon) untuk pengguna. Migrasi (sql/migration_security.sql)
 * menambahkan kolom `email` opsional pada tabel akun sebagai kanal
 * terverifikasi. Jika akun belum memiliki email terdaftar, permintaan
 * ditolak agar token tidak pernah terekspos ke kanal yang tidak
 * terverifikasi. Pengiriman email di bawah ini menggunakan mail() bawaan
 * PHP sebagai referensi; pada lingkungan produksi sebaiknya diganti dengan
 * layanan SMTP/transactional email yang sudah dikonfigurasi.
 */

require_once 'config.php';
require_once 'includes/security.php';
header('Content-Type: application/json');

$npm   = $_POST['npm'] ?? '';
$email = trim((string)($_POST['email'] ?? ''));

// Respons generik yang sama untuk semua kasus agar tidak membocorkan
// apakah suatu NPM/email terdaftar (mencegah enumerasi akun).
$genericResponse = [
    'status'  => 'ok',
    'message' => 'Jika NPM dan email cocok dengan data kami, instruksi reset password telah dikirim.'
];

if (!ekantin_valid_npm($npm) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode($genericResponse);
    exit;
}

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $pdo->prepare("SELECT email FROM akun WHERE NPM = ?");
    $stmt->execute([$npm]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && !empty($row['email']) && strcasecmp($row['email'], $email) === 0) {
        // Token acak 256-bit (32 byte), hanya hash SHA-256-nya yang disimpan.
        $token     = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $expiresAt = date('Y-m-d H:i:s', time() + EKANTIN_RESET_TOKEN_TTL);

        // Batalkan token lama yang belum dipakai agar hanya satu token aktif.
        $inv = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE npm = ? AND used = 0");
        $inv->execute([$npm]);

        $ins = $pdo->prepare("INSERT INTO password_resets (npm, token_hash, expires_at, ip_request) VALUES (?, ?, ?, ?)");
        $ins->execute([$npm, $tokenHash, $expiresAt, ekantin_client_ip()]);

        ekantin_log_event_pdo($pdo, 'password_reset_requested', $npm, 'Token reset password dibuat');

        // Pengiriman token melalui kanal terverifikasi (email).
        $resetLink = 'reset_password.html?token=' . urlencode($token);
        $subject   = 'Reset Password Kantin';
        $body      = "Gunakan tautan berikut untuk mengatur ulang password Anda (berlaku 15 menit):\r\n{$resetLink}\r\n\r\nAbaikan email ini jika Anda tidak meminta reset password.";
        $headers   = "Content-Type: text/plain; charset=UTF-8";
        @mail($email, $subject, $body, $headers);
    }
} catch (PDOException $e) {
    error_log('lupa_password.php PDOException: ' . $e->getMessage());
    // Tetap kembalikan respons generik agar tidak membocorkan detail internal.
}

echo json_encode($genericResponse);
