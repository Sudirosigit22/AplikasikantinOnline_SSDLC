<?php
/**
 * includes/security.php
 * -----------------------------------------------------------------------
 * Pustaka bantu keamanan bersama (shared security library) aplikasi
 * E-Kantin. Memusatkan mekanisme otorisasi sesi, rate limiting/lockout
 * login, pencatatan log keamanan (security_log), idempotency checkout,
 * dan kebijakan pembatalan pesanan, agar dapat dipakai ulang oleh
 * seluruh endpoint terkait.
 *
 * Mengimplementasikan bagian dari SR-02, SR-06, SR-07, SR-08, SR-09
 * (lihat Paper_SSDLC_Revisi_Implementasi, Bagian V).
 * -----------------------------------------------------------------------
 */

const EKANTIN_MAX_FAILED_LOGIN   = 5;      // SR-02: percobaan gagal beruntun
const EKANTIN_LOCKOUT_MINUTES    = 15;     // SR-02: durasi penguncian akun
const EKANTIN_RESET_TOKEN_TTL    = 900;    // SR-03: 15 menit (detik)
const EKANTIN_CANCEL_WINDOW_MIN  = 10;     // SR-07: batas waktu pembatalan
const EKANTIN_IDEMPOTENCY_WINDOW = 3;      // SR-05: jendela dedup (detik)

/**
 * SR-08: Memulai sesi PHP dengan konfigurasi cookie yang aman
 * (HttpOnly, SameSite, Secure bila koneksi HTTPS terdeteksi).
 * Aman dipanggil berkali-kali dalam satu request.
 */
function ekantin_secure_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
        (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
        (($_SERVER['SERVER_PORT'] ?? '') == 443)
    );

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

/** Mengambil NPM pengguna yang sedang login dari sesi server-side, atau null. */
function ekantin_session_npm(): ?string
{
    ekantin_secure_session_start();
    return $_SESSION['npm'] ?? null;
}

/** Menetapkan sesi login setelah kredensial berhasil diverifikasi. */
function ekantin_set_session(string $npm, string $nama, string $kelas): void
{
    ekantin_secure_session_start();
    session_regenerate_id(true); // mencegah session fixation
    $_SESSION['npm']   = $npm;
    $_SESSION['nama']  = $nama;
    $_SESSION['kelas'] = $kelas;
    $_SESSION['login_at'] = time();
}

/** Menghapus sesi login (logout). */
function ekantin_destroy_session(): void
{
    ekantin_secure_session_start();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

/** Validasi format NPM/username (alfanumerik + underscore). */
function ekantin_valid_npm(?string $npm): bool
{
    return is_string($npm) && $npm !== '' && preg_match('/^[a-zA-Z0-9_]+$/', $npm) === 1;
}

/** Alamat IP klien (dukung reverse proxy sederhana). */
function ekantin_client_ip(): string
{
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '-';
}

/* ------------------------------------------------------------------ *
 * SR-09: Security logging & monitoring
 * ------------------------------------------------------------------ */

/** Mencatat event keamanan menggunakan koneksi mysqli. */
function ekantin_log_event_mysqli(mysqli $conn, string $eventType, ?string $npm, string $detail = ''): void
{
    $stmt = $conn->prepare("INSERT INTO security_log (event_type, npm, ip_address, detail) VALUES (?, ?, ?, ?)");
    if (!$stmt) {
        return; // logging tidak boleh menggagalkan alur utama
    }
    $ip = ekantin_client_ip();
    $stmt->bind_param('ssss', $eventType, $npm, $ip, $detail);
    $stmt->execute();
    $stmt->close();
}

/** Mencatat event keamanan menggunakan koneksi PDO. */
function ekantin_log_event_pdo(PDO $pdo, string $eventType, ?string $npm, string $detail = ''): void
{
    try {
        $stmt = $pdo->prepare("INSERT INTO security_log (event_type, npm, ip_address, detail) VALUES (?, ?, ?, ?)");
        $stmt->execute([$eventType, $npm, ekantin_client_ip(), $detail]);
    } catch (PDOException $e) {
        // logging tidak boleh menggagalkan alur utama transaksi
    }
}

/* ------------------------------------------------------------------ *
 * SR-02: Rate limiting & account lockout pada login
 * ------------------------------------------------------------------ */

/**
 * Mengecek apakah akun sedang terkunci.
 * Mengembalikan jumlah detik tersisa penguncian, atau 0 jika tidak terkunci.
 */
function ekantin_lockout_remaining_seconds(mysqli $conn, string $npm): int
{
    $stmt = $conn->prepare("SELECT locked_until FROM akun WHERE NPM = ?");
    $stmt->bind_param('s', $npm);
    $stmt->execute();
    $stmt->bind_result($lockedUntil);
    if (!$stmt->fetch() || empty($lockedUntil)) {
        $stmt->close();
        return 0;
    }
    $stmt->close();

    $remaining = strtotime($lockedUntil) - time();
    return $remaining > 0 ? $remaining : 0;
}

/**
 * Mencatat satu percobaan login gagal. Mengunci akun selama
 * EKANTIN_LOCKOUT_MINUTES setelah EKANTIN_MAX_FAILED_LOGIN kegagalan beruntun.
 */
function ekantin_register_failed_login(mysqli $conn, string $npm): void
{
    $stmt = $conn->prepare("SELECT gagal_login FROM akun WHERE NPM = ?");
    $stmt->bind_param('s', $npm);
    $stmt->execute();
    $stmt->bind_result($gagal);
    $found = $stmt->fetch();
    $stmt->close();

    if (!$found) {
        return; // NPM tidak ditemukan, tidak ada counter untuk diperbarui
    }

    $gagal = (int)$gagal + 1;

    if ($gagal >= EKANTIN_MAX_FAILED_LOGIN) {
        $lockedUntil = date('Y-m-d H:i:s', time() + (EKANTIN_LOCKOUT_MINUTES * 60));
        $upd = $conn->prepare("UPDATE akun SET gagal_login = 0, locked_until = ? WHERE NPM = ?");
        $upd->bind_param('ss', $lockedUntil, $npm);
        $upd->execute();
        $upd->close();
        ekantin_log_event_mysqli($conn, 'account_lockout', $npm, "Akun dikunci {$lockedUntil} setelah {$gagal} percobaan gagal beruntun");
    } else {
        $upd = $conn->prepare("UPDATE akun SET gagal_login = ? WHERE NPM = ?");
        $upd->bind_param('is', $gagal, $npm);
        $upd->execute();
        $upd->close();
    }
}

/** Mereset counter percobaan gagal setelah login berhasil. */
function ekantin_reset_failed_login(mysqli $conn, string $npm): void
{
    $stmt = $conn->prepare("UPDATE akun SET gagal_login = 0, locked_until = NULL WHERE NPM = ?");
    $stmt->bind_param('s', $npm);
    $stmt->execute();
    $stmt->close();
}

/* ------------------------------------------------------------------ *
 * SR-05: Idempotency checkout / transaksi atomik
 * ------------------------------------------------------------------ */

/**
 * Menghitung hash idempotensi dari identitas pemesan + isi pesanan pada
 * jendela waktu singkat, sehingga dua request checkout yang identik yang
 * datang hampir bersamaan (race condition) akan menghasilkan hash yang
 * sama dan bentrok pada UNIQUE constraint di basis data.
 */
function ekantin_idempotency_hash(string $npm, string $itemsText, $total): string
{
    $bucket = (int) floor(time() / EKANTIN_IDEMPOTENCY_WINDOW);
    return hash('sha256', $npm . '|' . $itemsText . '|' . $total . '|' . $bucket);
}

/* ------------------------------------------------------------------ *
 * SR-07: Kebijakan pembatalan pesanan (status & batas waktu)
 * ------------------------------------------------------------------ */

/**
 * Menentukan apakah sebuah pesanan masih boleh dibatalkan berdasarkan
 * status saat ini dan batas waktu sejak pesanan dibuat.
 */
function ekantin_can_cancel_order(string $waktuDibuat, ?string $status): bool
{
    // Status yang menandakan pesanan sudah diproses tidak boleh dibatalkan lagi.
    $statusDiproses = ['diproses', 'diambil', 'selesai', 'batal', 'dibatalkan'];
    $statusNormalized = strtolower(trim((string) $status));

    if ($statusNormalized !== '' && in_array($statusNormalized, $statusDiproses, true)) {
        return false;
    }

    $dibuat = strtotime($waktuDibuat);
    if ($dibuat === false) {
        return false;
    }

    $batasDetik = EKANTIN_CANCEL_WINDOW_MIN * 60;
    return (time() - $dibuat) <= $batasDetik;
}
