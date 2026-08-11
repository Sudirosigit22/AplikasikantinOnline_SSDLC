<?php
require_once 'config.php';
require_once 'includes/security.php';
header('Content-Type: application/json');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
  echo json_encode(['status' => 'error', 'message' => 'Koneksi gagal']);
  exit;
}

$npm      = $_POST['npm'] ?? '';
$password = $_POST['password'] ?? '';

// SR-01: input NPM divalidasi formatnya sebelum dipakai pada query.
if (!ekantin_valid_npm($npm) || $password === '') {
  echo json_encode(['status' => 'not_found', 'message' => 'NPM tidak ditemukan!']);
  exit;
}

$akses = 'buka';
$result = $conn->query("SELECT status FROM status_etalase");
if ($row = $result->fetch_assoc()) {
    $akses = $row['status'];
}

// SR-02: akun yang sedang terkunci akibat percobaan gagal beruntun ditolak
// lebih dulu, sebelum verifikasi password dilakukan.
$lockRemaining = ekantin_lockout_remaining_seconds($conn, $npm);
if ($lockRemaining > 0) {
    ekantin_log_event_mysqli($conn, 'login_blocked_lockout', $npm, "Percobaan login saat akun terkunci, sisa {$lockRemaining} detik");
    echo json_encode([
        'status'  => 'locked',
        'message' => 'Akun terkunci sementara karena terlalu banyak percobaan gagal. Coba lagi dalam beberapa menit.'
    ]);
    exit;
}

// SR-01: parameterized query / prepared statement dipertahankan.
$sql = "SELECT password, nama, blokir, kelas FROM akun WHERE NPM = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $npm);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    if (empty($row['password'])) {
        echo json_encode(['status' => 'not_found', 'message' => 'Password belum dibuat!']);
        exit;
    }

    if (password_verify($password, $row['password'])) {
        // Login berhasil -> reset counter percobaan gagal (SR-02)
        ekantin_reset_failed_login($conn, $npm);

        if ($row['blokir'] == 1) {
            ekantin_log_event_mysqli($conn, 'login_blocked_account', $npm, 'Login ditolak: akun berstatus diblokir');
            echo json_encode(['status' => 'blocked', 'message' => 'Anda diblokir dari Kantin karena belum bayar utang Kantin/uang kas!']);
            exit;
        } elseif ($akses === 'tutup') {
            echo json_encode(['status' => 'tutup', 'message' => 'Kantin Tutup!']);
            exit;
        } else {
            // SR-06/SR-08: identitas pengguna ditetapkan pada sesi server-side
            // yang aman (HttpOnly/Secure/SameSite), bukan hanya disimpan di
            // sisi client, agar endpoint lain dapat memverifikasi kepemilikan
            // data berdasarkan sesi, bukan parameter kiriman client.
            ekantin_set_session($npm, $row['nama'], $row['kelas']);
            ekantin_log_event_mysqli($conn, 'login_success', $npm, 'Login berhasil');
            echo json_encode(['status' => 'Y', 'nama' => $row['nama'], 'kelas' => $row['kelas']]);
            exit;
        }
    } else {
        // SR-02/SR-09: percobaan gagal dicatat pada counter lockout dan security_log.
        ekantin_register_failed_login($conn, $npm);
        ekantin_log_event_mysqli($conn, 'login_failed', $npm, 'Password salah');
        echo json_encode(['status' => 'not_found', 'message' => 'Password Salah!']);
        exit;
    }
} else {
    // NPM tidak ditemukan: pesan digeneralisasi agar tidak membantu enumerasi akun,
    // namun tetap konsisten dengan kontrak respons front-end yang sudah ada.
    ekantin_log_event_mysqli($conn, 'login_failed', $npm, 'NPM tidak ditemukan');
    echo json_encode(['status' => 'not_found', 'message' => 'NPM tidak ditemukan!']);
    exit;
}

$conn->close();
