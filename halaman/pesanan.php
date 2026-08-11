<?php
require_once 'config.php';
require_once 'includes/security.php';
header('Content-Type: application/json');

// SR-06: identitas pemesan diambil dari sesi server-side, bukan dari
// parameter "user"/"username" yang dikirim client, sehingga endpoint ini
// tidak dapat digunakan untuk melihat atau membatalkan pesanan milik
// pengguna lain (mencegah Insecure Direct Object Reference).
$sessionNpm = ekantin_session_npm();
if (!$sessionNpm) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Sesi tidak valid. Silakan login kembali.']);
    exit;
}

$host   = DB_HOST;
$dbname = DB_NAME;

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Koneksi DB gagal']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $pdo->prepare("SELECT * FROM pesanan WHERE username = ? ORDER BY id DESC");
    $stmt->execute([$sessionNpm]);
    $pesanan = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($pesanan as &$p) {
        if (empty(trim($p['pesanan']))) {
            $p['pesanan'] = "-";
        }
    }

    echo json_encode($pesanan);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $id = $data['id'] ?? null;

    if (!$id) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Data tidak lengkap']);
        exit;
    }

    // Ambil pesanan berdasarkan id DAN kepemilikan (username = sesi), sekaligus
    // sebagai object ownership authorization check (SR-06).
    $stmt = $pdo->prepare("SELECT waktu, status FROM pesanan WHERE id = ? AND username = ?");
    $stmt->execute([$id, $sessionNpm]);
    $pesanan = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$pesanan) {
        ekantin_log_event_pdo($pdo, 'cancel_denied_ownership', $sessionNpm, "Percobaan membatalkan pesanan id={$id} yang bukan miliknya atau tidak ditemukan");
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Pesanan tidak ditemukan atau bukan milik Anda']);
        exit;
    }

    // SR-07: pembatalan divalidasi di sisi server terhadap status pesanan dan
    // batas waktu (10 menit sejak dibuat) untuk mencegah penyalahgunaan alur
    // bisnis, mis. membatalkan pesanan yang sudah diproses dapur.
    if (!ekantin_can_cancel_order($pesanan['waktu'], $pesanan['status'] ?? null)) {
        ekantin_log_event_pdo($pdo, 'cancel_denied_window', $sessionNpm, "Percobaan membatalkan pesanan id={$id} di luar kebijakan pembatalan");
        http_response_code(409);
        echo json_encode(['status' => 'error', 'message' => 'Pesanan tidak dapat dibatalkan lagi (sudah diproses atau melewati batas waktu 10 menit)']);
        exit;
    }

    $stmt = $pdo->prepare("DELETE FROM pesanan WHERE id = ? AND username = ?");
    $success = $stmt->execute([$id, $sessionNpm]);

    if ($success) {
        ekantin_log_event_pdo($pdo, 'cancel_success', $sessionNpm, "Pesanan id={$id} dibatalkan");
    }

    echo json_encode(['status' => $success ? 'success' : 'error']);
    exit;
}

echo json_encode(['status' => 'error', 'message' => 'Metode tidak didukung']);
exit;
