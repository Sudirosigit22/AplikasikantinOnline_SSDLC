<?php
require_once 'config.php';
require_once 'includes/security.php';

header('Content-Type: application/json');
date_default_timezone_set('Asia/Jakarta');

$data = json_decode(file_get_contents('php://input'), true);

if (!$data) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Data tidak valid']);
    exit;
}

// SR-06: identitas pemesan diambil dari sesi server-side (hasil login),
// bukan dari parameter "username"/"akun" yang dikirim client, sehingga
// pesanan tidak dapat dibuat atas nama pengguna lain.
$sessionNpm = ekantin_session_npm();
if (!$sessionNpm) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Sesi tidak valid. Silakan login kembali.']);
    exit;
}

$name    = trim((string)($data['name'] ?? ''));
$pesan   = trim((string)($data['pesan'] ?? ''));
$payment = (string)($data['paymentText'] ?? '');
$kelas   = (string)($data['kelas'] ?? '');
$items   = is_array($data['items'] ?? null) ? $data['items'] : [];

if ($name === '' || $payment === '' || empty($items)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Data pesanan tidak lengkap']);
    exit;
}

$host   = DB_HOST;
$dbname = DB_NAME;

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // SR-04: harga & jumlah setiap item dihitung ulang di sisi server
    // berdasarkan data menu pada basis data (tabel produk), nilai harga
    // yang dikirim client sama sekali diabaikan dalam perhitungan akhir.
    $stmtProduk = $pdo->prepare("SELECT price FROM produk WHERE name = ? AND tampilkan = 1");

    $itemsText  = '';
    $totalServer = 0;

    foreach ($items as $item) {
        $itemName = trim((string)($item['name'] ?? ''));
        $qty      = (int)($item['qty'] ?? 0);

        if ($itemName === '' || $qty <= 0 || $qty > 100) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Item pesanan tidak valid']);
            exit;
        }

        $stmtProduk->execute([$itemName]);
        $produk = $stmtProduk->fetch(PDO::FETCH_ASSOC);

        if (!$produk) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => "Produk tidak ditemukan/tidak tersedia: {$itemName}"]);
            exit;
        }

        $hargaServer = (int)$produk['price'];
        $totalServer += $hargaServer * $qty;
        $itemsText   .= $itemName . ' (x' . $qty . '); ';
    }

    $waktu = date('Y-m-d H:i:s');

    // SR-05: hash idempotensi dihitung di server dari identitas pemesan +
    // isi pesanan pada jendela waktu singkat, dikombinasikan dengan UNIQUE
    // constraint pada basis data dan transaksi atomik untuk mencegah
    // pesanan ganda (duplicate order) akibat request checkout paralel.
    $idempotencyHash = ekantin_idempotency_hash($sessionNpm, $itemsText, $totalServer);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("INSERT INTO pesanan (idempotency_hash, waktu, username, akun, nama, kelas, pesanan, pesan, total, pembayaran)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$idempotencyHash, $waktu, $sessionNpm, $_SESSION['nama'] ?? $sessionNpm, $name, $kelas, $itemsText, $pesan, $totalServer, $payment]);
        $pdo->commit();

        ekantin_log_event_pdo($pdo, 'checkout_success', $sessionNpm, "Total dihitung server: Rp{$totalServer}");
        echo json_encode(['status' => 'success', 'message' => 'Pesanan berhasil disimpan']);
    } catch (PDOException $e) {
        $pdo->rollBack();

        // Kode 23000 = pelanggaran UNIQUE constraint -> permintaan duplikat
        // (mis. race condition dari klik ganda/paralel) sudah pernah tersimpan.
        if ($e->getCode() === '23000') {
            ekantin_log_event_pdo($pdo, 'checkout_duplicate_blocked', $sessionNpm, 'Duplicate order ditolak oleh idempotency constraint');
            echo json_encode(['status' => 'success', 'message' => 'Pesanan berhasil disimpan']);
            exit;
        }

        throw $e;
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log('checkout.php PDOException: ' . $e->getMessage());
    if (isset($pdo)) {
        ekantin_log_event_pdo($pdo, 'checkout_error', $sessionNpm ?? null, 'Kesalahan sistem saat checkout');
    }
    echo json_encode(['status' => 'error', 'message' => 'Gagal menyimpan ke database']);
}
exit;
