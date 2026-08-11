<?php
require_once 'halaman/config.php'; 
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Koneksi gagal: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$resu = $conn->query("SELECT COUNT(*) as total FROM jadwal_etalase");
$rows = $resu->fetch_assoc();
$total = $rows['total'];

if ($total >= 20) {
    $pending = [];
    $res = $conn->query("SELECT * FROM jadwal_etalase WHERE status='pending' ORDER BY id ASC");
    while ($r = $res->fetch_assoc()) {
        $pending[] = $r;
    }
    $conn->query("TRUNCATE TABLE jadwal_etalase");
    if (!empty($pending)) {
        $stmt = $conn->prepare("INSERT INTO jadwal_etalase (tipe, waktu, status) VALUES (?, ?, ?)");
        foreach ($pending as $p) {
            $stmt->bind_param("sss", $p['tipe'], $p['waktu'], $p['status']);
            $stmt->execute();
        }
        $stmt->close();
    }
}

date_default_timezone_set('Asia/Jakarta');

$now = date("Y-m-d H:i:s"); 
$sql = "SELECT * FROM jadwal_etalase WHERE waktu <= '$now' AND status='pending' ORDER BY waktu ASC";
$result = $conn->query($sql);

while($row = $result->fetch_assoc()){
    if($row['tipe'] == 'buka'){
        $conn->query("UPDATE status_etalase SET status='buka' WHERE id=1");
    } else if($row['tipe'] == 'tutup'){
        $conn->query("UPDATE status_etalase SET status='tutup' WHERE id=1");
    }
    $conn->query("UPDATE jadwal_etalase SET status='done' WHERE id=".$row['id']);
}
