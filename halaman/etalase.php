<?php
require_once 'config.php'; 

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if($conn->connect_error) die("Koneksi gagal");

header('Content-Type: application/json');
$res = $conn->query("SELECT * FROM produk WHERE tampilkan = 1 ORDER BY FIELD(kategori, 'makanan', 'minuman', 'gorengan', 'lain-lain'), SUBSTRING_INDEX(name, ' ', 2), price ASC");


$produk = [];
while($row = $res->fetch_assoc()) {
  $produk[] = $row;
}
echo json_encode($produk);
