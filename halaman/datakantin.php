<?php
require_once 'config.php'; 

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) die("Koneksi gagal");

$data = $conn->query("SELECT * FROM pesanan ORDER BY waktu ASC");

$no = 1;
$hasData = false;

while($r = $data->fetch_assoc()):
  $hasData = true;
?>
<tr>
  <td><?= $no++ ?></td>
  <td><?= htmlspecialchars($r['nama']) ?></td>
  <td><?= htmlspecialchars($r['kelas']) ?></td>
  <td><?= htmlspecialchars($r['pesanan']) ?></td>
  <td><?= htmlspecialchars($r['pesan']) ?></td>
  <td>Rp <?= number_format($r['total'], 0, ',', '.') ?></td>
  <td><?= htmlspecialchars($r['pembayaran']) ?></td>
  <td><?= htmlspecialchars($r['status']) ?></td>
  <td><?= htmlspecialchars($r['status_kas']) ?></td>
</tr>
<?php endwhile; ?>

<?php if (!$hasData): ?>
<tr>
  <td colspan="9" class="no-data">Tidak ada data pesanan</td>
</tr>
<?php endif; ?>
