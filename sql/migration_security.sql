-- =====================================================================
-- MIGRASI KEAMANAN - Aplikasi E-Kantin
-- Mendukung implementasi SR-01 s.d. SR-09 (Paper SSDLC - Attack Tree)
-- Jalankan skrip ini SEKALI pada basis data sebelum menggunakan versi
-- kode yang sudah diperbarui. Skrip ini HANYA menambah kolom/tabel baru
-- (ADD COLUMN / CREATE TABLE) dan tidak mengubah data maupun kolom yang
-- sudah ada, sehingga fitur dan struktur aplikasi eksisting tetap utuh.
-- =====================================================================

-- ---------------------------------------------------------------------
-- SR-02: Rate limiting & account lockout pada login
-- ---------------------------------------------------------------------
ALTER TABLE `akun`
  ADD COLUMN `gagal_login` INT NOT NULL DEFAULT 0 AFTER `blokir`,
  ADD COLUMN `locked_until` DATETIME NULL DEFAULT NULL AFTER `gagal_login`;

-- ---------------------------------------------------------------------
-- SR-03: Reset password (token acak, hash SHA-256, kedaluwarsa, single-use)
-- Kolom `email` ditambahkan sebagai kanal terverifikasi opsional untuk
-- pengiriman token. Jika akun tidak memiliki email terdaftar, permintaan
-- reset password akan ditolak agar token tidak pernah dikirim ke kanal
-- yang tidak terverifikasi kepemilikannya.
-- ---------------------------------------------------------------------
ALTER TABLE `akun`
  ADD COLUMN `email` VARCHAR(191) NULL DEFAULT NULL AFTER `nama`;

CREATE TABLE IF NOT EXISTS `password_resets` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `npm` VARCHAR(50) NOT NULL,
  `token_hash` CHAR(64) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `used` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_request` VARCHAR(45) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_token_hash` (`token_hash`),
  KEY `idx_npm` (`npm`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- SR-05: Idempotency / transaksi atomik untuk mencegah duplicate order
-- Kolom idempotency_hash dihitung di server dari (username + isi pesanan
-- + jendela waktu singkat) sehingga dua request checkout yang identik
-- yang datang paralel akan bentrok pada UNIQUE constraint ini, dan hanya
-- salah satu yang berhasil tersimpan.
-- ---------------------------------------------------------------------
ALTER TABLE `pesanan`
  ADD COLUMN `idempotency_hash` CHAR(64) NULL DEFAULT NULL AFTER `id`,
  ADD UNIQUE KEY `uniq_idempotency_hash` (`idempotency_hash`);

-- ---------------------------------------------------------------------
-- SR-09: Security logging & monitoring
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_log` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `waktu` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `event_type` VARCHAR(64) NOT NULL,
  `npm` VARCHAR(50) NULL DEFAULT NULL,
  `ip_address` VARCHAR(45) NULL DEFAULT NULL,
  `detail` VARCHAR(500) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_npm` (`npm`),
  KEY `idx_waktu` (`waktu`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------
-- Catatan: kolom `status` dan `waktu` pada tabel `pesanan` DIASUMSIKAN
-- sudah ada (dipakai oleh datakantin.php/checkout.php pada kode
-- eksisting) dan dipakai ulang oleh SR-07 (jendela waktu pembatalan)
-- tanpa perubahan skema tambahan.
-- ---------------------------------------------------------------------
