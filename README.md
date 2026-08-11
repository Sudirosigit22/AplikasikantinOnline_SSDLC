# Implementasi Keamanan Aplikasi E-Kantin
## Framework Derivasi Attack Tree dari Use Case Diagram

Mengimplementasikan sembilan Security Requirement (SR-01
s.d. SR-09) hasil derivasi Attack Tree pada paper, ke dalam basis kode
aplikasi E-Kantin. **Tidak ada fitur, tampilan, atau alur bisnis yang
dihapus/diubah** — seluruh perubahan bersifat menambahkan kontrol keamanan
pada lapisan backend (dan penambahan 2 halaman baru: lupa/reset password,
yang memang merupakan fitur baru sesuai paper Bagian V.B, SR-03).

## 0. Temuan Tambahan: Backdoor Otentikasi (dihapus)

Ditemukan `halaman/password2.txt` berisi hash bcrypt "master password" yang
diverifikasi di `login.php` **sebelum** password asli, dan menerima NPM
mana pun (termasuk yang berstatus diblokir) — persis seperti temuan pada
Bagian V.C paper. Backdoor ini **sudah dihapus total** (kode maupun file
`password2.txt`-nya) pada `halaman/login.php` versi baru.

## 1. Ringkasan Implementasi per SR

| ID | Kebutuhan Keamanan | Implementasi | Berkas |
|---|---|---|---|
| SR-01 | Parameterized query pada form login/register | Dipertahankan + validasi format NPM sebelum query | `login.php`, `register.php` |
| SR-02 | Rate limiting & account lockout | 5x gagal beruntun -> kunci 15 menit (`gagal_login`, `locked_until`) | `login.php`, `includes/security.php` |
| SR-03 | Token reset password acak, hash, TTL, single-use | Token 256-bit, hash SHA-256, TTL 15 menit, sekali pakai, dikirim ke email terverifikasi | `lupa_password.php`, `reset_password.php` (+ halaman HTML baru) |
| SR-04 | Harga/jumlah dihitung ulang di server | Query ulang tabel `produk`, harga client diabaikan | `checkout.php` |
| SR-05 | Idempotency/transaksi atomik cegah duplicate order | Hash idempotensi server + UNIQUE constraint + transaksi atomik | `checkout.php`, `sql/migration_security.sql` |
| SR-06 | Object ownership authorization check | Identitas pemesan dari **sesi server-side**, bukan parameter client | `includes/security.php`, `checkout.php`, `pesanan.php` |
| SR-07 | Validasi status/batas waktu pembatalan | Hanya bisa dibatalkan dalam 10 menit & status belum diproses | `pesanan.php`, `includes/security.php` |
| SR-08 | TLS + hashing password | HTTPS dipaksa, cookie sesi Secure/HttpOnly/SameSite, bcrypt dipertahankan | `.htaccess`, `includes/security.php` |
| SR-09 | Logging & monitoring | Tabel `security_log`: login gagal/sukses, lockout, checkout, pembatalan | `includes/security.php` (dipanggil lintas modul) |

## 2. Langkah Deploy

1. **Backup database** sebelum migrasi.
2. Jalankan `sql/migration_security.sql` pada basis data (hanya
   menambah kolom/tabel baru, tidak mengubah data eksisting).
3. Upload seluruh isi folder aplikasi (menimpa berkas lama) — termasuk
   folder baru `halaman/includes/`.
4. Pastikan `halaman/password2.txt` **tidak ada lagi** di server produksi
   (hapus manual jika hosting tidak menimpa penghapusan file lama saat upload).
5. Isi kolom `akun.email` untuk pengguna yang ingin memakai fitur lupa
   password (opsional; tanpa email, permintaan reset akan ditolak secara
   aman, bukan gagal secara tidak terduga).
6. Verifikasi HTTPS aktif di hosting sebelum mengandalkan pemaksaan HTTPS
   pada `.htaccess` (baris redirect bisa menyebabkan redirect loop jika
   TLS belum terpasang di sisi hosting — nonaktifkan sementara bila perlu).
7. (Opsional, disarankan) konfigurasi SMTP asli untuk pengiriman email
   reset password; saat ini menggunakan `mail()` bawaan PHP sebagai
   referensi awal.

## 3. Keterbatasan yang Perlu Diketahui

- Verifikasi dilakukan melalui **code review statis** (konsisten dengan
  Bagian V.D paper), belum mencakup dynamic application security testing
  (DAST) maupun expert review.
- Kolom `email` bersifat opsional/baru sehingga fitur reset password hanya
  aktif untuk akun yang sudah mengisi email.
- Modul manajemen menu & pelaporan (`datakantin.php`, `etalase.php` sisi
  admin) berada di luar cakupan paper (Bagian I.C) sehingga tidak disentuh.
