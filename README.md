# E-Kantin Secure

**Aplikasi Pemesanan Kantin Sekolah berbasis Web dengan Implementasi Keamanan SSDLC**

---

## 1. Perkenalan

**E-Kantin** adalah aplikasi web pemesanan makanan di kantin sekolah yang dirancang untuk memudahkan taruna melakukan pemesanan secara digital. Versi **Secure** ini merupakan hasil implementasi persyaratan keamanan (Security Requirements) yang diturunkan dari **Attack Tree** berdasarkan Use Case Diagram, mengikuti kerangka kerja **SSDLC (Secure Software Development Life Cycle)**.

Aplikasi ini mempertahankan seluruh fitur dan alur bisnis asli, sambil menambahkan lapisan kontrol keamanan di backend. Perubahan utama mencakup penghapusan backdoor autentikasi, penguatan sesi, rate limiting, validasi server-side, dan mekanisme logging keamanan.

Proyek ini cocok digunakan sebagai:
- Sistem pemesanan kantin di lingkungan sekolah/kampus
- Studi kasus implementasi keamanan web (SSDLC, Attack Tree, OWASP-related controls)
- Referensi praktis penerapan SR (Security Requirements) pada aplikasi PHP + MySQL

---

## 2. Fungsi Utama

E-Kantin memungkinkan pengguna (siswa) untuk:

1. **Mendaftar / Membuat Password** — Mengaktifkan akun menggunakan NPM yang sudah terdaftar di sistem.
2. **Login** — Mengakses aplikasi dengan NPM dan password.
3. **Melihat Etalase / Menu** — Melihat daftar produk yang tersedia (buka/tutup sesuai jadwal).
4. **Memesan Makanan** — Menambahkan item ke keranjang dan melakukan checkout.
5. **Melihat & Membatalkan Pesanan** — Melihat riwayat pesanan sendiri dan membatalkan dalam batas waktu tertentu.
6. **Lupa / Reset Password** — Meminta token reset password yang dikirim ke email terverifikasi.
7. **Manajemen Data Kantin (Admin)** — Halaman `datakantin` untuk mengelola data terkait kantin (di luar cakupan utama paper keamanan).

Sistem juga mendukung:
- Penjadwalan buka/tutup etalase secara otomatis (melalui `cron_etalase.php`)
- Pengecekan status akun (diblokir) dan status etalase

---

## 3. Fitur Aplikasi

### 3.1 Fitur Bisnis
| Fitur | Deskripsi |
|-------|-----------|
| Registrasi Password | Siswa dengan NPM terdaftar dapat membuat password pertama kali |
| Login / Logout | Autentikasi berbasis NPM + password (bcrypt) |
| Etalase Menu | Tampilan produk dengan status buka/tutup |
| Keranjang & Checkout | Pemesanan multi-item dengan metode pembayaran |
| Riwayat Pesanan | Melihat daftar pesanan milik sendiri |
| Pembatalan Pesanan | Dibatalkan dalam window waktu terbatas & status belum diproses |
| Lupa Password | Request token via email |
| Reset Password | Ganti password menggunakan token yang valid |
| Jadwal Etalase | Buka/tutup otomatis berdasarkan jadwal |
| Status Blokir | Akun yang memiliki utang dapat diblokir |

### 3.2 Fitur Keamanan (SR-01 s.d. SR-09)
| ID | Nama | Ringkasan |
|----|------|-----------|
| **SR-01** | Parameterized Query | Prepared statement + validasi format NPM |
| **SR-02** | Rate Limiting & Account Lockout | 5 kali gagal → kunci 15 menit |
| **SR-03** | Secure Password Reset | Token 256-bit, hash SHA-256, TTL 15 menit, single-use |
| **SR-04** | Server-side Price Recalculation | Harga dihitung ulang dari tabel `produk` |
| **SR-05** | Idempotency / Atomic Transaction | Hash + UNIQUE constraint mencegah duplicate order |
| **SR-06** | Object Ownership Authorization | Identitas diambil dari sesi server, bukan parameter client |
| **SR-07** | Validasi Status & Batas Waktu Pembatalan | Hanya ≤ 10 menit & status belum diproses |
| **SR-08** | TLS + Secure Session + Password Hashing | HTTPS, cookie Secure/HttpOnly/SameSite, bcrypt |
| **SR-09** | Security Logging & Monitoring | Tabel `security_log` untuk event penting |

---

## 4. Kegunaan

- **Bagi Siswa**: Memesan makanan kantin dengan cepat tanpa antri, melihat riwayat, dan mengatur password dengan aman.
- **Bagi Pengelola Kantin**: Mengelola menu, melihat pesanan, dan mengatur jadwal buka/tutup.
- **Bagi Pengembang / Peneliti**: Contoh nyata penerapan derivasi Attack Tree → Security Requirements → implementasi kode + migrasi database.
- **Bagi Pendidikan**: Materi praktikum keamanan aplikasi web, SSDLC, dan pengendalian kerentanan umum (SQL Injection, IDOR, brute-force, price manipulation, race condition, dll).

---

## 5. Kelebihan

1. **Keamanan Terintegrasi** — Seluruh SR diimplementasikan tanpa mengorbankan fitur bisnis.
2. **Backdoor Dihapus** — Master password / backdoor autentikasi yang sebelumnya ada telah dihapus total.
3. **Session Management Aman** — Cookie sesi dikonfigurasi dengan `HttpOnly`, `Secure` (jika HTTPS), dan `SameSite=Lax`. Session ID di-regenerate setelah login.
4. **Perlindungan terhadap Serangan Umum**:
   - SQL Injection → Prepared statements
   - Brute-force login → Rate limiting + lockout
   - IDOR / Privilege Escalation → Object ownership dari sesi
   - Price Tampering → Harga dihitung ulang di server
   - Duplicate Order / Race Condition → Idempotency hash + UNIQUE
   - Session Fixation → `session_regenerate_id(true)`
5. **Audit Trail** — Semua event penting dicatat di `security_log`.
6. **Kode Modular** — Logika keamanan dipusatkan di `includes/security.php` agar mudah dirawat dan digunakan ulang.
7. **Migrasi Database Non-Destruktif** — Hanya menambah kolom/tabel baru, tidak mengubah data eksisting.
8. **Loader Aman** — `loader.php` hanya mengizinkan daftar file HTML yang di-whitelist.

---

## 6. Struktur Proyek

```
aplikasi_E-kantin_secure/
├── app.html                    # Entry point aplikasi (SPA-like loader)
├── loader.php                  # Loader aman dengan whitelist halaman
├── cron_etalase.php            # Script cron untuk jadwal buka/tutup etalase
├── 403.html / 404.html / 500.html
├── IMPLEMENTASI_KEAMANAN.md    # Dokumentasi detail implementasi SR
├── README.md                   # File ini
│
├── sql/
│   └── migration_security.sql  # Migrasi database untuk fitur keamanan
│
└── halaman/
    ├── .htaccess               # Blok akses langsung ke .html dan .txt
    ├── config.php              # Konfigurasi database
    ├── includes/
    │   └── security.php        # Pustaka keamanan bersama (inti SR)
    │
    ├── login.html / login.php
    ├── register.html / register.php
    ├── lupa_password.html / lupa_password.php
    ├── reset_password.html / reset_password.php
    ├── etalase.html / etalase.php
    ├── checkout.html / checkout.php
    ├── pesanan.php             # Riwayat + pembatalan pesanan
    ├── datakantin.html / datakantin.php
    ├── cek_akses.php
    └── final.html
```

### Penjelasan Folder Penting

- **`halaman/includes/security.php`**  
  Inti keamanan: manajemen sesi aman, rate limiting, lockout, logging, idempotency hash, dan kebijakan pembatalan.

- **`sql/migration_security.sql`**  
  Menambah kolom `gagal_login`, `locked_until`, `email` pada tabel `akun`, kolom `idempotency_hash` pada `pesanan`, serta membuat tabel `password_resets` dan `security_log`.

- **`loader.php`**  
  Mencegah path traversal / arbitrary file inclusion dengan daftar file yang diizinkan.

---

## 7. Implementasi Keamanan yang Sudah Diterapkan

Dokumentasi lengkap terdapat di file **`IMPLEMENTASI_KEAMANAN.md`**. Ringkasan teknis:

### SR-01 — Parameterized Query & Validasi Input
- Semua query login/register menggunakan **prepared statements**.
- Format NPM divalidasi dengan regex `^[a-zA-Z0-9_]+$` sebelum digunakan.

### SR-02 — Rate Limiting & Account Lockout
- Setelah **5** percobaan login gagal beruntun, akun dikunci selama **15 menit**.
- Kolom `gagal_login` dan `locked_until` ditambahkan ke tabel `akun`.
- Event lockout dicatat di `security_log`.

### SR-03 — Secure Password Reset
- Token acak kuat (256-bit), disimpan sebagai **hash SHA-256**.
- TTL **15 menit**, **sekali pakai** (`used` flag).
- Hanya dikirim ke email yang sudah terdaftar di akun (mencegah token dikirim ke kanal tidak terverifikasi).

### SR-04 — Server-side Recalculation
- Pada `checkout.php`, harga setiap item **diambil ulang** dari tabel `produk`.
- Nilai harga yang dikirim client **diabaikan** sepenuhnya.

### SR-05 — Idempotency & Transaksi Atomik
- Hash idempotensi dihitung dari: `NPM + isi pesanan + jendela waktu singkat`.
- Disimpan di kolom `idempotency_hash` dengan **UNIQUE constraint**.
- Mencegah pesanan duplikat akibat double-submit atau race condition.

### SR-06 — Object Ownership Authorization
- Identitas pengguna **selalu diambil dari sesi server-side** (`ekantin_session_npm()`).
- Endpoint `checkout.php` dan `pesanan.php` menolak request tanpa sesi valid dan tidak mempercayai parameter `username`/`akun` dari client.

### SR-07 — Batas Waktu & Status Pembatalan
- Pesanan hanya dapat dibatalkan dalam **10 menit** sejak dibuat.
- Status yang sudah `diproses`, `diambil`, `selesai`, `batal`, atau `dibatalkan` tidak dapat dibatalkan lagi.

### SR-08 — TLS, Session Aman, & Password Hashing
- Password di-hash dengan `password_hash(..., PASSWORD_DEFAULT)` (bcrypt).
- Cookie sesi: `HttpOnly`, `Secure` (jika HTTPS terdeteksi), `SameSite=Lax`.
- `session_regenerate_id(true)` setelah login berhasil.
- `.htaccess` memblokir akses langsung ke file `.html` dan `.txt`.

### SR-09 — Security Logging
- Tabel `security_log` mencatat:
  - `login_success`, `login_failed`, `login_blocked_lockout`, `login_blocked_account`
  - `account_lockout`
  - `register_password_created`
  - Event checkout dan pembatalan
- Logging **tidak pernah** menggagalkan alur bisnis utama.

### Temuan Tambahan yang Diperbaiki
- **Backdoor autentikasi** (file `password2.txt` + logika master password di `login.php`) **telah dihapus total**.

---

## 8. Teknologi yang Digunakan

| Layer | Teknologi |
|-------|-----------|
| Frontend | HTML5, CSS3, JavaScript (vanilla) |
| Backend | PHP (mysqli + PDO) |
| Database | MySQL / MariaDB |
| Keamanan | bcrypt, SHA-256, prepared statements, session hardening |
| Lainnya | Cron job untuk jadwal etalase |

---

## 9. Keterbatasan & Catatan

- Verifikasi keamanan dilakukan melalui **code review statis** (sesuai paper). Belum mencakup DAST atau expert penetration testing.
- Fitur reset password hanya aktif untuk akun yang sudah memiliki email terdaftar.
- Modul manajemen menu & pelaporan admin (`datakantin`, `etalase` sisi admin) berada di luar cakupan paper keamanan sehingga tidak diubah.
- Pengiriman email masih menggunakan `mail()` PHP — disarankan diganti dengan library SMTP yang lebih andal di lingkungan produksi.
- Pastikan server mendukung HTTPS agar cookie `Secure` dan force-HTTPS berfungsi optimal.

---

## 10. Referensi

- Paper SSDLC — Framework Derivasi Attack Tree dari Use Case Diagram.
---

## 11. Lisensi & Kontribusi

Proyek ini dikembangkan untuk keperluan pendidikan dan implementasi keamanan aplikasi web.  
Silakan gunakan, pelajari, dan modifikasi sesuai kebutuhan, dengan tetap mempertahankan praktik keamanan yang telah diterapkan.

---

**E-Kantin Secure** — Memesan lebih mudah, dengan keamanan yang lebih kuat.
