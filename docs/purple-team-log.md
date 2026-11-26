# Purple Team Loop Log — Kelompok 16 (KABITA Smart Breeder)

* **Mata Kuliah:** TEK1314 – Keamanan Siber (Kelas TEK A)
* **Target Node:** Replika Backend IoT KABITA (Debian 13, ThingsBoard CE 3.8, PostgreSQL 18, Nginx 1.26.3)
* **Monitoring Node:** Security Onion (Suricata IDS / Zeek / Kibana)
* **Referensi:** `docs/redteam/attack_plan.md` & `docs/blueteam/hardening_checklist.md`

---

## Ringkasan Status Purple Team Loop

| No | Skenario Serangan | Tahap 1 (Serang) | Tahap 2 (Deteksi) | Tahap 3 (Analisis) | Tahap 4 (Respons) | Tahap 5 (Verifikasi) | Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | Brute Force (PostgreSQL & Login) | `[ ]` | `[ ]` | `[ ]` | `[x]` | `[ ]` | Progress |
| 2 | Sniffing Paket HTTP | `[ ]` | `[ ]` | `[ ]` | `[ ]` | `[ ]` | Progress |
| 3 | Exploitation Dashboard & API | `[x]` | `[ ]` | `[ ]` | `[x]` | `[ ]` | Progress |
| 4 | MQTT Unauthorized Access | `[ ]` | `[ ]` | `[ ]` | `[x]` | `[ ]` | Progress |
| 5 | Security Misconfiguration | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 6 | DDoS Resilience Testing | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |

---

## Skenario 1: Brute Force Testing (Target: PostgreSQL & Halaman Login)
*(Contoh Template Siap Isi oleh Red Team & Blue Team)*

* **Waktu Eksekusi:** `[YYYY-MM-DD HH:MM WIB]`
* **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
* **Target:** Halaman login web ThingsBoard & layanan PostgreSQL (dari konteks akun SSH non-privilege).
* **Tools & Perintah:** `[DIISI RED TEAM: misal Hydra / Python script / psql + wordlist yang digunakan]`
* **Hasil Awal:** `[DIISI RED TEAM: misal X percobaan login berjalan tanpa pemblokiran / berhasil atau gagal]`
* **Bukti:** `docs/redteam/evidence/s1_bruteforce_before.png`

### 2. Tahap Deteksi (Blue Team)
* **Sumber Log / Alert:** Security Onion (Suricata/Zeek), `/var/log/postgresql/`, `/var/log/nginx/error.log`.
* **Temuan:** `[DIISI BLUE TEAM: salin 2-3 baris ringkasan alert/log yang muncul beserta timestamp]`
* **Bukti:** `docs/blueteam/evidence/s1_bruteforce_alert.png`

### 3. Tahap Analisis (Purple Team)
* **Klasifikasi NIST:** Unauthorized Access Attempt.
* **Root Cause:** `[DIISI: misal belum ada pembatasan laju request pada endpoint login sebelum mitigasi / upaya koneksi lokal ke PostgreSQL]`

### 4. Tahap Respons & Mitigasi (Blue Team)
* Mengikat PostgreSQL khusus ke `127.0.0.1` dengan autentikasi `scram-sha-256` dan role `NOSUPERUSER` (`/etc/postgresql/18/main/pg_hba.conf`).
* Mengunci izin berkas konfigurasi & secrets ThingsBoard ke `750`/`640` (`/usr/share/thingsboard/conf/`).
* Menerapkan *Rate Limiting* pada Nginx (`/etc/nginx/conf.d/security_hardening.conf`).

### 5. Tahap Verifikasi (Red Team & Blue Team)
* **Uji Ulang:** Red Team menjalankan ulang perintah yang sama persis.
* **Hasil Akhir:** `[DIISI: misal request berlebih ditolak HTTP 503, koneksi PostgreSQL ditolak & tercatat di log]`
* **Bukti:** `docs/redteam/evidence/s1_bruteforce_after.png`

---

## Skenario 5: Security Misconfiguration (Nginx, HTTPS & Header)
*(Contoh Sudah Terisi Berdasarkan Data Hardening)*

* **Waktu Eksekusi:** `[YYYY-MM-DD HH:MM WIB]`
* **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
* **Target:** Reverse Proxy Nginx (`http://<IP_TARGET>`).
* **Tools & Perintah:** `curl -I http://<IP_TARGET>` dan pemindaian OWASP ZAP.
* **Hasil Awal:** Header respons menampilkan banner versi server (`Server: nginx/1.26.3`) dan tidak memiliki header keamanan standar OWASP.
* **Bukti:** `docs/redteam/evidence/s5_misconfig_before.png`

### 2. Tahap Deteksi (Blue Team)
* **Sumber Log / Alert:** Security Onion (alert pemindaian OWASP ZAP) & `/var/log/nginx/access.log`.
* **Temuan:** `[DIISI BLUE TEAM: catatan alert/log pemindaian dari IP Attacker]`

### 3. Tahap Analisis (Purple Team)
* **Klasifikasi NIST:** Reconnaissance / Misconfiguration (Dampak Fungsional: Rendah | Dampak Informasi: Sedang).
* **Root Cause:** Konfigurasi bawaan Nginx mengekspos versi perangkat lunak dan belum mengaktifkan header pertahanan terhadap Clickjacking/MIME-sniffing.

### 4. Tahap Respons & Mitigasi (Blue Team)
* Menonaktifkan banner versi (`server_tokens off`) pada `/etc/nginx/nginx.conf`.
* Menambahkan 5 header OWASP (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`) pada `/etc/nginx/conf.d/security_hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
* **Uji Ulang:** Menjalankan ulang `curl -I` ke target.
* **Hasil Akhir:** Banner tersamar menjadi `Server: nginx` dan seluruh 5 header keamanan OWASP tampil aktif pada respons HTTP.
* **Bukti:** `docs/blueteam/evidence/after_security_headers.png`

---

## Skenario 6: DDoS Resilience Testing (Availability)
*(Contoh Sudah Terisi Sebagian — Tinggal Tambah Metrik k6 Red Team)*

### 1. Tahap Serang (Red Team)
* **Target:** Endpoint Web Nginx & API ThingsBoard.
* **Tools & Perintah:** `k6` (`[DIISI RED TEAM: jumlah VU, durasi, RPS]`).
* **Hasil Awal:** `[DIISI RED TEAM: lonjakan beban memperlambat respons server sebelum mitigasi]`

### 2. Tahap Deteksi (Blue Team)
* **Sumber Log / Alert:** Security Onion & `/var/log/nginx/error.log`.
* **Temuan:** Muncul anomali lonjakan koneksi HTTP dan pesan `[error] limiting requests, excess: ... by zone "req_limit"`.

### 3. Tahap Analisis (Purple Team)
* **Klasifikasi NIST:** Denial of Service (DoS).
* **Root Cause:** Tidak adanya pembatasan laju permintaan (*rate limiting*) memungkinkan banjir request menguras worker Nginx.

### 4. Tahap Respons & Mitigasi (Blue Team)
* Menerapkan *Leaky-Bucket Rate Limiting* Nginx (`rate=10r/s`, `burst=20 nodelay`, `limit_conn 20`) pada `/etc/nginx/sites-available/default`.
* Mengaktifkan `net.ipv4.tcp_syncookies = 1` pada `/etc/sysctl.d/99-network-hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
* **Uji Ulang:** Pengiriman 40 request HTTP secara cepat.
* **Hasil Akhir:** **23 request lolos (`HTTP 200`)** dan **17 request berlebih diblokir otomatis (`HTTP 503`)**, layanan tetap stabil.
* **Bukti:** `docs/blueteam/evidence/after_rate_limiting.png`
