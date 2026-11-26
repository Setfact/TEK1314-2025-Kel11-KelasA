# Purple Team Loop Log — Kelompok 16 (KABITA Smart Breeder)

- **Mata Kuliah:** TEK1314 – Keamanan Siber (Kelas TEK A)
- **Target Node:** Replika Backend IoT KABITA (Debian 13, ThingsBoard CE 3.8, PostgreSQL 18, Nginx 1.26.3)
- **Monitoring Node:** Security Onion (Suricata IDS / Zeek / Kibana)
- **Referensi:** `docs/redteam/attack_plan.md` & `docs/blueteam/hardening_checklist.md`

---

## Ringkasan Status Purple Team Loop

| No | Skenario Serangan | Tahap 1 (Serang) | Tahap 2 (Deteksi) | Tahap 3 (Analisis) | Tahap 4 (Respons) | Tahap 5 (Verifikasi) | Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | Brute Force (PostgreSQL & Login) | `[x]` | `[ ]` | `[x]` | `[x]` | `[x]` | Progress (Menunggu Log Blue Team) |
| 2 | Sniffing Paket HTTP | `[x]` | `[ ]` | `[x]` | `[x]` | `[ ]` | Progress (Menunggu Uji Ulang TLS) |
| 3 | Exploitation Dashboard & API | `[x]` | `[ ]` | `[x]` | `[x]` | `[ ]` | Progress (Menunggu Log & Verifikasi) |
| 4 | MQTT Unauthorized Access | `[x]` | `[ ]` | `[x]` | `[x]` | `[ ]` | Progress (Menunggu Log & Verifikasi) |
| 5 | Security Misconfiguration | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 6 | DDoS Resilience Testing | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |

---

## Skenario 1: Brute Force Testing (Target: PostgreSQL & Halaman Login)

- **Waktu Eksekusi:** `2026-11-26 03:17:49 – 03:17:52 WIB` (durasi ±3 detik)
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Endpoint REST API login ThingsBoard `POST /api/auth/login` (`http://10.10.100.184:8080`) dan layanan PostgreSQL (dari konteks akun SSH non-privilege).
- **Tools & Perintah:** Skrip bash (`brute_login.sh`) menggunakan loop `curl -X POST` dengan header `Content-Type: application/json` dan body `{"username":"...","password":"..."}` sebagai pengganti Hydra (modul `http-post-form` Hydra gagal mem-parsing body JSON karena tanda titik dua terbaca sebagai pemisah field). Pengujian menggunakan wordlist `wordlist_kecil.txt` berisi 8 kandidat password (`customer`, `password`, `123456`, `admin123`, `thingsboard`, `qwerty123`, `customer123`, `salahsatu`) terhadap akun `customer@thingsboard.org`.
- **Hasil Awal:** 8 percobaan login dijalankan dalam ±3 detik (`03:17:49–03:17:52`). Password default `customer` berhasil ditemukan pada percobaan pertama, sementara 7 percobaan gagal lainnya direspons kode HTTP `401` tanpa rate limiting, delay, maupun lockout.
- **Bukti:** `docs/redteam/evidence/s1_bruteforce_before.png` *(sesuaikan dengan nama file aktual di repositori)*

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Suricata/Zeek), `/var/log/postgresql/`, `/var/log/nginx/error.log`.
- **Temuan:** `[DIISI BLUE TEAM: salin 2-3 baris ringkasan alert/log yang muncul beserta timestamp]`
- **Bukti:** `docs/blueteam/evidence/s1_bruteforce_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Unauthorized Access Attempt.
- **Root Cause:** Masih aktifnya kredensial bawaan (*default password*) yang lemah pada akun `customer@thingsboard.org` (kata sandi `customer`), serta belum adanya mekanisme pembatasan laju permintaan (*rate limiting*), penundaan progresif, maupun *account lockout* pada endpoint `POST /api/auth/login` port 8080 sebelum mitigasi.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mengikat PostgreSQL khusus ke `127.0.0.1` dengan autentikasi `scram-sha-256` dan role `NOSUPERUSER` (`/etc/postgresql/18/main/pg_hba.conf`).
- Mengunci izin berkas konfigurasi & secrets ThingsBoard ke `750`/`640` (`/usr/share/thingsboard/conf/`).
- Menerapkan *Rate Limiting* pada Nginx (`/etc/nginx/conf.d/security_hardening.conf`).

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Red Team menjalankan ulang skrip `brute_login.sh` dengan wordlist yang sama persis.
- **Hasil Akhir:** Seluruh percobaan login mengalami gagal autentikasi (kredensial default telah diganti dan pembatasan laju request aktif).
- **Bukti:** `docs/redteam/evidence/s1_bruteforce_after.png`

---

## Skenario 2: Analisis Paket HTTP Tidak Terenkripsi (Sniffing)

- **Waktu Eksekusi:** `2026-11-26 15:38 WIB`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Trafik web monitoring ThingsBoard pada protokol HTTP (`http://10.10.100.184:8080`), khususnya endpoint `POST /api/auth/login` dan `GET /api/mobile/qr/deepLink`.
- **Tools & Perintah:** **Wireshark** (capture pada interface `eth0`) dengan *display filter* `ip.addr == 10.10.100.184` dan `http.request.method == "POST"`, serta fitur *Follow HTTP Stream*.
- **Hasil Awal:** Lalu lintas HTTP tertangkap secara terbuka (*plaintext/cleartext*). Paket `GET /api/mobile/qr/deepLink HTTP/1.1` beserta respons `HTTP/1.1 200 (text/plain)` terbaca utuh tanpa enkripsi, dan kredensial login serta token JWT dikirimkan secara terbuka di jaringan lokal.
- **Bukti:** `docs/redteam/evidence/wireshark sniffing_before_1.jpg`, `docs/redteam/evidence/wireshark sniffing_before_2.jpg`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Zeek `http.log` / Suricata).
- **Temuan:** `[DIISI BLUE TEAM: temuan paket HTTP plaintext pada Zeek http.log atau alert ARP spoofing jika dijalankan]`
- **Bukti:** `docs/blueteam/evidence/s2_http_sniffing_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Eavesdropping / Information Disclosure (Dampak Fungsional: Rendah | Dampak Informasi: Tinggi).
- **Root Cause:** Layanan web monitoring ThingsBoard masih menggunakan protokol HTTP (port 80/8080) tanpa enkripsi transport SSL/TLS (HTTPS), sehingga siapa pun di segmen jaringan lokal dapat membaca kredensial autentikasi dan payload telemetri dalam bentuk *cleartext*.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mengaktifkan enkripsi SSL/TLS (HTTPS port 443) pada Reverse Proxy Nginx serta pengalihan paksa HTTP (port 80) ke HTTPS (`/etc/nginx/sites-available/default`).

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Red Team melakukan penyadapan ulang menggunakan Wireshark saat aktivitas login dan akses dashboard berlangsung melalui HTTPS.
- **Hasil Akhir:** `[DIISI RED TEAM: trafik terenkripsi menggunakan protokol TLS, payload kredensial dan token tidak lagi terbaca plaintext]`
- **Bukti:** `docs/redteam/evidence/s2_sniffing_after.png`

---

## Skenario 3: Exploitation / Akses Dashboard & API

- **Waktu Eksekusi:** `2026-11-26` `[sesuaikan jam WIB]`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Antarmuka Dashboard & endpoint REST API ThingsBoard (`http://10.10.100.184:8080`), serta berkas konfigurasi/kompilator lokal dari akun SSH non-privilege.
- **Tools & Perintah:** Browser dan **OWASP ZAP** (inspeksi *Request/Response* HTTP, header autentikasi, dan endpoint API).
- **Hasil Awal:**
  - Kredensial default (`tenant@thingsboard.org` dan `customer@thingsboard.org`) masih aktif dan dapat digunakan untuk mengakses dashboard.
  - Lalu lintas berjalan di atas HTTP/1.1 tanpa TLS sehingga token JWT (`Bearer`) pada header `X-Authorization` terekspos secara terbuka (berisiko *Session Hijacking / Replay Attack*).
  - Header keamanan aplikasi web tidak terpasang pada port 8080 (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
  - Endpoint `/api/mobile/qr/deepLink` mengekspos struktur JSON internal dan parameter tautan registrasi (`https://thingsboard.cloud/api/noauth/qr?...`) pada *response body*.
  - Endpoint `/api/auth/login` tidak memiliki *rate limiting* maupun *account lockout*.
- **Bukti:** `docs/redteam/evidence/s3_exploitation_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Suricata/Kibana), `/var/log/nginx/access.log`, dan `auditd`.
- **Temuan:** `[DIISI BLUE TEAM: alert pemindaian OWASP ZAP pada Suricata/Kibana & log akses API]`
- **Bukti:** `docs/blueteam/evidence/s3_exploitation_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Web Application Attack / Access Control.
- **Root Cause:** Layanan web dan REST API ThingsBoard dijalankan menggunakan konfigurasi bawaan (*default*) pada port 8080 tanpa enkripsi SSL/TLS, tanpa header keamanan standar OWASP, tanpa pembatasan laju permintaan, serta masih menggunakan akun bawaan (`tenant@thingsboard.org` & `customer@thingsboard.org`).

### 4. Tahap Respons & Mitigasi (Blue Team)
- Restriksi izin berkas konfigurasi sensitif & secrets (`chmod 750`/`640`).
- Pembatasan kompilator biner `/usr/bin/gcc` dan `/usr/bin/make` ke mode `chmod 700` untuk mencegah kompilasi exploit lokal dari akun SSH non-privilege.
- Aktivasi pengawasan integritas file kritis via `auditd` (`/etc/audit/rules.d/hardening.rules`) dan pembaruan kredensial default.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Pengujian ulang login dengan kredensial default, akses API tanpa token sah, serta percobaan akses file secrets / eksekusi `gcc` dari akun SSH non-privilege.
- **Hasil Akhir:** `[DIISI RED TEAM: login kredensial default gagal, akses berkas sensitif dan kompilator gcc/make ditolak (Permission denied) serta tercatat di auditd]`
- **Bukti:** `docs/redteam/evidence/s3_exploitation_after.png`

---

## Skenario 4: Web/API/Protokol IoT - MQTT Unauthorized Access

- **Waktu Eksekusi:** `2026-11-26` `[sesuaikan jam WIB]`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Broker MQTT ThingsBoard (`10.10.100.184:1883`).
- **Tools & Perintah:** `mosquitto_sub` dan `mosquitto_pub` (paket `mosquitto-clients`) dari Kali Linux untuk menguji: (a) *subscribe* wildcard tanpa kredensial ke topic `#` dan `sensor/#`, (b) *publish* pesan uji ke topic `test/unauthorized`, dan (c) koneksi dengan kredensial acak (`username: asal`, `password: ngasal123`).
- **Hasil Awal:** Seluruh percobaan koneksi anonim maupun dengan kredensial sembarangan langsung ditolak oleh broker MQTT dengan kode `CONNACK 5 (Not Authorized)` / pesan `"Connection Refused: not authorised"`.
- **Bukti:** `docs/redteam/evidence/s4_mqtt_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** `/var/log/thingsboard/thingsboard.log` & Security Onion (Zeek logs).
- **Temuan:** `[DIISI BLUE TEAM: catatan penolakan autentikasi MQTT pada thingsboard.log & log Zeek]`
- **Bukti:** `docs/blueteam/evidence/s4_mqtt_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** IoT Protocol Abuse / Unauthorized Access.
- **Root Cause:** Broker MQTT ThingsBoard sejak awal telah mewajibkan autentikasi berbasis *Access Token* yang valid untuk seluruh klien (baik untuk *subscribe* maupun *publish*), sehingga tidak ditemukan celah *unauthorized access* tanpa kredensial.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mempertahankan dan menegakkan autentikasi berbasis *Access Token* unik per perangkat IoT di ThingsBoard.
- Membatasi akses port jaringan melalui UFW sehingga hanya mengizinkan port resmi (`1883/tcp`).

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Menjalankan ulang perintah `mosquitto_sub` dan `mosquitto_pub` tanpa token maupun dengan kredensial acak ke port `1883`.
- **Hasil Akhir:** `[DIISI RED TEAM: koneksi tanpa access token valid tetap ditolak broker dengan kode CONNACK 5 (Not Authorized)]`
- **Bukti:** `docs/redteam/evidence/s4_mqtt_after.png`

---

## Skenario 5: Security Misconfiguration (Nginx, HTTPS & Header)

- **Waktu Eksekusi:** `2026-11-26` `[sesuaikan jam WIB]`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Reverse Proxy Nginx (`http://10.10.100.184`) dan Dashboard ThingsBoard (`http://10.10.100.184:8080`).
- **Tools & Perintah:** `curl -I http://10.10.100.184` dan pemindaian otomatis **OWASP ZAP (Automated Scan)** ke `http://10.10.100.184:8080`.
- **Hasil Awal:** Header respons port 80 menampilkan banner versi server (`Server: nginx/1.26.3`) serta halaman bawaan `"Welcome to nginx!"`, HTTPS belum aktif (port 443 closed), dan dashboard port 8080 tidak memiliki header keamanan standar OWASP (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`).
- **Bukti:** `docs/redteam/evidence/s5_misconfig_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (alert pemindaian OWASP ZAP) & `/var/log/nginx/access.log`.
- **Temuan:** `[DIISI BLUE TEAM: catatan alert/log pemindaian dari IP Attacker]`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Reconnaissance / Misconfiguration (Dampak Fungsional: Rendah | Dampak Informasi: Sedang).
- **Root Cause:** Konfigurasi bawaan Nginx mengekspos versi perangkat lunak dan halaman default, serta belum mengaktifkan enkripsi HTTPS maupun header pertahanan terhadap *Clickjacking* dan *MIME-sniffing*.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Menonaktifkan banner versi (`server_tokens off`) pada `/etc/nginx/nginx.conf`.
- Menambahkan 5 header OWASP (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`) pada `/etc/nginx/conf.d/security_hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Menjalankan ulang `curl -I` ke target.
- **Hasil Akhir:** Banner tersamar menjadi `Server: nginx` dan seluruh 5 header keamanan OWASP tampil aktif pada respons HTTP.
- **Bukti:** `docs/blueteam/evidence/after_security_headers.png`

---

## Skenario 6: DDoS Resilience Testing (Availability)

- **Waktu Eksekusi:** `2026-11-26` `[sesuaikan jam WIB]`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Endpoint Web Nginx & API ThingsBoard (`10.10.100.184` port 80).
- **Tools & Perintah:**
  - Pengujian TCP SYN Flood menggunakan `hping3` ke IP `10.10.100.184` port 80 (`451.704 paket SYN` ditransmisikan).
  - Pengujian beban HTTP cepat sebanyak `40 request` secara beruntun dalam `0,3 detik`.
- **Hasil Awal:**
  - Pada uji `hping3` SYN Flood: dari `451.704 paket SYN` yang dikirim, `0 paket` diterima kembali (*100% packet loss*), mengindikasikan tumpukan koneksi SYN berkecepatan tinggi memicu *resource exhaustion* / pengabaian paket.
  - Pada uji beban 40 request HTTP: seluruh `40/40 request` mendapat status `HTTP 200` (rata-rata respons `160ms`, total eksekusi `0,3 detik`), `0` ditolak `HTTP 503`, dan `0` ditolak `HTTP 429` — menunjukkan belum adanya pembatasan laju trafik (*rate limiting*) sebelum mitigasi.
- **Bukti:** `docs/redteam/evidence/s6_ddos_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion & `/var/log/nginx/error.log`.
- **Temuan:** Muncul anomali lonjakan koneksi HTTP dan pesan `[error] limiting requests, excess: ... by zone "req_limit"`.

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Denial of Service (DoS) (Dampak Fungsional: Tinggi sebelum mitigasi / Rendah setelah mitigasi | Dampak Informasi: Tidak Ada).
- **Root Cause:** Tidak adanya pembatasan laju permintaan (*rate limiting*) dan proteksi *SYN Cookies* memungkinkan banjir request menguras worker Nginx dan menurunkan ketersediaan dashboard IoT.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Menerapkan *Leaky-Bucket Rate Limiting* Nginx (`rate=10r/s`, `burst=20 nodelay`, `limit_conn 20`) pada `/etc/nginx/sites-available/default`.
- Mengaktifkan `net.ipv4.tcp_syncookies = 1` pada `/etc/sysctl.d/99-network-hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Pengiriman 40 request HTTP secara cepat.
- **Hasil Akhir:** **23 request lolos (`HTTP 200`)** dan **17 request berlebih diblokir otomatis (`HTTP 503`)**, layanan tetap stabil.
- **Bukti:** `docs/blueteam/evidence/after_rate_limiting.png`
