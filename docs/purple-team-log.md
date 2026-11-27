# Purple Team Loop Log — Kelompok 16 (KABITA Smart Breeder)

- **Mata Kuliah:** TEK1314 – Keamanan Siber (Kelas TEK A)
- **Target Node:** Replika Backend IoT KABITA (Debian 13, ThingsBoard CE 3.8, PostgreSQL 18, Nginx 1.26.3)
- **Monitoring Node:** Security Onion (Suricata IDS / Zeek / Kibana)
- **Referensi:** `docs/redteam/attack_plan.md` & `docs/blueteam/hardening_checklist.md`

---

## Ringkasan Status Purple Team Loop

| No | Skenario Serangan | Tahap 1 (Serang) | Tahap 2 (Deteksi) | Tahap 3 (Analisis) | Tahap 4 (Respons) | Tahap 5 (Verifikasi) | Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | Brute Force (PostgreSQL & Login) | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 2 | Sniffing Paket HTTP | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 3 | Exploitation Dashboard & API | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 4 | MQTT Unauthorized Access | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 5 | Security Misconfiguration | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** |
| 6 | DDoS Resilience Testing | `[x]` | `[x]` | `[x]` | `[x]` | `[x]` | **Selesai** (catatan: port 8080 ditutup via UFW) |

---

## Skenario 1: Brute Force Testing (Target: PostgreSQL & Halaman Login)

- **Waktu Eksekusi:** `2026-11-26 03:17:49 WIB` (serangan awal) dan `2026-11-26 19:03 WIB` (uji ulang)
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Endpoint REST API login ThingsBoard `POST /api/auth/login` (`http://10.10.100.184:8080`) dan layanan PostgreSQL (dari konteks akun SSH non-privilege).
- **Tools & Perintah:** Skrip bash (`brute_login.sh`) menggunakan loop `curl -X POST` dengan header `Content-Type: application/json` dan body `{"username":"...","password":"..."}` sebagai pengganti Hydra (modul `http-post-form` Hydra gagal mem-parsing body JSON karena tanda titik dua terbaca sebagai pemisah field). Pengujian menggunakan wordlist `wordlist_kecil.txt` berisi 8 kandidat password (`customer`, `password`, `123456`, `admin123`, `thingsboard`, `qwerty123`, `customer123`, `salahsatu`) terhadap akun `customer@thingsboard.org`.
- **Hasil Awal:** 8 percobaan login dijalankan dalam ±3 detik (`03:17:49–03:17:52`). Password default `customer` berhasil ditemukan pada percobaan pertama, sementara 7 percobaan gagal lainnya direspons kode HTTP `401` tanpa rate limiting, delay, maupun lockout.
- **Bukti:** `docs/redteam/evidence/brute force_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Suricata/Zeek), `/var/log/postgresql/`, `/var/log/nginx/error.log`.
- **Temuan:**
  - Pada kondisi awal, 8 request `POST /api/auth/login` beruntun ke port 8080 terekam sebagai lonjakan koneksi HTTP berulang dari satu sumber pada telemetri Security Onion (Zeek `http.log`/Suricata), tanggal `2026-11-26` pukul `03:17:49–03:17:52 WIB`. Port 8080 saat itu diakses langsung tanpa melalui Nginx sehingga tidak ada jejak di log Nginx.
  - PostgreSQL hanya mendengarkan pada `127.0.0.1` sehingga tidak dapat dijangkau langsung dari jaringan.
  - Setelah mitigasi, pola yang sama tercatat di `/var/log/nginx/error.log`: `[error] limiting requests, excess: 3.980 by zone "login_ratelimit"` untuk `POST /api/auth/login`.
- **Bukti:** `docs/blueteam/evidence/s1_bruteforce_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Unauthorized Access Attempt.
- **Root Cause:** Masih aktifnya kredensial bawaan (*default password*) yang lemah pada akun `customer@thingsboard.org` (kata sandi `customer`), serta belum adanya mekanisme pembatasan laju permintaan (*rate limiting*), penundaan progresif, maupun *account lockout* pada endpoint `POST /api/auth/login` port 8080 sebelum mitigasi.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mengikat PostgreSQL khusus ke `127.0.0.1` dengan autentikasi `scram-sha-256` dan role `NOSUPERUSER` (`/etc/postgresql/18/main/pg_hba.conf`).
- Mengunci izin berkas konfigurasi & secrets ThingsBoard ke `750`/`640` (`/usr/share/thingsboard/conf/`).
- Menerapkan *Rate Limiting* pada Nginx (`/etc/nginx/conf.d/security_hardening.conf`).
- Menerapkan *Leaky-Bucket Rate Limiting* khusus endpoint login (`rate=5r/m`, `burst=3 nodelay`, status `429`) pada `/etc/nginx/conf.d/rate_limit_auth.conf` dan `/etc/nginx/sites-available/default`.
- Mengaktifkan *account lockout* ThingsBoard (`SECURITY_USER_MAX_FAILED_LOGIN_ATTEMPTS=5`, `SECURITY_USER_LOCKOUT_DURATION_MS=600000`) pada `/usr/share/thingsboard/conf/thingsboard.conf`, serta mengganti kata sandi dan menonaktifkan akun bawaan pabrik.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Red Team menjalankan ulang skrip `brute_login.sh` dengan wordlist yang sama persis.
- **Hasil Akhir:** Pada uji ulang `2026-11-26 19:03 WIB`, seluruh 8 percobaan (termasuk `customer`) berstatus `[GAGAL]` (`HTTP 401`), artinya password default sudah tidak valid karena kredensial bawaan telah diganti. Skrip uji ulang masih menyasar `:8080` secara langsung (melewati Nginx), sehingga pembatasan laju belum teruji pada skrip tersebut; efeknya dibuktikan pada jalur HTTPS di baris berikut.
- **Verifikasi Blue Team (8 request beruntun melalui jalur HTTPS Nginx setelah remediasi Temuan B):** request #1–#4 diproses backend dengan `HTTP 401`, request #5–#8 langsung ditolak Nginx dengan `HTTP 429 Too Many Requests`.
- **Bukti:** `docs/redteam/evidence/brute force_after.png`

---

## Skenario 2: Analisis Paket HTTP Tidak Terenkripsi (Sniffing)

- **Waktu Eksekusi:** `2026-11-26 15:38 WIB`
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Trafik web monitoring ThingsBoard pada protokol HTTP (`http://10.10.100.184:8080`), khususnya endpoint `POST /api/auth/login` dan `GET /api/mobile/qr/deepLink`.
- **Tools & Perintah:** **Wireshark** (capture pada interface `eth0`) dengan *display filter* `ip.addr == 10.10.100.184` dan `http.request.method == "POST"`, serta fitur *Follow HTTP Stream*.
- **Hasil Awal:** Lalu lintas HTTP tertangkap secara terbuka (*plaintext/cleartext*). Paket `GET /api/mobile/qr/deepLink HTTP/1.1` beserta respons `HTTP/1.1 200 (text/plain)` terbaca utuh tanpa enkripsi, dan kredensial login serta token JWT dikirimkan secara terbuka di jaringan lokal.
- **Bukti:** `docs/redteam/evidence/wireshark sniffing_before_1.png`, `docs/redteam/evidence/wireshark sniffing_before_2.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Zeek `http.log` / Suricata).
- **Temuan:** Security Onion (Zeek `http.log`) mencatat `POST /api/auth/login` dan `GET /api/mobile/qr/deepLink` ke port 8080 sebagai lalu lintas HTTP tanpa enkripsi (tanpa TLS) antara klien Red Team dan Target Node, sehingga kredensial dan token JWT berada pada jalur *plaintext* yang dapat dibaca siapa pun di segmen jaringan yang sama.
- **Bukti:** `docs/blueteam/evidence/s2_http_sniffing_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Eavesdropping / Information Disclosure (Dampak Fungsional: Rendah | Dampak Informasi: Tinggi).
- **Root Cause:** Layanan web monitoring ThingsBoard masih menggunakan protokol HTTP (port 80/8080) tanpa enkripsi transport SSL/TLS (HTTPS), sehingga siapa pun di segmen jaringan lokal dapat membaca kredensial autentikasi dan payload telemetri dalam bentuk *cleartext*.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mengaktifkan enkripsi SSL/TLS (HTTPS port 443, TLS 1.2 dan TLS 1.3, sertifikat *self-signed* `ssl-cert-snakeoil`) pada Reverse Proxy Nginx serta pengalihan paksa HTTP (port 80) ke HTTPS dengan kode `301` (`/etc/nginx/sites-available/default`).
- Menghapus aturan `allow 8080/tcp` pada UFW sehingga ThingsBoard hanya dapat diakses Nginx melalui `127.0.0.1:8080`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Red Team melakukan penyadapan ulang menggunakan Wireshark saat aktivitas login dan akses dashboard berlangsung melalui HTTPS.
- **Hasil Akhir:** Trafik login dan dashboard kini melalui HTTPS port 443 sehingga payload kredensial dan token JWT terenkripsi TLS dan tidak lagi terbaca *plaintext*. Pada Wireshark, filter `http.request.method == "POST"` tidak lagi menghasilkan paket; yang tampak hanya `TLSv1.3` *Application Data*, dan fitur *Follow HTTP Stream* tidak tersedia.
- **Verifikasi Blue Team:** `openssl s_client -connect <target>:443 -tls1_3` menegosiasikan `TLSv1.3` dengan cipher `TLS_AES_256_GCM_SHA384` (`Verify return code: 18`, sertifikat *self-signed*), dan `Test-NetConnection -Port 8080` mengembalikan `TcpTestSucceeded : False`.
- **Bukti:** `docs/redteam/evidence/s2_sniffing_after.png`

---

## Skenario 3: Exploitation / Akses Dashboard & API

- **Waktu Eksekusi:** `2026-11-26 ±16:30 WIB` (perkiraan)
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
- **Bukti:** `docs/redteam/evidence/API and Auth_before_1.png` s.d. `docs/redteam/evidence/API and Auth_before_5.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (Suricata/Kibana), `/var/log/nginx/access.log`, dan `auditd`.
- **Temuan:** Pemindaian OWASP ZAP terlihat pada Security Onion (Zeek `http.log`/Suricata) sebagai rentetan request HTTP dalam jumlah besar ke berbagai path ThingsBoard port 8080, termasuk `/api/auth/login` dan `/api/mobile/qr/deepLink`. Karena port 8080 pada kondisi awal diakses langsung tanpa reverse proxy, aktivitas ini tidak tercatat di `/var/log/nginx/access.log`; setelah remediasi seluruh akses wajib melalui HTTPS port 443 sehingga setiap request tercatat di `access.log` dan lonjakan request ditandai pesan `limiting requests` di `error.log`. Pengawasan `auditd` aktif pada `/etc/ssh`, `/etc/shadow`, `/etc/passwd`, dan `/etc/ufw`.
- **Bukti:** `docs/blueteam/evidence/s3_exploitation_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Web Application Attack / Access Control.
- **Root Cause:** Layanan web dan REST API ThingsBoard dijalankan menggunakan konfigurasi bawaan (*default*) pada port 8080 tanpa enkripsi SSL/TLS, tanpa header keamanan standar OWASP, tanpa pembatasan laju permintaan, serta masih menggunakan akun bawaan (`tenant@thingsboard.org` & `customer@thingsboard.org`).

### 4. Tahap Respons & Mitigasi (Blue Team)
- Restriksi izin berkas konfigurasi sensitif & secrets (`chmod 750`/`640`).
- Pembatasan kompilator biner `/usr/bin/gcc` dan `/usr/bin/make` ke mode `chmod 700` untuk mencegah kompilasi exploit lokal dari akun SSH non-privilege.
- Aktivasi pengawasan integritas file kritis via `auditd` (`/etc/audit/rules.d/hardening.rules`) dan pembaruan kredensial default.
- Mengganti kata sandi dan menonaktifkan seluruh akun bawaan pabrik (`tenant`, `customer`, `sysadmin`), menutup port 8080 dari UFW, mengaktifkan *rate limiting* (`429`) dan *account lockout* pada login, serta menambahkan header `Strict-Transport-Security` dan `Content-Security-Policy` pada blok HTTPS Nginx.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Pengujian ulang login dengan kredensial default, akses API tanpa token sah, serta percobaan akses file secrets / eksekusi `gcc` dari akun SSH non-privilege.
- **Hasil Akhir:** Login dengan kredensial default gagal, serta akses berkas sensitif dan kompilator `gcc`/`make` dari akun non-privilege ditolak (`Permission denied`). Akses API tanpa token sah dijawab `HTTP 401 Unauthorized`.
- **Verifikasi Blue Team:** login akun default mengembalikan `HTTP 401 Unauthorized`; `sudo -u nobody head /etc/thingsboard/conf/thingsboard.conf` dan `sudo -u nobody gcc --version` sama-sama menghasilkan `Permission denied`; port 8080 `TcpTestSucceeded : False`.
- **Bukti:** `docs/redteam/evidence/s3_exploitation_after.png`

---

## Skenario 4: Web/API/Protokol IoT - MQTT Unauthorized Access

- **Waktu Eksekusi:** `2026-11-26 ±17:15 WIB` (perkiraan)
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Broker MQTT ThingsBoard (`10.10.100.184:1883`).
- **Tools & Perintah:** `mosquitto_sub` dan `mosquitto_pub` (paket `mosquitto-clients`) dari Kali Linux untuk menguji: (a) *subscribe* wildcard tanpa kredensial ke topic `#` dan `sensor/#`, (b) *publish* pesan uji ke topic `test/unauthorized`, dan (c) koneksi dengan kredensial acak (`username: asal`, `password: ngasal123`).
- **Hasil Awal:** Seluruh percobaan koneksi anonim maupun dengan kredensial sembarangan langsung ditolak oleh broker MQTT dengan kode `CONNACK 5 (Not Authorized)` / pesan `"Connection Refused: not authorised"`.
- **Bukti:** `docs/redteam/evidence/s4_mqtt_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** `/var/log/thingsboard/thingsboard.log` & Security Onion (Zeek logs).
- **Temuan:** Percobaan koneksi MQTT anonim dan berkredensial acak ke port `1883/tcp` terlihat pada Security Onion (Zeek `conn.log`) sebagai koneksi singkat tanpa sesi data, konsisten dengan penolakan broker `CONNACK 5 (Not Authorized)`; penolakan autentikasi dapat ditelusuri pada `/var/log/thingsboard/thingsboard.log`. Tidak ada pesan yang berhasil di-*publish* maupun di-*subscribe*. Baris `Transport Stats` pada `thingsboard.log` tidak menunjukkan sesi MQTT aktif yang tidak sah.
- **Bukti:** `docs/blueteam/evidence/s4_mqtt_alert.png`

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** IoT Protocol Abuse / Unauthorized Access.
- **Root Cause:** Broker MQTT ThingsBoard sejak awal telah mewajibkan autentikasi berbasis *Access Token* yang valid untuk seluruh klien (baik untuk *subscribe* maupun *publish*), sehingga tidak ditemukan celah *unauthorized access* tanpa kredensial.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Mempertahankan dan menegakkan autentikasi berbasis *Access Token* unik per perangkat IoT di ThingsBoard.
- Membatasi akses port jaringan melalui UFW sehingga hanya mengizinkan port resmi (`1883/tcp`).

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Menjalankan ulang perintah `mosquitto_sub` dan `mosquitto_pub` tanpa token maupun dengan kredensial acak ke port `1883`.
- **Hasil Akhir:** Seluruh percobaan tanpa *access token* valid maupun dengan kredensial acak tetap ditolak broker dengan kode `CONNACK 5 (Not Authorized)`; tidak ada pesan yang berhasil di-*publish* atau di-*subscribe*. Hasil ini konsisten karena autentikasi *Access Token* tidak diubah selama hardening dan perimeter UFW hanya meneruskan `1883/tcp`.
- **Bukti:** `docs/redteam/evidence/s4_mqtt_after.png`

---

## Skenario 5: Security Misconfiguration (Nginx, HTTPS & Header)

- **Waktu Eksekusi:** `2026-11-26 ±17:45 WIB` (perkiraan)
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Reverse Proxy Nginx (`http://10.10.100.184`) dan Dashboard ThingsBoard (`http://10.10.100.184:8080`).
- **Tools & Perintah:** `curl -I http://10.10.100.184` dan pemindaian otomatis **OWASP ZAP (Automated Scan)** ke `http://10.10.100.184:8080`.
- **Hasil Awal:** Header respons port 80 menampilkan banner versi server (`Server: nginx/1.26.3`) serta halaman bawaan `"Welcome to nginx!"`, HTTPS belum aktif (port 443 closed), dan dashboard port 8080 tidak memiliki header keamanan standar OWASP (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`). OWASP ZAP 2.17.0 (*Automated Scan*) melaporkan 5 alert: `Content Security Policy (CSP) Header Not Set` (2), `Missing Anti-clickjacking Header` (2), `Timestamp Disclosure - Unix`, `Information Disclosure - Suspicious Comments` (7), dan `Modern Web Application` (2).
- **Bukti:** `docs/redteam/evidence/Security misconfiguration_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion (alert pemindaian OWASP ZAP) & `/var/log/nginx/access.log`.
- **Temuan:** Pemindaian OWASP ZAP (*Automated Scan*) dan `curl -I` dari IP Attacker terlihat pada Security Onion sebagai rentetan request HTTP beruntun ke port 80 dan 8080. `/var/log/nginx/access.log` hanya merekam request ke port 80, karena port 8080 diakses langsung tanpa melalui Nginx.

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Reconnaissance / Misconfiguration (Dampak Fungsional: Rendah | Dampak Informasi: Sedang).
- **Root Cause:** Konfigurasi bawaan Nginx mengekspos versi perangkat lunak dan halaman default, serta belum mengaktifkan enkripsi HTTPS maupun header pertahanan terhadap *Clickjacking* dan *MIME-sniffing*.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Menonaktifkan banner versi (`server_tokens off`) pada `/etc/nginx/nginx.conf`.
- Menambahkan 5 header OWASP (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`) pada `/etc/nginx/conf.d/security_hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Menjalankan ulang `curl -I` ke target.
- **Hasil Akhir:** Banner tersamar menjadi `Server: nginx` dan seluruh 5 header keamanan OWASP tampil aktif pada respons HTTP.
- **Setelah remediasi Temuan A (HTTPS):** `curl -I http://<target>/` dijawab `HTTP/1.1 301 Moved Permanently` menuju HTTPS, dan respons HTTPS memuat 7 header (ditambah `Strict-Transport-Security` dan `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`).
- **Bukti:** `docs/blueteam/evidence/after_security_headers.png`

---

## Skenario 6: DDoS Resilience Testing (Availability)

- **Waktu Eksekusi:** `2026-11-26 19:15 WIB` (uji sebelum mitigasi) dan `2026-11-26 19:31 WIB` (uji ulang)
- **PIC:** Red Team (`Adiko / Rafiyuda`) & Blue Team (`Calvin`)

### 1. Tahap Serang (Red Team)
- **Target:** Endpoint Web Nginx & API ThingsBoard (`10.10.100.184` port 80).
- **Tools & Perintah:**
  - Pengujian TCP SYN Flood menggunakan `hping3` ke IP `10.10.100.184` port 80 (`451.704 paket SYN` ditransmisikan).
  - Pengujian beban HTTP cepat sebanyak `40 request` secara beruntun dalam `0,3 detik`.
  - Uji beban `k6` (2000 iterasi, hingga 1901 VU) langsung ke `http://10.10.100.184:8080`.
- **Hasil Awal:**
  - Pada uji `hping3` SYN Flood: dari `451.704 paket SYN` yang dikirim, `0 paket` diterima kembali (*100% packet loss*), mengindikasikan tumpukan koneksi SYN berkecepatan tinggi memicu *resource exhaustion* / pengabaian paket.
  - Pada uji beban 40 request HTTP: seluruh `40/40 request` mendapat status `HTTP 200` (rata-rata respons `160ms`, total eksekusi `0,3 detik`), `0` ditolak `HTTP 503`, dan `0` ditolak `HTTP 429` — menunjukkan belum adanya pembatasan laju trafik (*rate limiting*) sebelum mitigasi.
  - Pada uji `k6`: `http_req_failed` 76,55% (1531 dari 2000 request), `http_reqs` ±63,96 req/s, dan banyak pesan `dial: i/o timeout`.
- **Bukti:** `docs/redteam/evidence/ddos_before.png`

### 2. Tahap Deteksi (Blue Team)
- **Sumber Log / Alert:** Security Onion & `/var/log/nginx/error.log`.
- **Temuan:** Muncul anomali lonjakan koneksi HTTP pada Security Onion dan pesan `[error] limiting requests, excess: 20.190 by zone "req_limit"` pada `/var/log/nginx/error.log`.

### 3. Tahap Analisis (Purple Team)
- **Klasifikasi NIST:** Denial of Service (DoS) (Dampak Fungsional: Tinggi sebelum mitigasi / Rendah setelah mitigasi | Dampak Informasi: Tidak Ada).
- **Root Cause:** Tidak adanya pembatasan laju permintaan (*rate limiting*) dan proteksi *SYN Cookies* memungkinkan banjir request menguras worker Nginx dan menurunkan ketersediaan dashboard IoT.

### 4. Tahap Respons & Mitigasi (Blue Team)
- Menerapkan *Leaky-Bucket Rate Limiting* Nginx (`rate=10r/s`, `burst=20 nodelay`, `limit_conn 20`) pada `/etc/nginx/sites-available/default`.
- Mengaktifkan `net.ipv4.tcp_syncookies = 1` pada `/etc/sysctl.d/99-network-hardening.conf`.

### 5. Tahap Verifikasi (Red Team & Blue Team)
- **Uji Ulang:** Pengiriman 40 request HTTP secara cepat.
- **Hasil Akhir:** **23 request lolos (`HTTP 200`)** dan **17 request berlebih diblokir otomatis (`HTTP 503`)**, layanan tetap stabil.
- **Catatan Purple Team:** Uji `k6` ke port 8080 pada uji ulang (`19:31 WIB`) menghasilkan angka yang sama dengan uji awal (`19:15 WIB`, 76,55% gagal), sedangkan `htop` pada server mencatat satu *worker* Nginx pada ±100% CPU selama uji beban. Ini mengindikasikan beban pada port 8080 tidak banyak terpengaruh *rate limiting* Nginx, sehingga efektivitas mitigasi dibuktikan pada jalur Nginx (uji 40 request: 23 lolos / 17 `503`) dan port 8080 ditutup dari UFW pada remediasi Temuan A.
- **Bukti:** `docs/blueteam/evidence/after_rate_limiting.png`, `docs/redteam/evidence/ddos_after_1.png`, `docs/redteam/evidence/ddos_after_2.png`

---

## Catatan Purple Team Lintas Skenario

- **Dua fase remediasi:** Fase 1 (hardening dasar 18 kontrol) diuji ulang Red Team pada `2026-11-26` sore hari (brute force `19:03 WIB`, beban `19:31 WIB`). Setelah Laporan Temuan Red Team V2, Blue Team menjalankan Fase 2 (Lab 6): HTTPS port 443 dengan redirect `301`, 7 header OWASP, *rate limiting* login `5r/m` (`429`), *account lockout* (5 percobaan, 10 menit), penonaktifan akun bawaan, dan penutupan port 8080 pada UFW.
- **Pelajaran utama:** Port aplikasi yang terbuka langsung (8080) melewati seluruh kontrol Nginx (TLS, header, *rate limiting*), sehingga seluruh akses harus dipaksa melalui reverse proxy.
- **Rekomendasi lanjutan:** Migrasi MQTT ke MQTTS (port 8883) dengan sertifikat TLS, serta penggantian sertifikat *self-signed* dengan sertifikat valid (mis. Let's Encrypt) pada lingkungan produksi.
