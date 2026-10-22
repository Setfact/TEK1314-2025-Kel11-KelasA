| Tahap | Skenario | Teknik & Tools | Target Node | Hasil yang Diharapkan |
|---|---|---|---|---|
| 1 | MQTT Unauthorized Access | MQTT Explorer atau Mosquitto client | MQTT Broker | Memastikan broker menolak klien yang tidak memiliki izin dan mencatat aktivitas yang relevan. |
| 2 | Pengujian Login dan Kontrol Akses | Browser dan OWASP ZAP | Dashboard IoT | Mengidentifikasi kelemahan autentikasi atau otorisasi tanpa mengubah data produksi. |
| 3 | Analisis Paket Tidak Terenkripsi | Wireshark | Jalur komunikasi IoT | Mengidentifikasi apakah data komunikasi dapat dibaca tanpa perlindungan enkripsi. |
