Sebuah lingkungan laboratorium simulasi dibangun menggunakan satu segmen jaringan lokal yang sama (192.168.16.0/24) dengan koneksi kabel UTP yang terhubung ke Switch dan Router.
Target Server (192.168.16.5): Menjalankan sistem operasi Ubuntu Server di port Fa0/2 yang berfungsi sebagai server utama yang menyediakan layanan/aplikasi target.
Attacker Node (192.168.16.100): Menggunakan OS Kali Linux di port Fa0/1, bertindak sebagai pihak luar yang mencoba mencari celah keamanan dan melancarkan serangan ke Target Server.
Monitoring Node (192.168.16.200): Menggunakan Security Onion di port Fa0/3, bertindak sebagai tim pertahanan (Blue Team) yang memantau dan menganalisis seluruh lalu lintas data (traffic) di dalam Switch.
