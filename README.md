Google Dork Scanner adalah tool otomatis yang melakukan pencarian Google menggunakan puluhan dork khusus untuk menemukan:
File konfigurasi (.env, .json, .yml, .config)
File backup (.zip, .tar, .gz, .rar, .bak)
File database (.sql, .db, .mdb)
Credentials & password files (password.txt, credential.txt)
API Keys & Tokens
Log files
Index directory listing (index of /backup/, /config/, /database/)
SSH private keys
Cloud credentials (AWS, S3, API tokens)
Dokumen sensitif (confidential, financial, password)
Tool ini dibuat untuk membantu security researcher mengevaluasi data exposure pada domain yang diizinkan

EXAMPLE :

python3 gdork.py
╔══════════════════════════════════════════════════════════════╗
║                   GOOGLE DORK SCANNER                        ║
║               Sensitive File Discovery Tool                  ║
║                       Author: iyanji                         ║
║                                                              ║
║     Find exposed sensitive files and data using Google       ║
╚══════════════════════════════════════════════════════════════╝  
Target : target.com
