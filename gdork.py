#!/usr/bin/env python3
"""
Google Dork Scanner for Sensitive Files and Data Exposure
Author: iyanji
Version: 1.0
"""

import requests
import time
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import re

class GoogleDorkScanner:
    def __init__(self):
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Daftar Google Dorks untuk file sensitif
        self.dorks = [
            # File Konfigurasi
            'site:{} filetype:env',
            'site:{} "DB_PASSWORD"',
            'site:{} "API_KEY"',
            'site:{} "config" ext:json',
            'site:{} "config" ext:yml',
            'site:{} "config" ext:yaml',
            'site:{} "configuration" ext:xml',
            
            # Database Files
            'site:{} filetype:sql',
            'site:{} "dump" ext:sql',
            'site:{} "backup" ext:sql',
            'site:{} filetype:db',
            'site:{} filetype:mdb',
            
            # Log Files
            'site:{} filetype:log',
            'site:{} "error.log"',
            'site:{} "access.log"',
            
            # Backup Files
            'site:{} "backup" ext:zip',
            'site:{} "backup" ext:tar',
            'site:{} "backup" ext:gz',
            'site:{} "backup" ext:bak',
            'site:{} "backup" ext:rar',
            
            # Source Code
            'site:{} filetype:git',
            'site:{} ".git" intitle:"index of"',
            'site:{} filetype:svn',
            
            # Credential Files
            'site:{} "password" ext:txt',
            'site:{} "username" ext:txt',
            'site:{} "login" ext:csv',
            'site:{} "credentials" ext:txt',
            
            # Admin Files
            'site:{} "admin" ext:php',
            'site:{} "admin" ext:asp',
            'site:{} "administrator"',
            'site:{} intitle:"admin"',
            
            # Sensitive Directories
            'site:{} intitle:"index of" "/.git/"',
            'site:{} intitle:"index of" "/backup/"',
            'site:{} intitle:"index of" "/config/"',
            'site:{} intitle:"index of" "/database/"',
            'site:{} intitle:"index of" "/sql/"',
            
            # API Keys & Tokens
            'site:{} "api_key"',
            'site:{} "secret_key"',
            'site:{} "access_token"',
            'site:{} "refresh_token"',
            
            # Email Lists
            'site:{} filetype:csv "email"',
            'site:{} "email" ext:xls',
            'site:{} "email" ext:xlsx',
            
            # Document Files
            'site:{} filetype:pdf "confidential"',
            'site:{} filetype:doc "password"',
            'site:{} filetype:xls "financial"',
            
            # SSH Keys
            'site:{} "BEGIN RSA PRIVATE KEY"',
            'site:{} "BEGIN PRIVATE KEY"',
            'site:{} "ssh-rsa"',
            
            # Cloud Credentials
            'site:{} "aws_access_key"',
            'site:{} "AKIA"',
            'site:{} "s3.amazonaws.com"',
            
            # Database Dumps
            'site:{} "phpMyAdmin" "sql"',
            'site:{} "MySQL dump"',
            'site:{} "Database dump"'
        ]

    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                   GOOGLE DORK SCANNER                       ║
║               Sensitive File Discovery Tool                 ║
║                       Author: iyanji                        ║
║                                                              ║
║     Find exposed sensitive files and data using Google      ║
╚══════════════════════════════════════════════════════════════╝
        """)

    def google_search(self, dork, max_results=50):
        """Melakukan pencarian Google dengan dork tertentu"""
        try:
            encoded_dork = urllib.parse.quote_plus(dork)
            url = f"https://www.google.com/search?q={encoded_dork}&num=100"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Ekstrak link dari hasil pencarian
            links = self.extract_links(response.text)
            return links[:max_results]
            
        except Exception as e:
            print(f"Error searching for {dork}: {e}")
            return []

    def extract_links(self, html):
        """Ekstrak link dari hasil HTML Google"""
        pattern = r'https?://[^&"\'<>\\\x7f-\xff]+'
        links = re.findall(pattern, html)
        
        # Filter hanya link yang valid
        filtered_links = []
        for link in links:
            if 'google.com' not in link and 'webcache' not in link:
                # Decode URL
                decoded_link = urllib.parse.unquote(link)
                filtered_links.append(decoded_link)
        
        return list(set(filtered_links))  # Remove duplicates

    def is_sensitive_file(self, url):
        """Deteksi apakah file termasuk sensitif berdasarkan ekstensi dan pattern"""
        sensitive_extensions = [
            '.env', '.sql', '.db', '.mdb', '.log', '.bak', 
            '.zip', '.tar', '.gz', '.rar', '.key', '.pem',
            '.ppk', '.csv', '.xls', '.xlsx', '.doc', '.docx',
            '.pdf', '.json', '.yml', '.yaml', '.xml', '.config'
        ]
        
        sensitive_patterns = [
            'config', 'backup', 'dump', 'password', 'credential',
            'admin', 'secret', 'key', 'database', 'sql', 'log',
            'private', 'ssh', 'aws', 'api'
        ]
        
        url_lower = url.lower()
        
        # Cek berdasarkan ekstensi file
        for ext in sensitive_extensions:
            if ext in url_lower:
                return True
        
        # Cek berdasarkan pattern dalam URL
        for pattern in sensitive_patterns:
            if pattern in url_lower:
                return True
        
        return False

    def scan_domain(self, domain, threads=5):
        """Scan domain menggunakan semua Google dorks"""
        print(f"\n[*] Starting scan for: {domain}")
        print(f"[*] Using {len(self.dorks)} dorks with {threads} threads")
        print("[*] This may take a while...\n")
        
        all_links = []
        
        def process_dork(dork):
            formatted_dork = dork.format(domain)
            print(f"[+] Searching: {formatted_dork}")
            
            links = self.google_search(formatted_dork)
            sensitive_links = [link for link in links if self.is_sensitive_file(link)]
            
            for link in sensitive_links:
                print(f"    FOUND: {link}")
                all_links.append(link)
            
            time.sleep(2)  # Delay untuk menghindari rate limiting
            return sensitive_links

        # Multi-threading untuk mempercepat proses
        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = list(executor.map(process_dork, self.dorks))
        
        # Flatten results dan remove duplicates
        all_links = list(set(all_links))
        
        return all_links

    def save_results(self, domain, links, format='txt'):
        """Save results ke file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{domain}_{timestamp}.{format}"
        
        if format == 'txt':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Google Dork Scan Results for: {domain}\n")
                f.write(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total sensitive files found: {len(links)}\n\n")
                
                for link in links:
                    f.write(f"{link}\n")
        
        elif format == 'json':
            data = {
                'domain': domain,
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(links),
                'sensitive_files': links
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        
        print(f"\n[+] Results saved to: {filename}")

def main():
    scanner = GoogleDorkScanner()
    scanner.banner()
    
    try:
        # Input target
        target = input("Target : ").strip()
        
        if not target:
            print("[-] Error: Target cannot be empty!")
            sys.exit(1)
        
        # Validasi domain
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            print("[-] Error: Invalid domain format!")
            sys.exit(1)
        
        # Langsung jalankan scan tanpa konfirmasi
        print(f"\n[*] Target set to: {target}")
        print("[*] Starting scan automatically...")
        
        # Jalankan scan
        start_time = time.time()
        sensitive_links = scanner.scan_domain(target, threads=5)
        end_time = time.time()
        
        # Tampilkan hasil
        print(f"\n" + "="*60)
        print("SCAN COMPLETED!")
        print("="*60)
        print(f"Domain: {target}")
        print(f"Scan duration: {end_time - start_time:.2f} seconds")
        print(f"Sensitive files found: {len(sensitive_links)}")
        print("="*60)
        
        if sensitive_links:
            print("\nSENSITIVE FILES FOUND:")
            print("-" * 60)
            for i, link in enumerate(sensitive_links, 1):
                print(f"{i:3d}. {link}")
            
            # Otomatis save results ke file
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{target}_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Google Dork Scan Results for: {target}\n")
                f.write(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total sensitive files found: {len(sensitive_links)}\n\n")
                for link in sensitive_links:
                    f.write(f"{link}\n")
            print(f"\n[+] Results automatically saved to: {filename}")
        else:
            print("\n[-] No sensitive files found!")
        
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user!")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
