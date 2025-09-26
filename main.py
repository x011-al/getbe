import sys
import requests
import json
import time
import secrets
import logging
import os
import threading
import argparse
from datetime import datetime
from typing import Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Pustaka baru yang diperlukan
# pip install bit tqdm cryptography
import bit
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Konfigurasi Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('btc_scanner_upgraded.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- Konfigurasi Default (dapat di-override via CLI) ---
CONFIG = {
    'api_timeout': 15,
    'retry_delay': 5,
    'max_retries': 2,
    'results_dir': './scan_results_encrypted',
}

# --- Header HTTP ---
WEB_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json',
}

class SecureKeyManager:
    """Manager untuk handling private key yang aman dengan enkripsi nyata."""

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Mendapatkan kunci enkripsi dari password menggunakan PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_data(data: dict, password: str) -> str:
        """Enkripsi data JSON dengan password."""
        salt = os.urandom(16)
        key = SecureKeyManager._derive_key(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        return f"salt:{base64.b64encode(salt).decode()}|encrypted:{encrypted_data.decode()}"

    @staticmethod
    def save_found_key(private_key_wif: str, address: str, balance: int, password: str):
        """Simpan private key yang ditemukan dengan enkripsi yang kuat."""
        try:
            os.makedirs(CONFIG['results_dir'], exist_ok=True)
            
            data_to_encrypt = {
                'address': address,
                'private_key_wif': private_key_wif,
                'balance_satoshi': balance,
                'timestamp': datetime.now().isoformat()
            }
            
            encrypted_content = SecureKeyManager.encrypt_data(data_to_encrypt, password)
            
            filename = f"FOUND_{address}.enc"
            filepath = os.path.join(CONFIG['results_dir'], filename)
            
            with open(filepath, 'w') as f:
                f.write(encrypted_content)
            
            logger.critical(f"Kunci untuk alamat {address} DITEMUKAN dan DIENKRIPSI ke file: {filepath}")
            
        except Exception as e:
            logger.error(f"Gagal menyimpan dan mengenkripsi kunci: {e}")

class BlockchainAPI:
    """Handler API yang efisien dengan session pooling."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(WEB_HEADERS)
        
    def get_balance(self, address: str) -> Optional[int]:
        """
        Mengecek saldo menggunakan beberapa API secara berurutan.
        Mengembalikan total saldo dalam satoshi jika berhasil, None jika gagal.
        """
        # Daftar API (URL, parser_function)
        # Blockchain.info adalah yang paling andal untuk saldo tunggal.
        apis = [
            (f"https://blockchain.info/balance?active={address}", lambda data: data[address]['final_balance']),
            (f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance", lambda data: data['final_balance']),
            (f"https://blockstream.info/api/address/{address}", lambda data: data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']),
        ]

        for url, parser in apis:
            for attempt in range(CONFIG['max_retries']):
                try:
                    response = self.session.get(url, timeout=CONFIG['api_timeout'])
                    if response.status_code == 200:
                        data = response.json()
                        balance = parser(data)
                        return int(balance)
                    elif response.status_code == 429: # Rate limited
                        time.sleep(CONFIG['retry_delay'] * (attempt + 1))
                        continue
                except (requests.RequestException, json.JSONDecodeError, KeyError):
                    continue # Coba API berikutnya jika ada error
            # Jika satu API gagal setelah semua retry, coba API berikutnya.
        return None # Jika semua API gagal

class BitcoinScanner:
    """Scanner Bitcoin multithreaded yang efisien."""
    
    def __init__(self, password: str, max_workers: int, max_iterations: int):
        self.api = BlockchainAPI()
        self.password = password
        self.max_workers = max_workers
        self.max_iterations = max_iterations
        self.stats = {'scanned': 0, 'found': 0, 'api_errors': 0}
        self.lock = threading.Lock()

    def scan_worker(self) -> None:
        """
        Satu unit pekerjaan: buat kunci, cek saldo, simpan jika ditemukan.
        """
        # 1. Generate Kunci (menggunakan 'bit' yang lebih cepat)
        key = bit.Key()
        
        # 2. Cek saldo untuk kedua format alamat (compressed & uncompressed)
        addresses_to_check = [key.address, key.segwit_address] # compressed P2PKH dan P2WPKH
        
        for address in addresses_to_check:
            balance = self.api.get_balance(address)

            if balance is not None:
                if balance > 0:
                    with self.lock:
                        self.stats['found'] += 1
                    logger.critical(f"🎉 SALDO DITEMUKAN! Alamat: {address}, Saldo: {balance} satoshi")
                    SecureKeyManager.save_found_key(key.to_wif(), address, balance, self.password)
                break # Jika alamat pertama punya saldo, tidak perlu cek yang kedua
            else:
                with self.lock:
                    self.stats['api_errors'] += 1
                break # Jika API gagal, tidak perlu cek alamat lain dari key yang sama

    def run_scan(self):
        """Memulai proses pemindaian menggunakan thread pool."""
        logger.info(f"🚀 Memulai pemindaian dengan {self.max_workers} worker...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Membuat progress bar dengan tqdm
            with tqdm(total=self.max_iterations, desc="Mencari Alamat Bitcoin", unit=" kunci") as pbar:
                futures = {executor.submit(self.scan_worker) for _ in range(self.max_iterations)}
                
                for future in as_completed(futures):
                    try:
                        future.result()  # Menunggu worker selesai
                    except Exception as e:
                        logger.error(f"Error pada worker: {e}")
                    finally:
                        pbar.update(1) # Update progress bar setelah setiap pekerjaan selesai
                        with self.lock:
                           self.stats['scanned'] += 1
                           # Opsi: Update deskripsi progress bar secara dinamis
                           pbar.set_postfix(
                               found=self.stats['found'], 
                               errors=self.stats['api_errors'],
                               refresh=True
                           )

        logger.info("📊 Pemindaian selesai.")
        logger.info(f"Total Alamat Discan: {self.stats['scanned']}")
        logger.info(f"Total Dompet Ditemukan: {self.stats['found']}")
        logger.info(f"Total Kegagalan API: {self.stats['api_errors']}")

def main():
    """Fungsi utama untuk menjalankan scanner dari command line."""
    print("================================================")
    print("    🚀 Bitcoin Address Scanner v2.0 (Upgraded)   ")
    print("    - Multithreaded, Encrypted, Efficient -     ")
    print("================================================")
    print("\n⚠️  DISCLAIMER: Peluang menemukan dompet dengan saldo secara acak")
    print("   adalah SANGAT KECIL, mendekati nol secara astronomis.")
    print("   Skrip ini dibuat untuk tujuan edukasi dan eksperimental.\n")
    
    parser = argparse.ArgumentParser(description="Bitcoin Address Scanner yang Ditingkatkan.")
    parser.add_argument(
        '-w', '--workers', 
        type=int, 
        default=50, 
        help='Jumlah thread paralel untuk pemindaian (default: 50).'
    )
    parser.add_argument(
        '-n', '--iterations', 
        type=int, 
        default=100000, 
        help='Jumlah total kunci yang akan digenerate dan dicek (default: 100000).'
    )
    args = parser.parse_args()

    password = input("Masukkan password untuk ENKRIPSI file hasil temuan (PENTING!): ").strip()
    if not password:
        logger.error("Password tidak boleh kosong. Proses dibatalkan.")
        return
        
    confirm = input(
        f"\nAnda akan memulai pemindaian {args.iterations} kunci menggunakan {args.workers} worker."
        f"\nFile yang ditemukan akan disimpan di direktori '{CONFIG['results_dir']}'."
        f"\nLanjutkan? (y/n): "
    ).strip().lower()

    if confirm != 'y':
        print("Pemindaian dibatalkan.")
        return
    
    scanner = BitcoinScanner(password, args.workers, args.iterations)
    scanner.run_scan()

if __name__ == "__main__":
    main()
