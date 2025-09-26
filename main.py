import sys
import bitcoin
import requests
import json
import time
import random
import secrets
import logging
import hashlib
import hmac
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Union

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('btc_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Konfigurasi
CONFIG = {
    'max_iterations': 1000000,  # Safety limit
    'api_timeout': 10,
    'retry_delay': 2,
    'max_retries': 3,
    'save_interval': 1000,  # Simpan progress setiap 1000 alamat
    'results_dir': './scan_results',
    'progress_file': './scan_progress.json',
    'api_weights': [0.3, 0.25, 0.25, 0.2]  # Bobot untuk setiap API
}

# Header HTTP yang lebih realistis
WEB_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive'
}

class SecureKeyManager:
    """Manager untuk handling private key yang aman"""
    
    @staticmethod
    def generate_secure_private_key() -> Tuple[str, int]:
        """Generate private key yang benar-benar acak dan aman"""
        while True:
            # Generate 256-bit random number
            random_bytes = secrets.randbits(256)
            private_key_int = random_bytes % bitcoin.N
            
            if 1 <= private_key_int < bitcoin.N:
                private_key_hex = format(private_key_int, '064x')
                return private_key_hex, private_key_int
    
    @staticmethod
    def encrypt_private_key(private_key_hex: str, password: str) -> bytes:
        """Enkripsi private key dengan password"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        # Simple XOR encryption (dalam production gunakan library seperti cryptography)
        key_bytes = bytes.fromhex(private_key_hex)
        encrypted = bytes(a ^ b for a, b in zip(key_bytes, key.ljust(len(key_bytes), b'\0')))
        
        return salt + encrypted
    
    @staticmethod
    def save_private_key_secure(private_key_hex: str, address: str, balance: int, password: str):
        """Simpan private key dengan enkripsi"""
        try:
            os.makedirs(CONFIG['results_dir'], exist_ok=True)
            
            encrypted_key = SecureKeyManager.encrypt_private_key(private_key_hex, password)
            timestamp = datetime.now().isoformat()
            
            data = {
                'address': address,
                'private_key_encrypted': encrypted_key.hex(),
                'balance': balance,
                'timestamp': timestamp,
                'salt': encrypted_key[:32].hex()  # Salt adalah 32 byte pertama
            }
            
            filename = f"{address}_{int(time.time())}.secure"
            filepath = os.path.join(CONFIG['results_dir'], filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Private key untuk address {address} disimpan secara aman")
            
        except Exception as e:
            logger.error(f"Error menyimpan private key: {e}")

class APIRateLimiter:
    """Manager untuk rate limiting dan rotasi API"""
    
    def __init__(self):
        self.api_calls = 0
        self.last_call_time = time.time()
        self.api_stats = {i: {'success': 0, 'errors': 0} for i in range(4)}
        
    def should_make_call(self) -> bool:
        """Cek apakah boleh melakukan API call berikutnya"""
        current_time = time.time()
        elapsed = current_time - self.last_call_time
        
        # Rate limiting: maksimal 1 call per 0.5 detik
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)
        
        self.last_call_time = time.time()
        return True
    
    def record_api_result(self, api_index: int, success: bool):
        """Record hasil API call untuk load balancing"""
        if success:
            self.api_stats[api_index]['success'] += 1
        else:
            self.api_stats[api_index]['errors'] += 1
    
    def get_best_api(self) -> int:
        """Pilih API terbaik berdasarkan statistik"""
        scores = []
        for i in range(4):
            total_calls = self.api_stats[i]['success'] + self.api_stats[i]['errors']
            if total_calls == 0:
                success_rate = 1.0
            else:
                success_rate = self.api_stats[i]['success'] / total_calls
            
            # Gabungkan success rate dengan bobot konfigurasi
            score = success_rate * CONFIG['api_weights'][i]
            scores.append((score, i))
        
        # Pilih API dengan score tertinggi
        scores.sort(reverse=True)
        return scores[0][1]

class BlockchainAPI:
    """Class untuk handle semua API calls dengan error handling yang robust"""
    
    def __init__(self, rate_limiter: APIRateLimiter):
        self.rate_limiter = rate_limiter
    
    def safe_api_call(self, url: str, api_name: str, api_index: int) -> Optional[Dict]:
        """Wrapper untuk API call dengan error handling"""
        if not self.rate_limiter.should_make_call():
            return None
            
        try:
            response = requests.get(
                url, 
                timeout=CONFIG['api_timeout'],
                headers=WEB_HEADERS,
                verify=True  # Enable SSL verification
            )
            
            if response.status_code == 200:
                data = response.json()
                self.rate_limiter.record_api_result(api_index, True)
                return data
            else:
                logger.warning(f"API {api_name} returned status {response.status_code}")
                self.rate_limiter.record_api_result(api_index, False)
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"API {api_name} error: {e}")
            self.rate_limiter.record_api_result(api_index, False)
        except json.JSONDecodeError as e:
            logger.warning(f"API {api_name} JSON decode error: {e}")
            self.rate_limiter.record_api_result(api_index, False)
        
        return None
    
    def check_balance_blockcypher(self, address: str) -> Optional[Dict]:
        """Check balance via BlockCypher API"""
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}"
        return self.safe_api_call(url, "BlockCypher", 0)
    
    def check_balance_chain(self, address: str) -> Optional[Dict]:
        """Check balance via Chain API"""
        url = f"https://chain.api.btc.com/v3/address/{address}"
        return self.safe_api_call(url, "Chain", 1)
    
    def check_balance_blockchain(self, address: str) -> Optional[Dict]:
        """Check balance via Blockchain.com API"""
        url = f"https://blockchain.info/rawaddr/{address}"
        return self.safe_api_call(url, "Blockchain.com", 2)
    
    def check_balance_sochain(self, address: str) -> Optional[Dict]:
        """Check balance via SoChain API"""
        url = f"https://sochain.com/api/v2/get_address_balance/BTC/{address}"
        return self.safe_api_call(url, "SoChain", 3)

class BalanceChecker:
    """Class untuk mengecek balance dengan multiple fallback strategies"""
    
    def __init__(self, blockchain_api: BlockchainAPI):
        self.api = blockchain_api
    
    @staticmethod
    def is_non_zero_balance(value: Union[int, float, str]) -> bool:
        """Check if balance is non-zero dengan type handling yang robust"""
        try:
            if value is None:
                return False
            
            if isinstance(value, (int, float)):
                return value > 0
            elif isinstance(value, str):
                # Handle berbagai format string
                cleaned = value.replace(',', '').strip()
                return float(cleaned) > 0
            return False
        except (ValueError, TypeError):
            return False
    
    def parse_balance_blockcypher(self, data: Dict) -> Tuple[int, int]:
        """Parse balance dari BlockCypher response"""
        if not data:
            return 0, 0
            
        confirmed = data.get('final_balance', 0)
        unconfirmed = data.get('unconfirmed_balance', 0)
        
        return confirmed, unconfirmed
    
    def parse_balance_chain(self, data: Dict) -> Tuple[int, int]:
        """Parse balance dari Chain API response"""
        if not data or 'data' not in data:
            return 0, 0
            
        data = data['data']
        confirmed = data.get('balance', 0)
        unconfirmed = data.get('unconfirmed_balance', 0)
        
        return confirmed, unconfirmed
    
    def parse_balance_blockchain(self, data: Dict) -> Tuple[int, int]:
        """Parse balance dari Blockchain.com response"""
        if not data:
            return 0, 0
            
        confirmed = data.get('final_balance', 0)
        unconfirmed = 0  # Blockchain.com tidak provide unconfirmed secara explicit
        
        return confirmed, unconfirmed
    
    def parse_balance_sochain(self, data: Dict) -> Tuple[int, int]:
        """Parse balance dari SoChain response"""
        if not data or 'data' not in data:
            return 0, 0
            
        data = data['data']
        confirmed = float(data.get('confirmed_balance', 0)) * 100000000  # Convert to satoshi
        unconfirmed = float(data.get('unconfirmed_balance', 0)) * 100000000
        
        return int(confirmed), int(unconfirmed)
    
    def check_balance(self, address: str) -> Tuple[int, int, int]:
        """
        Check balance dengan multiple API fallback
        Returns: (confirmed_balance, unconfirmed_balance, api_used_index)
        """
        apis = [
            (0, self.api.check_balance_blockcypher, self.parse_balance_blockcypher),
            (1, self.api.check_balance_chain, self.parse_balance_chain),
            (2, self.api.check_balance_blockchain, self.parse_balance_blockchain),
            (3, self.api.check_balance_sochain, self.parse_balance_sochain)
        ]
        
        # Coba APIs berdasarkan priority
        for api_index, api_call, parser in apis:
            data = api_call(address)
            if data:
                confirmed, unconfirmed = parser(data)
                
                # Jika mendapatkan data valid, return
                if confirmed > 0 or unconfirmed > 0:
                    logger.info(f"Address {address} - Confirmed: {confirmed}, Unconfirmed: {unconfirmed}")
                    return confirmed, unconfirmed, api_index
                
                # Jika balance 0, tetap catat sebagai success
                return 0, 0, api_index
        
        # Semua APIs gagal
        logger.warning(f"All APIs failed for address {address}")
        return -1, -1, -1

class KeyGenerator:
    """Class untuk generate Bitcoin keys"""
    
    @staticmethod
    def generate_bitcoin_keys() -> Dict:
        """Generate complete set of Bitcoin keys"""
        # Generate secure private key
        private_key_hex, private_key_int = SecureKeyManager.generate_secure_private_key()
        
        # Generate public key
        public_key_point = bitcoin.fast_multiply(bitcoin.G, private_key_int)
        
        # Regular address
        regular_address = bitcoin.pubkey_to_address(public_key_point)
        
        # Compressed public key and address
        if public_key_point[1] % 2 == 0:
            compressed_prefix = '02'
        else:
            compressed_prefix = '03'
        
        compressed_public_key = compressed_prefix + format(public_key_point[0], '064x')
        compressed_address = bitcoin.pubkey_to_address(compressed_public_key)
        
        # WIF formats
        wif_regular = bitcoin.encode_privkey(private_key_int, 'wif')
        wif_compressed = bitcoin.encode_privkey(private_key_int, 'wif_compressed')
        
        return {
            'private_key_hex': private_key_hex,
            'private_key_int': private_key_int,
            'regular_address': regular_address,
            'compressed_address': compressed_address,
            'public_key_hex': bitcoin.encode_pubkey(public_key_point, 'hex'),
            'compressed_public_key': compressed_public_key,
            'wif_regular': wif_regular,
            'wif_compressed': wif_compressed,
            'timestamp': datetime.now().isoformat()
        }

class ProgressManager:
    """Manager untuk menyimpan dan memuat progress scan"""
    
    @staticmethod
    def load_progress() -> Dict:
        """Load progress dari file"""
        try:
            if os.path.exists(CONFIG['progress_file']):
                with open(CONFIG['progress_file'], 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading progress: {e}")
        
        return {
            'total_scanned': 0,
            'start_time': datetime.now().isoformat(),
            'addresses_with_balance': [],
            'last_save': 0
        }
    
    @staticmethod
    def save_progress(progress: Dict):
        """Simpan progress ke file"""
        try:
            progress['last_save'] = time.time()
            with open(CONFIG['progress_file'], 'w') as f:
                json.dump(progress, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving progress: {e}")

class BitcoinScanner:
    """Main class untuk scanning Bitcoin addresses"""
    
    def __init__(self, password: str = "default_password"):
        self.rate_limiter = APIRateLimiter()
        self.blockchain_api = BlockchainAPI(self.rate_limiter)
        self.balance_checker = BalanceChecker(self.blockchain_api)
        self.key_generator = KeyGenerator()
        self.progress = ProgressManager.load_progress()
        self.password = password
        
        # Stats
        self.stats = {
            'addresses_scanned': 0,
            'api_calls_made': 0,
            'balances_found': 0,
            'start_time': time.time()
        }
    
    def calculate_stats(self) -> Dict:
        """Calculate current statistics"""
        elapsed = time.time() - self.stats['start_time']
        addresses_per_second = self.stats['addresses_scanned'] / elapsed if elapsed > 0 else 0
        
        return {
            'elapsed_time': elapsed,
            'addresses_per_second': addresses_per_second,
            'estimated_time_remaining': (CONFIG['max_iterations'] - self.stats['addresses_scanned']) / addresses_per_second if addresses_per_second > 0 else float('inf'),
            'completion_percentage': (self.stats['addresses_scanned'] / CONFIG['max_iterations']) * 100
        }
    
    def print_progress(self):
        """Print progress information"""
        stats = self.calculate_stats()
        
        logger.info(
            f"Progress: {self.stats['addresses_scanned']}/{CONFIG['max_iterations']} "
            f"({stats['completion_percentage']:.2f}%) | "
            f"Balances found: {self.stats['balances_found']} | "
            f"Speed: {stats['addresses_per_second']:.2f} addr/sec"
        )
    
    def scan_addresses(self):
        """Main scanning loop"""
        logger.info("Starting Bitcoin address scanner...")
        
        try:
            while self.stats['addresses_scanned'] < CONFIG['max_iterations']:
                # Generate new keys
                keys = self.key_generator.generate_bitcoin_keys()
                
                # Check both regular and compressed addresses
                addresses_to_check = [
                    keys['regular_address'],
                    keys['compressed_address']
                ]
                
                found_balance = False
                total_balance = 0
                
                for address in addresses_to_check:
                    if address:  # Pastikan address valid
                        confirmed, unconfirmed, api_used = self.balance_checker.check_balance(address)
                        
                        if confirmed > 0 or unconfirmed > 0:
                            total_balance = confirmed + unconfirmed
                            found_balance = True
                            
                            # Simpan keys securely
                            SecureKeyManager.save_private_key_secure(
                                keys['private_key_hex'],
                                address,
                                total_balance,
                                self.password
                            )
                            
                            # Update progress
                            self.progress['addresses_with_balance'].append({
                                'address': address,
                                'balance': total_balance,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            self.stats['balances_found'] += 1
                            logger.critical(f"🚨 FOUND BALANCE: {address} - {total_balance} satoshis")
                            break
                
                self.stats['addresses_scanned'] += 1
                
                # Print progress periodically
                if self.stats['addresses_scanned'] % 100 == 0:
                    self.print_progress()
                
                # Save progress periodically
                if self.stats['addresses_scanned'] % CONFIG['save_interval'] == 0:
                    self.progress['total_scanned'] = self.stats['addresses_scanned']
                    ProgressManager.save_progress(self.progress)
                
                # Small delay to be respectful to APIs
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            # Save final progress
            self.progress['total_scanned'] = self.stats['addresses_scanned']
            self.progress['end_time'] = datetime.now().isoformat()
            ProgressManager.save_progress(self.progress)
            
            logger.info("Scan completed. Final statistics:")
            self.print_progress()

def main():
    """Main function"""
    print("=== Bitcoin Address Scanner ===")
    print("Warning: This is for educational purposes only!")
    print("The probability of finding a balance is extremely low.")
    print()
    
    # Minta password untuk encryption
    password = input("Enter encryption password for private keys: ").strip()
    if not password:
        print("Using default password (not recommended for production)")
        password = "default_password"
    
    # Konfirmasi
    confirm = input(f"Scan {CONFIG['max_iterations']} addresses? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return
    
    # Jalankan scanner
    scanner = BitcoinScanner(password)
    scanner.scan_addresses()

if __name__ == "__main__":
    main()
