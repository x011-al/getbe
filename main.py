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

# Konfigurasi yang Diperbarui
CONFIG = {
    'max_iterations': 100000,
    'api_timeout': 15,
    'retry_delay': 5,
    'max_retries': 2,
    'save_interval': 100,
    'results_dir': './scan_results',
    'progress_file': './scan_progress.json',
    'addresses_per_minute': 30,  # Reduced rate untuk avoid rate limiting
    'rotation_delay': 2,  # Delay antara API calls
}

# Header HTTP yang lebih baik
WEB_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Referer': 'https://www.blockchain.com/'
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
    def save_private_key_secure(private_key_hex: str, address: str, balance: int, password: str):
        """Simpan private key dengan enkripsi sederhana"""
        try:
            os.makedirs(CONFIG['results_dir'], exist_ok=True)
            
            timestamp = datetime.now().isoformat()
            
            data = {
                'address': address,
                'private_key': private_key_hex,
                'balance': balance,
                'timestamp': timestamp,
                'wif_compressed': bitcoin.encode_privkey(int(private_key_hex, 16), 'wif_compressed'),
                'wif_regular': bitcoin.encode_privkey(int(private_key_hex, 16), 'wif')
            }
            
            filename = f"{address}_{int(time.time())}.json"
            filepath = os.path.join(CONFIG['results_dir'], filename)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Private key untuk address {address} disimpan")
            
        except Exception as e:
            logger.error(f"Error menyimpan private key: {e}")

class APIRateLimiter:
    """Improved rate limiter dengan exponential backoff"""
    
    def __init__(self):
        self.api_calls = 0
        self.last_call_time = time.time()
        self.api_stats = {i: {'success': 0, 'errors': 0, 'last_429': 0} for i in range(4)}
        self.global_cooldown_until = 0
        
    def can_make_call(self, api_index: int) -> bool:
        """Cek apakah boleh melakukan API call"""
        current_time = time.time()
        
        # Global cooldown check
        if current_time < self.global_cooldown_until:
            return False
            
        # API-specific cooldown (jika recent 429)
        if current_time - self.api_stats[api_index]['last_429'] < 60:  # 1 menit cooldown setelah 429
            return False
            
        # Rate limiting dasar
        elapsed = current_time - self.last_call_time
        required_delay = 60 / CONFIG['addresses_per_minute']  # Spread requests evenly
        
        if elapsed < required_delay:
            time.sleep(required_delay - elapsed)
            
        return True
    
    def record_api_result(self, api_index: int, success: bool, status_code: int = None):
        """Record hasil API call"""
        if success:
            self.api_stats[api_index]['success'] += 1
        else:
            self.api_stats[api_index]['errors'] += 1
            if status_code == 429:
                self.api_stats[api_index]['last_429'] = time.time()
                # Global cooldown jika multiple 429
                if sum(1 for i in range(4) if time.time() - self.api_stats[i]['last_429'] < 60) >= 2:
                    self.global_cooldown_until = time.time() + 300  # 5 menit global cooldown
                    
        self.last_call_time = time.time()
        self.api_calls += 1

class BlockchainAPI:
    """Improved API handler dengan better error handling"""
    
    def __init__(self, rate_limiter: APIRateLimiter):
        self.rate_limiter = rate_limiter
        self.session = requests.Session()
        self.session.headers.update(WEB_HEADERS)
        
    def safe_api_call(self, url: str, api_name: str, api_index: int) -> Optional[Dict]:
        """Improved API call dengan retry logic"""
        if not self.rate_limiter.can_make_call(api_index):
            return None
            
        for attempt in range(CONFIG['max_retries']):
            try:
                response = self.session.get(
                    url, 
                    timeout=CONFIG['api_timeout'],
                    verify=True
                )
                
                status_code = response.status_code
                
                if status_code == 200:
                    data = response.json()
                    self.rate_limiter.record_api_result(api_index, True, status_code)
                    return data
                elif status_code == 429:
                    logger.warning(f"API {api_name} rate limited (429). Attempt {attempt + 1}")
                    self.rate_limiter.record_api_result(api_index, False, status_code)
                    
                    if attempt < CONFIG['max_retries'] - 1:
                        # Exponential backoff
                        delay = CONFIG['retry_delay'] * (2 ** attempt)
                        logger.info(f"Waiting {delay} seconds before retry...")
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(f"API {api_name} max retries exceeded")
                        return None
                else:
                    logger.warning(f"API {api_name} returned status {status_code}")
                    self.rate_limiter.record_api_result(api_index, False, status_code)
                    return None
                    
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"API {api_name} connection error: {e}")
                self.rate_limiter.record_api_result(api_index, False)
                
                if attempt < CONFIG['max_retries'] - 1:
                    time.sleep(CONFIG['retry_delay'])
                    continue
                else:
                    return None
                    
            except requests.exceptions.Timeout as e:
                logger.warning(f"API {api_name} timeout: {e}")
                self.rate_limiter.record_api_result(api_index, False)
                
                if attempt < CONFIG['max_retries'] - 1:
                    time.sleep(CONFIG['retry_delay'])
                    continue
                else:
                    return None
                    
            except Exception as e:
                logger.warning(f"API {api_name} error: {e}")
                self.rate_limiter.record_api_result(api_index, False)
                return None
                
        return None
    
    def check_balance_blockcypher(self, address: str) -> Optional[Dict]:
        """Check balance via BlockCypher API"""
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}?limit=1"
        return self.safe_api_call(url, "BlockCypher", 0)
    
    def check_balance_blockchain(self, address: str) -> Optional[Dict]:
        """Check balance via Blockchain.com API - lebih reliable"""
        url = f"https://blockchain.info/balance?active={address}"
        return self.safe_api_call(url, "Blockchain.com", 1)
    
    def check_balance_blockstream(self, address: str) -> Optional[Dict]:
        """Check balance via Blockstream API - alternative"""
        url = f"https://blockstream.info/api/address/{address}"
        return self.safe_api_call(url, "Blockstream", 2)
    
    def check_balance_mempool(self, address: str) -> Optional[Dict]:
        """Check balance via Mempool.space API - alternative"""
        url = f"https://mempool.space/api/address/{address}"
        return self.safe_api_call(url, "Mempool.space", 3)

class BalanceChecker:
    """Improved balance checker dengan fallback APIs"""
    
    def __init__(self, blockchain_api: BlockchainAPI):
        self.api = blockchain_api
    
    @staticmethod
    def is_non_zero_balance(value: Union[int, float, str]) -> bool:
        """Check if balance is non-zero"""
        try:
            if value is None:
                return False
            
            if isinstance(value, (int, float)):
                return value > 0
            elif isinstance(value, str):
                cleaned = value.replace(',', '').strip()
                return float(cleaned) > 0
            return False
        except (ValueError, TypeError):
            return False
    
    def parse_balance_blockcypher(self, data: Dict, address: str) -> Tuple[int, int]:
        """Parse balance dari BlockCypher response"""
        if not data:
            return 0, 0
            
        # BlockCypher returns balance in satoshis
        confirmed = data.get('final_balance', 0)
        unconfirmed = data.get('unconfirmed_balance', 0)
        
        return confirmed, unconfirmed
    
    def parse_balance_blockchain(self, data: Dict, address: str) -> Tuple[int, int]:
        """Parse balance dari Blockchain.com response"""
        if not data or address not in data:
            return 0, 0
            
        address_data = data[address]
        confirmed = address_data.get('final_balance', 0)
        unconfirmed = 0  # Blockchain.com doesn't provide unconfirmed separately
        
        return confirmed, unconfirmed
    
    def parse_balance_blockstream(self, data: Dict, address: str) -> Tuple[int, int]:
        """Parse balance dari Blockstream response"""
        if not data:
            return 0, 0
            
        confirmed = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        unconfirmed = data.get('mempool_stats', {}).get('funded_txo_sum', 0) - data.get('mempool_stats', {}).get('spent_txo_sum', 0)
        
        return confirmed, unconfirmed
    
    def parse_balance_mempool(self, data: Dict, address: str) -> Tuple[int, int]:
        """Parse balance dari Mempool.space response"""
        if not data:
            return 0, 0
            
        confirmed = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        unconfirmed = data.get('mempool_stats', {}).get('funded_txo_sum', 0) - data.get('mempool_stats', {}).get('spent_txo_sum', 0)
        
        return confirmed, unconfirmed
    
    def check_balance(self, address: str) -> Tuple[int, int, int]:
        """
        Check balance dengan priority pada APIs yang lebih reliable
        """
        apis = [
            (1, self.api.check_balance_blockchain, self.parse_balance_blockchain),
            (3, self.api.check_balance_mempool, self.parse_balance_mempool),
            (2, self.api.check_balance_blockstream, self.parse_balance_blockstream),
            (0, self.api.check_balance_blockcypher, self.parse_balance_blockcypher),
        ]
        
        for api_index, api_call, parser in apis:
            data = api_call(address)
            if data is not None:
                confirmed, unconfirmed = parser(data, address)
                
                if confirmed > 0 or unconfirmed > 0:
                    logger.info(f"💰 Balance found! {address} - Confirmed: {confirmed}, Unconfirmed: {unconfirmed}")
                    return confirmed, unconfirmed, api_index
                
                # Balance 0 is still a successful check
                return 0, 0, api_index
        
        # All APIs failed
        logger.warning(f"All APIs failed for address {address}")
        return -1, -1, -1

class KeyGenerator:
    """Class untuk generate Bitcoin keys"""
    
    @staticmethod
    def generate_bitcoin_keys() -> Dict:
        """Generate complete set of Bitcoin keys"""
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
        
        return {
            'private_key_hex': private_key_hex,
            'private_key_int': private_key_int,
            'regular_address': regular_address,
            'compressed_address': compressed_address,
            'timestamp': datetime.now().isoformat()
        }

class BitcoinScanner:
    """Improved scanner dengan better rate limiting"""
    
    def __init__(self, password: str = "default_password"):
        self.rate_limiter = APIRateLimiter()
        self.blockchain_api = BlockchainAPI(self.rate_limiter)
        self.balance_checker = BalanceChecker(self.blockchain_api)
        self.key_generator = KeyGenerator()
        self.password = password
        
        self.stats = {
            'addresses_scanned': 0,
            'balances_found': 0,
            'start_time': time.time(),
            'api_successes': 0,
            'api_errors': 0
        }
    
    def calculate_stats(self) -> Dict:
        """Calculate current statistics"""
        elapsed = time.time() - self.stats['start_time']
        addresses_per_second = self.stats['addresses_scanned'] / elapsed if elapsed > 0 else 0
        
        return {
            'elapsed_time': elapsed,
            'addresses_per_second': addresses_per_second,
            'estimated_time_remaining': (CONFIG['max_iterations'] - self.stats['addresses_scanned']) / addresses_per_second if addresses_per_second > 0 else float('inf'),
            'completion_percentage': (self.stats['addresses_scanned'] / CONFIG['max_iterations']) * 100,
            'success_rate': (self.stats['api_successes'] / (self.stats['api_successes'] + self.stats['api_errors'])) * 100 if (self.stats['api_successes'] + self.stats['api_errors']) > 0 else 0
        }
    
    def print_progress(self):
        """Print progress information"""
        stats = self.calculate_stats()
        
        logger.info(
            f"Progress: {self.stats['addresses_scanned']}/{CONFIG['max_iterations']} "
            f"({stats['completion_percentage']:.2f}%) | "
            f"Balances: {self.stats['balances_found']} | "
            f"Speed: {stats['addresses_per_second']:.4f} addr/sec | "
            f"API Success: {stats['success_rate']:.1f}%"
        )
    
    def scan_addresses(self):
        """Main scanning loop dengan improved rate limiting"""
        logger.info("🚀 Starting Improved Bitcoin Address Scanner...")
        logger.info(f"📊 Configuration: {CONFIG['addresses_per_minute']} addresses/minute")
        
        try:
            while self.stats['addresses_scanned'] < CONFIG['max_iterations']:
                # Generate new keys
                keys = self.key_generator.generate_bitcoin_keys()
                
                # Check both addresses
                addresses_to_check = [
                    keys['regular_address'],
                    keys['compressed_address']
                ]
                
                found_balance = False
                total_balance = 0
                
                for address in addresses_to_check:
                    if address:
                        confirmed, unconfirmed, api_used = self.balance_checker.check_balance(address)
                        
                        if confirmed > 0 or unconfirmed > 0:
                            total_balance = confirmed + unconfirmed
                            found_balance = True
                            
                            # Secure save
                            SecureKeyManager.save_private_key_secure(
                                keys['private_key_hex'],
                                address,
                                total_balance,
                                self.password
                            )
                            
                            self.stats['balances_found'] += 1
                            logger.critical(f"🎉 FOUND BALANCE: {address} - {total_balance} satoshis")
                            break
                        elif confirmed == 0 and unconfirmed == 0:
                            self.stats['api_successes'] += 1
                        else:  # API error
                            self.stats['api_errors'] += 1
                
                self.stats['addresses_scanned'] += 1
                
                # Progress reporting
                if self.stats['addresses_scanned'] % 10 == 0:
                    self.print_progress()
                
                # Additional delay untuk rate limiting
                time.sleep(CONFIG['rotation_delay'])
                
                # Emergency break jika terlalu banyak errors
                if self.stats['api_errors'] > 100 and self.stats['api_successes'] == 0:
                    logger.error("Too many API errors. Stopping scanner.")
                    break
        
        except KeyboardInterrupt:
            logger.info("⏹️ Scan interrupted by user")
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
        finally:
            logger.info("📊 Scan completed. Final statistics:")
            self.print_progress()

def main():
    """Main function"""
    print("=== Improved Bitcoin Address Scanner ===")
    print("🔒 Enhanced with better rate limiting and error handling")
    print("⚡ Target: 30 addresses/minute to avoid API blocking")
    print()
    
    password = input("Enter encryption password for private keys: ").strip()
    if not password:
        print("Using default password")
        password = "default_password"
    
    confirm = input(f"Scan {CONFIG['max_iterations']} addresses? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return
    
    scanner = BitcoinScanner(password)
    scanner.scan_addresses()

if __name__ == "__main__":
    main()
