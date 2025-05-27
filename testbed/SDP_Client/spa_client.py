#!/usr/bin/env python3

import json
import logging
import socket
import sys
import time
import os
import signal
import subprocess
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import threading

class SPAClient:
    def __init__(self, config_file='client_config.json'):
        self.load_config(config_file)
        self.setup_crypto()
        self.setup_logging()
        self.client_id = str(uuid.uuid4())  # Generate unique client ID
        self.wg_private_key = None
        self.wg_public_key = None
        self.keepalive_interval = 60  # Send keepalive every 60 seconds
        self.keepalive_thread = None
        self.running = True

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logging.error(f"Configuration file {config_file} not found")
            raise

    def setup_crypto(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'fwknop_salt',
            iterations=100000,
            backend=default_backend()
        )
        self.encryption_key = kdf.derive(self.config['encryption_key'].encode())
        self.hmac_key = self.config['hmac_key'].encode()

    def generate_wg_keys(self):
        """Generate new WireGuard key pair"""
        private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
        public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
        return private_key, public_key

    def create_wg_config(self, private_key, public_key, server_public_key, server_endpoint, client_ip):
        """Create WireGuard configuration"""
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {server_endpoint}
"""
        return config

    def save_wg_config(self, config):
        """Save WireGuard configuration to file"""
        try:
            os.makedirs('/etc/wireguard', exist_ok=True)
            with open('/etc/wireguard/wg0.conf', 'w') as f:
                f.write(config)
            logging.info("WireGuard configuration saved")
            return True
        except Exception as e:
            logging.error(f"Error saving WireGuard configuration: {str(e)}")
            return False

    def start_wg_interface(self):
        """Start the WireGuard interface"""
        try:
            subprocess.run(['wg-quick', 'up', 'wg0'], check=True)
            logging.info("WireGuard interface started")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error starting WireGuard interface: {str(e)}")
            return False

    def stop_wg_interface(self):
        """Stop the WireGuard interface"""
        try:
            subprocess.run(['wg-quick', 'down', 'wg0'], check=True)
            logging.info("WireGuard interface stopped")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error stopping WireGuard interface: {str(e)}")
            return False

    def start_keepalive(self):
        """Start sending keepalive packets"""
        def keepalive_sender():
            while self.running:
                try:
                    # Create keepalive packet
                    packet = {
                        'type': 'keepalive',
                        'client_id': self.client_id,
                        'timestamp': time.time()
                    }
                    
                    # Encrypt and send
                    encrypted = self.encrypt_packet(packet)
                    self.socket.sendto(encrypted, (self.config['server_ip'], self.config['server_port']))
                    
                    # Wait for response
                    try:
                        self.socket.settimeout(5)
                        data, addr = self.socket.recvfrom(4096)
                        response = self.decrypt_packet(data)
                        if response and response.get('status') == 'keepalive_ack':
                            logging.debug("Keepalive acknowledged")
                        else:
                            logging.warning("Invalid keepalive response")
                    except socket.timeout:
                        logging.warning("No response to keepalive")
                    
                except Exception as e:
                    logging.error(f"Error sending keepalive: {str(e)}")
                
                time.sleep(self.keepalive_interval)
        
        self.keepalive_thread = threading.Thread(target=keepalive_sender, daemon=True)
        self.keepalive_thread.start()

    def stop_keepalive(self):
        """Stop sending keepalive packets"""
        self.running = False
        if self.keepalive_thread:
            self.keepalive_thread.join()

    def encrypt_packet(self, data):
        """Encrypt and sign the packet data"""
        # Generate new IV for each packet
        iv = os.urandom(16)
        
        # Convert data to JSON and encode
        json_data = json.dumps(data).encode()
        
        # Calculate HMAC
        h = hmac.new(self.hmac_key, json_data, hashlib.sha256)
        hmac_digest = h.digest()
        
        # Combine data and HMAC
        combined_data = json_data + hmac_digest
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(combined_data) + padder.finalize()
        
        # Encrypt using AES-CBC
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        return iv + encrypted

    def decrypt_packet(self, encrypted_data):
        """Decrypt and verify the packet data"""
        try:
            # Extract IV and encrypted data
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Split data and HMAC
            data_len = len(data) - 32
            message = data[:data_len]
            hmac_digest = data[data_len:]
            
            # Verify HMAC
            h = hmac.new(self.hmac_key, message, hashlib.sha256)
            if not hmac.compare_digest(h.digest(), hmac_digest):
                logging.error("HMAC verification failed")
                return None
            
            return json.loads(message)
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            return None

    def send_spa_packet(self):
        """Send SPA packet and handle the response"""
        try:
            # Create SPA packet
            packet = {
                'type': 'spa',
                'source_ip': self.config['source_ip'],
                'target_port': self.config['target_port'],
                'protocol': self.config['protocol']
            }
            
            # Encrypt and send
            encrypted = self.encrypt_packet(packet)
            self.socket.sendto(encrypted, (self.config['server_ip'], self.config['server_port']))
            
            # Wait for response
            self.socket.settimeout(10)
            data, addr = self.socket.recvfrom(4096)
            response = self.decrypt_packet(data)
            
            if not response:
                logging.error("Invalid response from server")
                return False
            
            if response.get('status') != 'authorized':
                logging.error("SPA request not authorized")
                return False
            
            if response.get('type') != 'spa_verified':
                logging.error("Unexpected response type")
                return False
            
            # Generate WireGuard keys
            self.wg_private_key, self.wg_public_key = self.generate_wg_keys()
            
            # Send public key to server
            key_packet = {
                'type': 'wg_key',
                'client_id': self.client_id,
                'public_key': self.wg_public_key
            }
            
            encrypted = self.encrypt_packet(key_packet)
            self.socket.sendto(encrypted, (self.config['server_ip'], self.config['server_port']))
            
            # Wait for server response with gateway details
            data, addr = self.socket.recvfrom(4096)
            response = self.decrypt_packet(data)
            
            if not response or response.get('status') != 'authorized':
                logging.error("Failed to get gateway details")
                return False
            
            # Create and save WireGuard config
            wg_config = self.create_wg_config(
                self.wg_private_key,
                self.wg_public_key,
                response['server_public_key'],
                response['server_endpoint'],
                response['client_ip']
            )
            
            if not self.save_wg_config(wg_config):
                return False
            
            # Start WireGuard interface
            if not self.start_wg_interface():
                return False
            
            # Start sending keepalive packets
            self.start_keepalive()
            
            return True
            
        except Exception as e:
            logging.error(f"Error in SPA process: {str(e)}")
            return False

    def run(self):
        """Run the SPA client"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            if not self.send_spa_packet():
                return False
            
            # Keep the main thread running
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logging.info("Client stopped by user")
        finally:
            self.stop_keepalive()
            self.stop_wg_interface()
            self.socket.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SPA Client')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-c', '--config', default='client_config.json', help='Configuration file path')
    parser.add_argument('-A', '--target-port', type=int, help='Target port')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp'], help='Protocol')
    parser.add_argument('-S', '--source-ip', help='Source IP')
    parser.add_argument('-k', '--keepalive', type=int, help='Keepalive interval in seconds')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    client = SPAClient(args.config)
    
    # Override config with command line arguments
    if args.target_port:
        client.config['target_port'] = args.target_port
    if args.protocol:
        client.config['protocol'] = args.protocol
    if args.source_ip:
        client.config['source_ip'] = args.source_ip
    if args.keepalive:
        client.keepalive_interval = args.keepalive
    
    client.run()

if __name__ == "__main__":
    main() 