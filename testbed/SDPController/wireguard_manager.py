#!/usr/bin/env python3

import json
import os
import subprocess
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import socket

class WireGuardManager:
    def __init__(self, config_file='server_config.json'):
        self.load_config(config_file)
        self.setup_crypto()
        self.wg_config_dir = '/etc/wireguard'
        self.client_ip_range = '10.0.0.0/24'
        self.dns_servers = ['8.8.8.8', '8.8.4.4']  # Google DNS

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

    def get_next_client_ip(self):
        """Get next available IP in the range"""
        # This is a simple implementation - in production, you'd want to track used IPs
        return '10.0.0.2'  # First client IP

    def create_wg_config(self, client_private_key, client_public_key, server_public_key, client_ip):
        """Create WireGuard configuration for client"""
        config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = {', '.join(self.dns_servers)}

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {self.config.get('server_ip', '127.0.0.1')}:{self.config.get('wg_port', 51820)}
PersistentKeepalive = 25
"""
        return config

    def encrypt_response(self, data):
        """Encrypt and sign the response data"""
        # Generate new IV for each response
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

    def process_spa_request(self, source_ip):
        """Process SPA request and generate WireGuard config"""
        try:
            # Generate new key pair for client
            client_private_key, client_public_key = self.generate_wg_keys()
            
            # Get server's public key
            server_public_key = subprocess.check_output(['wg', 'show', 'wg0', 'public-key']).decode().strip()
            
            # Get next available client IP
            client_ip = self.get_next_client_ip()
            
            # Create WireGuard config
            wg_config = self.create_wg_config(
                client_private_key,
                client_public_key,
                server_public_key,
                client_ip
            )
            
            # Prepare response data
            response_data = {
                'status': 'authorized',
                'wireguard_config': wg_config,
                'expires': 3600  # 1 hour
            }
            
            # Encrypt the response
            encrypted_response = self.encrypt_response(response_data)
            
            return encrypted_response
            
        except Exception as e:
            logging.error(f"Error generating WireGuard config: {str(e)}")
            return None

def main():
    # Example usage
    manager = WireGuardManager()
    response = manager.process_spa_request('192.168.1.100')
    if response:
        print("WireGuard config generated and encrypted")
    else:
        print("Failed to generate config")

if __name__ == "__main__":
    main() 