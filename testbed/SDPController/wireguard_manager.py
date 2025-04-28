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
import time

class WireGuardManager:
    def __init__(self, config_file='server_config.json'):
        self.load_config(config_file)
        self.setup_crypto()
        self.gateway_ip = "10.0.3.2"         # Your gateway IP
        self.gateway_user = "ajay"           # Your gateway username
        self.setup_logging()

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

    def get_next_client_ip(self):
        """Get next available IP in the range"""
        # This is a simple implementation - in production, you'd want to track used IPs
        return '10.0.0.2'  # First client IP

    def create_wg_config(self, client_private_key, client_public_key, server_public_key, client_ip):
        """Create WireGuard configuration for client"""
        config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {self.config.get('server_ip', '127.0.0.1')}:{self.config.get('wg_port', 51820)}
PersistentKeepalive = 25
"""
        return config

    def update_gateway_config(self, client_public_key, client_ip):
        """Update WireGuard configuration on gateway"""
        try:
            # Create the peer configuration
            peer_config = f"""
[Peer]
PublicKey = {client_public_key}
AllowedIPs = {client_ip}/32
"""
            
            # SSH into gateway and update configuration
            ssh_command = f"""
# Create backup of current config
sudo cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak

# Check if peer already exists
if ! sudo grep -q "{client_public_key}" /etc/wireguard/wg0.conf; then
    # Append new peer configuration
    echo '{peer_config}' | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
    
    # Restart WireGuard interface
    sudo wg-quick down wg0
    sudo wg-quick up wg0
    
    # Log the update
    echo "$(date): Added new peer {client_ip} with public key {client_public_key}" | sudo tee -a /var/log/wireguard_updates.log
else
    echo "$(date): Peer {client_ip} already exists in configuration" | sudo tee -a /var/log/wireguard_updates.log
fi
"""
            
            # Execute SSH command
            result = subprocess.run(
                ['ssh', f'{self.gateway_user}@{self.gateway_ip}', ssh_command],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logging.info(f"Successfully updated gateway configuration for client {client_ip}")
                return True
            else:
                logging.error(f"Failed to update gateway configuration: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error updating gateway configuration: {str(e)}")
            return False

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
            logging.info(f"Processing SPA request from {source_ip}")
            
            # Generate new key pair for client
            client_private_key, client_public_key = self.generate_wg_keys()
            logging.info(f"Generated new key pair for client {source_ip}")
            
            # Get server's public key
            try:
                server_public_key = subprocess.check_output(['wg', 'show', 'wg0', 'public-key']).decode().strip()
                logging.info("Retrieved server's public key")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to get server's public key: {str(e)}")
                return None
            
            # Get next available client IP
            client_ip = self.get_next_client_ip()
            logging.info(f"Assigned IP {client_ip} to client {source_ip}")
            
            # Create WireGuard config
            wg_config = self.create_wg_config(
                client_private_key,
                client_public_key,
                server_public_key,
                client_ip
            )
            logging.info("Created WireGuard configuration")
            
            # Update gateway configuration
            if not self.update_gateway_config(client_public_key, client_ip):
                logging.error("Failed to update gateway configuration")
                return None
            
            # Prepare response data
            response_data = {
                'status': 'authorized',
                'wireguard_config': wg_config,
                'expires': 3600  # 1 hour
            }
            
            # Encrypt the response
            encrypted_response = self.encrypt_response(response_data)
            logging.info("Encrypted response data")
            
            return encrypted_response
            
        except Exception as e:
            logging.error(f"Error generating WireGuard config: {str(e)}")
            if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                import traceback
                traceback.print_exc()
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