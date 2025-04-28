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

class WireGuardClient:
    def __init__(self, config_file='client_config.json'):
        self.load_config(config_file)
        self.setup_crypto()
        # Use user's home directory for config storage
        self.wg_config_dir = os.path.expanduser('/etc/wireguard')
        self.interface_name = 'wg0'
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

    def decrypt_response(self, encrypted_data):
        """Decrypt and verify the server's response"""
        try:
            # Extract IV from the beginning of the packet
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            # Decrypt using AES-CBC
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted) + decryptor.finalize()
            
            # Unpad the data
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Split data and HMAC
            json_data = data[:-32]  # HMAC is 32 bytes
            received_hmac = data[-32:]
            
            # Verify HMAC
            h = hmac.new(self.hmac_key, json_data, hashlib.sha256)
            if not hmac.compare_digest(h.digest(), received_hmac):
                logging.error("Invalid HMAC in response")
                return None
            
            return json.loads(json_data)
        except Exception as e:
            logging.error(f"Error decrypting response: {str(e)}")
            return None

    def save_wg_config(self, config):
        """Save WireGuard configuration to file"""
        try:
            config_path = os.path.join(self.wg_config_dir, f"{self.interface_name}.conf")
            
            # Create directory if it doesn't exist
            os.makedirs(self.wg_config_dir, exist_ok=True)
            
            # Save configuration
            with open(config_path, 'w') as f:
                f.write(config)
            
            # Set proper permissions
            os.chmod(config_path, 0o600)
            
            logging.info(f"WireGuard configuration saved to {config_path}")
            return True
        except Exception as e:
            logging.error(f"Error saving WireGuard configuration: {str(e)}")
            return False

    def apply_wg_config(self):
        """Apply WireGuard configuration"""
        try:
            # Stop existing interface if running
            subprocess.run(['wg-quick', 'down', self.interface_name], 
                         check=False, capture_output=True)
            
            # Start interface with new config
            result = subprocess.run(['wg-quick', 'up', self.interface_name],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                logging.info("WireGuard interface started successfully")
                return True
            else:
                logging.error(f"Failed to start WireGuard interface: {result.stderr}")
                return False
        except Exception as e:
            logging.error(f"Error applying WireGuard configuration: {str(e)}")
            return False

    def process_server_response(self, encrypted_response):
        """Process the server's encrypted response"""
        try:
            # Decrypt the response
            response_data = self.decrypt_response(encrypted_response)
            if not response_data:
                return False
            
            # Check if response contains WireGuard config
            if 'wireguard_config' not in response_data:
                logging.error("No WireGuard configuration in response")
                return False
            
            # Save the configuration
            if not self.save_wg_config(response_data['wireguard_config']):
                return False
            
            # Apply the configuration
            return self.apply_wg_config()
            
        except Exception as e:
            logging.error(f"Error processing server response: {str(e)}")
            return False

def main():
    # Example usage
    client = WireGuardClient()
    
    # This would typically be called from the SPA client after receiving the response
    # For testing, you can read a saved response file
    try:
        with open('server_response.bin', 'rb') as f:
            encrypted_response = f.read()
        if client.process_server_response(encrypted_response):
            print("WireGuard configuration applied successfully")
        else:
            print("Failed to apply WireGuard configuration")
    except FileNotFoundError:
        print("No server response file found")

if __name__ == "__main__":
    main() 