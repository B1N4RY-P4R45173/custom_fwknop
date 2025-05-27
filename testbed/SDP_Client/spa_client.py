#!/usr/bin/env python3

import json
import logging
import socket
import time
import os
from base64 import b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class SPAClient:
    def __init__(self, config_file):
        self.setup_logging()
        self.load_config(config_file)
        self.setup_crypto()
        self.logger.info("SPA Client initialized")

    def setup_logging(self):
        self.logger = logging.getLogger('SPAClient')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def load_config(self, config_file):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.logger.info("Configuration loaded")

    def setup_crypto(self):
        # Derive encryption key from the base64 encoded key in config
        key_material = b64decode(self.config['encryption_key'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'SPA_SALT',
            iterations=100000,
            backend=default_backend()
        )
        self.encryption_key = kdf.derive(key_material)

        # Derive HMAC key
        hmac_material = b64decode(self.config['hmac_key'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'SPA_SALT',
            iterations=100000,
            backend=default_backend()
        )
        self.hmac_key = kdf.derive(hmac_material)

    def verify_hmac(self, data, hmac):
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(self.hmac_key)
        h.update(data)
        calculated_hmac = h.finalize()
        return hmac == calculated_hmac

    def decrypt_packet(self, encrypted_data):
        try:
            # Split IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding using PKCS7
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            self.logger.error(f"Decryption error: {str(e)}")
            return None

    def send_spa_packet(self):
        try:
            # Create SPA packet
            spa_data = {
                "source_ip": self.config['source_ip'],
                "target_port": self.config['target_port'],
                "protocol": self.config['protocol'],
                "timestamp": time.time()
            }
            
            # Convert to JSON and encode
            data = json.dumps(spa_data).encode()
            
            # Add PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Generate IV
            iv = os.urandom(16)
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calculate HMAC
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(self.hmac_key)
            h.update(encrypted_data)
            hmac = h.finalize()
            
            # Combine HMAC, IV, and encrypted data
            packet = hmac + iv + encrypted_data
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)  # 5 second timeout
            
            # Send packet
            server_address = (self.config['server_ip'], self.config['server_port'])
            self.logger.info(f"Sending SPA packet to {server_address}")
            sock.sendto(packet, server_address)
            
            # Wait for response
            try:
                response, _ = sock.recvfrom(4096)
                
                # Split HMAC and encrypted data
                response_hmac = response[:32]
                response_encrypted = response[32:]
                
                # Verify HMAC
                if not self.verify_hmac(response_encrypted, response_hmac):
                    self.logger.error("Invalid HMAC in response")
                    return False
                
                # Decrypt response
                decrypted_response = self.decrypt_packet(response_encrypted)
                if not decrypted_response:
                    self.logger.error("Failed to decrypt response")
                    return False
                
                # Parse response
                response_data = json.loads(decrypted_response)
                self.logger.info(f"Received response: {response_data}")
                
                if response_data.get('status') == 'spa_verified':
                    self.logger.info("SPA verification successful!")
                    return True
                else:
                    self.logger.error("SPA verification failed")
                    return False
                
            except socket.timeout:
                self.logger.error("Timeout waiting for response")
                return False
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.error(f"Error sending SPA packet: {str(e)}")
            return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SPA Client')
    parser.add_argument('-c', '--config', default='client_config.json',
                      help='Path to configuration file')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging')
    args = parser.parse_args()
    
    client = SPAClient(args.config)
    client.send_spa_packet()

if __name__ == '__main__':
    main() 