#!/usr/bin/env python3

import json
import logging
import socket
import time
import os
import base64
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
        # Use the raw keys directly
        self.encryption_key = b64decode(self.config['encryption_key'])
        self.hmac_key = b64decode(self.config['hmac_key'])
        self.logger.info(f"Encryption key: {base64.b64encode(self.encryption_key).decode()}")
        self.logger.info(f"HMAC key: {base64.b64encode(self.hmac_key).decode()}")

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
            
            self.logger.info(f"Decrypting packet - IV: {base64.b64encode(iv).decode()}")
            self.logger.info(f"Ciphertext length: {len(ciphertext)}")
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            self.logger.info(f"Padded plaintext length: {len(padded_plaintext)}")
            
            # Remove padding using PKCS7
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            self.logger.info(f"Plaintext length: {len(plaintext)}")
            
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
            self.logger.info(f"Original data: {data.decode()}")
            
            # Add PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            self.logger.info(f"Padded data length: {len(padded_data)}")
            
            # Generate IV
            iv = os.urandom(16)
            self.logger.info(f"Generated IV: {base64.b64encode(iv).decode()}")
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            self.logger.info(f"Encrypted data length: {len(encrypted_data)}")
            
            # Calculate HMAC
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(self.hmac_key)
            h.update(encrypted_data)
            hmac = h.finalize()
            self.logger.info(f"HMAC: {base64.b64encode(hmac).decode()}")
            
            # Combine HMAC, IV, and encrypted data
            packet = hmac + iv + encrypted_data
            self.logger.info(f"Final packet length: {len(packet)}")
            self.logger.info(f"Final packet (base64): {base64.b64encode(packet).decode()}")
            
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
                self.logger.info(f"Received response length: {len(response)}")
                
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