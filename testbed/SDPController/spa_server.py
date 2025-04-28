#!/usr/bin/env python3

import json
import logging
import socket
import sys
import time
import os
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import threading
import base64
import argparse
import pprint
from wireguard_manager import WireGuardManager

class SPAServer:
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        self.verbose = verbose
        self.port = port
        self.daemon = daemon
        self.load_config(config_file)
        self.setup_logging()
        self.setup_crypto()
        self.socket = None
        self.running = True
        # Track received SPA packets
        self.spa_requests = {}
        # Initialize WireGuard manager
        self.wg_manager = WireGuardManager(config_file)
        # Override verbose from config if specified
        if 'verbose' in self.config:
            self.verbose = self.config['verbose']
        # Override port from config if specified
        if 'listen_port' in self.config:
            self.port = self.config['listen_port']
        # Override daemon from config if specified
        if 'daemon' in self.config:
            self.daemon = self.config['daemon']

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)

    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        if self.verbose:
            # Log to both file and console in verbose mode
            logging.basicConfig(
                level=logging.INFO,
                format=log_format,
                handlers=[
                    logging.FileHandler(self.config['log_file']),
                    logging.StreamHandler()
                ]
            )
        else:
            if self.daemon:
                # In daemon mode, log only to file
                logging.basicConfig(
                    filename=self.config['log_file'],
                    level=logging.INFO,
                    format=log_format
                )
            else:
                # In normal mode, log to both file and console
                logging.basicConfig(
                    level=logging.INFO,
                    format=log_format,
                    handlers=[
                        logging.FileHandler(self.config['log_file']),
                        logging.StreamHandler()
                    ]
                )

    def setup_crypto(self):
        # Derive AES key from encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=b'fwknop_salt',  # Fixed salt for consistency
            iterations=100000,
            backend=default_backend()
        )
        self.encryption_key = kdf.derive(self.config['encryption_key'].encode())
        self.hmac_key = self.config['hmac_key'].encode()

    def verify_hmac(self, data, received_hmac):
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return hmac.compare_digest(h.digest(), received_hmac)

    def decrypt_packet(self, encrypted_data):
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
        
        return json_data, received_hmac

    def handle_packet(self, data, addr):
        try:
            if self.verbose:
                print(f"\nReceived packet from {addr[0]}:{addr[1]}")
                print(f"Raw data (base64): {base64.b64encode(data).decode()}")
            
            # Decrypt the packet
            decrypted, received_hmac = self.decrypt_packet(data)
            
            if self.verbose:
                print(f"Decrypted data: {decrypted}")
                print(f"HMAC from packet: {received_hmac.hex()}")
            
            # Verify HMAC
            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                return
            
            # Parse the packet
            packet_data = json.loads(decrypted)
            
            if self.verbose:
                print("\nPacket contents:")
                pprint.pprint(packet_data)
            
            # Check if source IP is allowed
            if packet_data.get('source_ip') not in self.config['allowed_ips']:
                logging.warning(f"Unauthorized IP {packet_data.get('source_ip')}")
                return
            
            # Check if protocol is allowed
            if 'allowed_protocols' in self.config:
                if packet_data.get('protocol') not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol {packet_data.get('protocol')}")
                    return
            
            # Process SPA request and get WireGuard config
            wg_response = self.wg_manager.process_spa_request(addr[0])  # Use actual source IP from socket
            
            if wg_response:
                # Send the encrypted WireGuard config back to client
                self.socket.sendto(wg_response, addr)
                logging.info(f"Sent WireGuard config to {addr[0]}")
            else:
                logging.error(f"Failed to generate WireGuard config for {addr[0]}")
            
            # Record the access request
            key = f"{addr[0]}:{packet_data.get('port', '')}:{packet_data.get('protocol', 'tcp')}"
            self.spa_requests[key] = {
                'timestamp': time.time(),
                'data': packet_data
            }
            
            logging.info(f"Authorized SPA request: {key}")
            
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Bind to all interfaces
            self.socket.bind(('0.0.0.0', self.port))
            logging.info(f"Server started on port {self.port}")
            logging.info(f"Listening on all interfaces (0.0.0.0)")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if self.verbose:
                        logging.info(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                    self.handle_packet(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Error processing packet: {str(e)}")
                    continue
        except KeyboardInterrupt:
            logging.info("Server shutting down")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.socket:
            self.socket.close()
        sys.exit(0)

    def cleanup(self):
        if self.socket:
            self.socket.close()
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description='SPA Server - Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Start server on default port (62201):
    python3 spa_server.py

  Start server on custom port with verbose output:
    python3 spa_server.py -p 12345 -v

  Start server in daemon mode:
    python3 spa_server.py --daemon

  Use custom config file:
    python3 spa_server.py -c custom_config.json
''')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='server_config.json',
                      help='Path to config file (default: server_config.json)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Port to listen on (default: 62201)')
    parser.add_argument('--daemon', action='store_true',
                      help='Run server in daemon mode')
    args = parser.parse_args()

    if args.daemon:
        # Daemonize the process
        try:
            pid = os.fork()
            if pid > 0:
                # Parent process exits
                sys.exit(0)
        except OSError as e:
            print(f"Fork failed: {e}")
            sys.exit(1)

        # Create new session
        os.setsid()
        os.umask(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    server = SPAServer(config_file=args.config, verbose=args.verbose, 
                      port=args.port, daemon=args.daemon)
    try:
        server.start()
    except KeyboardInterrupt:
        server.cleanup()

if __name__ == "__main__":
    main() 