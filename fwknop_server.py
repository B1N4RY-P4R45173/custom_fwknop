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
import iptc
import threading
import subprocess
import base64
import psutil
import argparse
import pprint

class FwknopServer:
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        self.verbose = verbose
        self.port = port
        self.daemon = daemon
        self.load_config(config_file)
        self.setup_logging()
        self.setup_crypto()
        self.socket = None
        self.active_rules = {}  # Track active rules and their timers
        self.keepalive_interval = 60  # Check for active connections every minute
        self.rule_lock = threading.Lock()  # Lock for thread-safe rule management
        self.running = True

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

    def has_active_connections(self, port, protocol='tcp'):
        try:
            # Check for active TCP connections on the port
            connections = psutil.net_connections()
            for conn in connections:
                if conn.laddr.port == port and conn.status == 'ESTABLISHED':
                    if self.verbose:
                        print(f"Found active connection on port {port}")
                    return True
            return False
        except Exception as e:
            logging.error(f"Error checking active connections: {e}")
            return True  # Assume there are active connections if we can't check

    def rule_exists(self, source_ip, port, protocol='tcp'):
        try:
            cmd = ['iptables', '-C', 'INPUT',
                  '-p', protocol,
                  '-s', source_ip,
                  '--dport', str(port),
                  '-j', 'ACCEPT']
            result = subprocess.run(cmd, capture_output=True)
            if self.verbose:
                print(f"Checking rule existence: {' '.join(cmd)}")
                print(f"Result: {'exists' if result.returncode == 0 else 'does not exist'}")
            return result.returncode == 0
        except Exception as e:
            logging.error(f"Error checking rule existence: {e}")
            return False

    def add_firewall_rule(self, source_ip, port, protocol='tcp'):
        with self.rule_lock:
            try:
                rule_key = f"{source_ip}:{port}:{protocol}"
                
                # Check if rule already exists in iptables
                if not self.rule_exists(source_ip, port, protocol):
                    # Add new rule
                    cmd = [
                        'iptables', '-A', 'INPUT',
                        '-p', protocol,
                        '-s', source_ip,
                        '--dport', str(port),
                        '-j', 'ACCEPT'
                    ]
                    if self.verbose:
                        print(f"Adding rule: {' '.join(cmd)}")
                    subprocess.run(cmd, check=True)
                    logging.info(f"Added firewall rule for {source_ip} on port {port}")
                
                # Update or create timer
                if rule_key in self.active_rules:
                    self.active_rules[rule_key].cancel()
                
                timer = threading.Timer(
                    self.config['default_rule_timeout'],
                    self.check_and_remove_rule,
                    args=(source_ip, port, protocol)
                )
                timer.start()
                self.active_rules[rule_key] = timer
                
            except Exception as e:
                logging.error(f"Error adding firewall rule: {e}")

    def check_and_remove_rule(self, source_ip, port, protocol='tcp'):
        with self.rule_lock:
            try:
                rule_key = f"{source_ip}:{port}:{protocol}"
                
                # Check for active connections
                if self.has_active_connections(port, protocol):
                    # Extend the rule if there are active connections
                    logging.info(f"Active connections found, extending rule for {source_ip}:{port}")
                    self.add_firewall_rule(source_ip, port, protocol)
                    return
                
                # No active connections, remove the rule
                if self.rule_exists(source_ip, port, protocol):
                    cmd = [
                        'iptables', '-D', 'INPUT',
                        '-p', protocol,
                        '-s', source_ip,
                        '--dport', str(port),
                        '-j', 'ACCEPT'
                    ]
                    if self.verbose:
                        print(f"Removing rule: {' '.join(cmd)}")
                    subprocess.run(cmd, check=True)
                    logging.info(f"Removed firewall rule for {source_ip} on port {port}")
                
                if rule_key in self.active_rules:
                    del self.active_rules[rule_key]
                
            except Exception as e:
                logging.error(f"Error checking/removing firewall rule: {e}")

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
            
            if packet_data.get('source_ip') not in self.config['allowed_ips']:
                logging.warning(f"Unauthorized IP {packet_data.get('source_ip')}")
                return
            
            # Add firewall rule
            self.add_firewall_rule(
                packet_data['source_ip'],
                packet_data['port'],
                packet_data.get('protocol', 'tcp')
            )
            
            logging.info(f"Successfully processed SPA packet from {addr[0]}")
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('0.0.0.0', self.port))
            logging.info(f"Server started on port {self.port}")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
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

    def cleanup(self):
        # Clean up all active rules
        for rule_key in list(self.active_rules.keys()):
            source_ip, port, protocol = rule_key.split(':')
            self.check_and_remove_rule(source_ip, int(port), protocol)
        if self.socket:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(
        description='fwknop server - Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Start server on default port (62201):
    sudo python3 fwknop_server.py

  Start server on custom port with verbose output:
    sudo python3 fwknop_server.py -p 12345 -v

  Start server in daemon mode:
    sudo python3 fwknop_server.py --daemon

  Use custom config file:
    sudo python3 fwknop_server.py -c custom_config.json
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

    server = FwknopServer(config_file=args.config, verbose=args.verbose, 
                         port=args.port, daemon=args.daemon)
    server.start()

if __name__ == "__main__":
    main() 