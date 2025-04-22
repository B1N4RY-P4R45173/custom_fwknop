#!/usr/bin/env python3

import json
import socket
import sys
import time
import threading
import os
import argparse
import base64
import pprint
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SPAClient:
    def __init__(self, config_file='client_config.json', port=None, server_port=62201, 
                 protocol='tcp', source_ip=None, keepalive_interval=240,
                 test_mode=False, verbose=False):
        self.verbose = verbose
        self.test_mode = test_mode
        self.load_config(config_file)
        if port:
            self.config['target_port'] = port
        if source_ip:
            self.config['source_ip'] = source_ip
        if server_port:
            self.config['server_port'] = server_port
        if protocol:
            self.config['protocol'] = protocol
        if keepalive_interval:
            self.config['keepalive_interval'] = keepalive_interval
        
        # Override settings from config if specified
        if 'verbose' in self.config:
            self.verbose = self.config['verbose']
        if 'test_mode' in self.config:
            self.test_mode = self.config['test_mode']
        if 'keepalive_interval' in self.config:
            self.keepalive_interval = self.config['keepalive_interval']
        
        self.setup_crypto()
        self.keepalive_timer = None

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            
            # Automatically detect source IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server to get our IP
                s.connect(("8.8.8.8", 80))
                self.config['source_ip'] = s.getsockname()[0]
            except Exception:
                # Fallback to localhost if detection fails
                self.config['source_ip'] = "127.0.0.1"
            finally:
                s.close()
            
            if self.verbose:
                print(f"Detected source IP: {self.config['source_ip']}")
            
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in configuration file {config_file}")
            sys.exit(1)

    def setup_crypto(self):
        # Use the encryption key for both encryption and HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=b'fwknop_salt',  # Fixed salt for consistency
            iterations=100000,
            backend=default_backend()
        )
        self.encryption_key = kdf.derive(self.config['encryption_key'].encode())
        self.hmac_key = self.config['hmac_key'].encode()

    def create_packet(self):
        # Generate a random nonce for each packet
        nonce = os.urandom(8)
        # Generate a new random IV for each packet
        iv = os.urandom(16)
        
        packet_data = {
            'source_ip': self.config['source_ip'],
            'port': self.config['target_port'],
            'protocol': self.config['protocol'],
            'timestamp': int(time.time()),
            'nonce': nonce.hex(),
            'message': 'SPA request from SDP Client'
        }
        
        if self.verbose:
            print("\nPacket data:")
            pprint.pprint(packet_data)
        
        # Convert to JSON and encode
        json_data = json.dumps(packet_data).encode()
        
        # Calculate HMAC
        h = hmac.new(self.hmac_key, json_data, hashlib.sha256)
        hmac_digest = h.digest()
        
        if self.verbose:
            print(f"\nHMAC digest (hex):")
            print(hmac_digest.hex())
        
        # Combine data and HMAC
        combined_data = json_data + hmac_digest
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(combined_data) + padder.finalize()
        
        # Encrypt using AES-CBC with new IV
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        final_packet = iv + encrypted
        
        if self.verbose:
            print(f"\nEncrypted data (base64):")
            print(base64.b64encode(final_packet).decode())
        
        return final_packet

    def send_keepalive(self):
        try:
            self.send_packet(is_keepalive=True)
            if self.verbose:
                print(f"Keepalive packet sent to {self.config['server_ip']}:{self.config['server_port']}")
        except Exception as e:
            print(f"Error sending keepalive packet: {str(e)}")
        finally:
            # Schedule next keepalive
            self.keepalive_timer = threading.Timer(
                self.keepalive_interval,
                self.send_keepalive
            )
            self.keepalive_timer.start()

    def send_packet(self, is_keepalive=False):
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Create and send the packet
            packet = self.create_packet()
            
            if self.test_mode:
                print("\n[TEST MODE] Would send packet:")
                print(f"  Source IP: {self.config['source_ip']}")
                print(f"  Target Port: {self.config['target_port']}")
                print(f"  Protocol: {self.config['protocol']}")
                print(f"  Server: {self.config['server_ip']}:{self.config['server_port']}")
                if self.verbose:
                    print(f"  Packet data (base64): {base64.b64encode(packet).decode()}")
                return
            
            sock.sendto(packet, (self.config['server_ip'], self.config['server_port']))
            
            if not is_keepalive or self.verbose:
                print(f"SPA packet sent to {self.config['server_ip']}:{self.config['server_port']}")
                if self.verbose:
                    print(f"Requesting access to port: {self.config['target_port']}")
            
        except Exception as e:
            print(f"Error sending packet: {str(e)}")
        finally:
            sock.close()

    def start_keepalive(self):
        if self.test_mode:
            print(f"\n[TEST MODE] Would start keepalive with interval: {self.keepalive_interval} seconds")
            return

        # Start keepalive timer
        self.keepalive_timer = threading.Timer(
            self.keepalive_interval,
            self.send_keepalive
        )
        self.keepalive_timer.start()
        if self.verbose:
            print(f"Keepalive mechanism started (interval: {self.keepalive_interval} seconds)")
        else:
            print("Keepalive mechanism started")

    def stop_keepalive(self):
        if self.keepalive_timer:
            self.keepalive_timer.cancel()
            print("Keepalive mechanism stopped")

def main():
    parser = argparse.ArgumentParser(
        description='SPA Client - Send Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Request access to port 80 (TCP):
    python3 spa_client.py -A 80 -p 62201

  Request access to port 53 (UDP):
    python3 spa_client.py -A 53 -P udp -p 62201

  Request access to port 443 with verbose output:
    python3 spa_client.py -A 443 -p 62201 -v

  Specify source IP and keepalive interval:
    python3 spa_client.py -A 80 -s 192.168.1.100 -k 120 (for 2 minutes)

  Test mode (no actual packet sending):
    python3 spa_client.py -A 80 --test

  Use custom config file:
    python3 spa_client.py -A 22 -p 62201 -c custom_config.json
''')
    parser.add_argument('-A', '--access', type=int,
                      help='Target port to request access to (overrides config file)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Destination port to send SPA packet to (default: 62201)')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp'], default='tcp',
                      help='Protocol to request access for (default: tcp)')
    parser.add_argument('-s', '--source-ip', type=str,
                      help='Override source IP address')
    parser.add_argument('-k', '--keepalive', type=int, default=240,
                      help='Keepalive interval in seconds (default: 240)')
    parser.add_argument('--test', action='store_true',
                      help='Test mode: show what would happen without sending packets')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='client_config.json',
                      help='Path to config file (default: client_config.json)')
    args = parser.parse_args()

    client = SPAClient(config_file=args.config, port=args.access, 
                      server_port=args.port, protocol=args.protocol,
                      source_ip=args.source_ip, keepalive_interval=args.keepalive,
                      test_mode=args.test, verbose=args.verbose)
    client.send_packet()  # Send initial packet
    client.start_keepalive()  # Start keepalive mechanism
    
    try:
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.stop_keepalive()
        print("\nClient shutting down")

if __name__ == "__main__":
    main() 