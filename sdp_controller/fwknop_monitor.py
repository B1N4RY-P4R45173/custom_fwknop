#!/usr/bin/env python3

import json
import logging
import os
import requests
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='logs/fwknop_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
with open('config/config.json', 'r') as f:
    config = json.load(f)

def parse_fwknop_log(log_line):
    """Parse fwknop log line to extract client IP"""
    try:
        # Example log line format:
        # [2024-04-22 15:30:00] 192.168.0.114,udp/62201 -> 10.0.1.30,udp/62201
        parts = log_line.split(']')[1].strip().split(',')
        client_ip = parts[0].strip()
        return client_ip
    except Exception as e:
        logger.error(f"Error parsing log line: {e}")
        return None

def generate_wg_config(client_ip):
    """Generate WireGuard configuration for client"""
    try:
        response = requests.post(
            'http://localhost:5000/auth',
            json={
                'client_ip': client_ip,
                'target_port': '22'  # Default SSH port
            }
        )
        if response.status_code == 200:
            logger.info(f"Generated WireGuard config for {client_ip}")
            return response.json()
        else:
            logger.error(f"Failed to generate config for {client_ip}: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error generating config: {e}")
        return None

def monitor_fwknop_log():
    """Monitor fwknop log file for new connections"""
    log_file = '/var/log/fwknop/fwknopd.log'
    processed_ips = set()
    
    # Check if log file exists
    if not os.path.exists(log_file):
        logger.error(f"Log file not found: {log_file}")
        return
    
    logger.info("Starting fwknop log monitor")
    
    try:
        # Get initial file size
        last_size = os.path.getsize(log_file)
        
        while True:
            # Check if file has grown
            current_size = os.path.getsize(log_file)
            if current_size > last_size:
                # Read new content
                with open(log_file, 'r') as f:
                    f.seek(last_size)
                    new_lines = f.read()
                    
                    # Process new lines
                    for line in new_lines.split('\n'):
                        if line.strip():
                            client_ip = parse_fwknop_log(line)
                            if client_ip and client_ip not in processed_ips:
                                logger.info(f"New fwknop connection from {client_ip}")
                                generate_wg_config(client_ip)
                                processed_ips.add(client_ip)
                
                last_size = current_size
            
            # Sleep for a short time
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Error monitoring logs: {e}")

if __name__ == '__main__':
    monitor_fwknop_log() 