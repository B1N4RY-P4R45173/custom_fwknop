#!/usr/bin/env python3

import time
import re
import requests
import json
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    filename='logs/fwknop_integration.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FwknopHandler(FileSystemEventHandler):
    def __init__(self):
        self.api_url = "http://localhost:5000/auth"
        self.last_processed = None
    
    def on_modified(self, event):
        if event.src_path != "/var/log/fwknop.log":
            return
            
        try:
            with open(event.src_path, 'r') as f:
                # Read new lines
                lines = f.readlines()
                if self.last_processed:
                    lines = lines[self.last_processed:]
                self.last_processed = len(lines)
                
                # Process each line
                for line in lines:
                    if "Successfully processed SPA packet from" in line:
                        # Extract client IP
                        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            client_ip = match.group(1)
                            
                            # Extract port from the line or use default
                            port_match = re.search(r'port (\d+)', line)
                            target_port = port_match.group(1) if port_match else "22"
                            
                            # Send to SDP API
                            response = requests.post(
                                self.api_url,
                                json={
                                    'client_ip': client_ip,
                                    'target_port': target_port
                                }
                            )
                            
                            if response.status_code == 200:
                                logger.info(f"Successfully processed auth for {client_ip}")
                            else:
                                logger.error(f"Failed to process auth for {client_ip}: {response.text}")
                            
        except Exception as e:
            logger.error(f"Error processing fwknop log: {str(e)}")

def main():
    event_handler = FwknopHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log", recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main() 