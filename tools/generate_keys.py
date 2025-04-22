#!/usr/bin/env python3

import base64
import os
import json

def generate_key():
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def update_config_files():
    # Generate new keys
    encryption_key = generate_key()
    hmac_key = generate_key()
    
    # Update server config
    with open('server_config.json', 'r') as f:
        server_config = json.load(f)
    
    server_config['encryption_key'] = encryption_key
    server_config['hmac_key'] = hmac_key
    
    with open('server_config.json', 'w') as f:
        json.dump(server_config, f, indent=4)
    
    # Update client config
    with open('client_config.json', 'r') as f:
        client_config = json.load(f)
    
    client_config['encryption_key'] = encryption_key
    client_config['hmac_key'] = hmac_key
    
    with open('client_config.json', 'w') as f:
        json.dump(client_config, f, indent=4)
    
    print("Generated and updated keys in both config files.")
    print("Please update the 'source_ip' in client_config.json and 'allowed_ips' in server_config.json")

if __name__ == "__main__":
    update_config_files() 