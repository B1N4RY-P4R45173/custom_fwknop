from flask import Flask, jsonify, request
import json
import logging
import os
import uuid
import subprocess
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='logs/sdp_controller.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
with open('config/config.json', 'r') as f:
    config = json.load(f)

def generate_wireguard_config(client_ip):
    """Generate WireGuard configuration for a client"""
    client_id = str(uuid.uuid4())[:8]
    wg_client_ip = f"10.0.0.{int(client_id, 16) % 254 + 1}"
    
    # Generate keys
    private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
    public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
    
    # Create client configuration
    client_config = {
        'interface': {
            'private_key': private_key,
            'address': f'{wg_client_ip}/24',
            'dns': config['wireguard']['dns']
        },
        'peer': {
            'public_key': config['wireguard']['server_public_key'],
            'endpoint': f"{config['gateway']['ip']}:{config['wireguard']['port']}",
            'allowed_ips': '0.0.0.0/0'
        }
    }
    
    # Save client config
    config_path = f"wireguard/client_{client_id}.conf"
    with open(config_path, 'w') as f:
        f.write(f"[Interface]\n")
        f.write(f"PrivateKey = {private_key}\n")
        f.write(f"Address = {wg_client_ip}/24\n")
        f.write(f"DNS = {config['wireguard']['dns']}\n\n")
        f.write(f"[Peer]\n")
        f.write(f"PublicKey = {config['wireguard']['server_public_key']}\n")
        f.write(f"Endpoint = {config['gateway']['ip']}:{config['wireguard']['port']}\n")
        f.write(f"AllowedIPs = 0.0.0.0/0\n")
    
    return client_config, config_path

@app.route('/auth', methods=['POST'])
def handle_auth():
    """Handle client authentication and WireGuard setup"""
    try:
        data = request.json
        client_ip = data.get('client_ip')
        target_port = data.get('target_port')
        
        if not client_ip or not target_port:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Generate WireGuard configuration
        wg_config, config_path = generate_wireguard_config(client_ip)
        
        # Log the event
        logger.info(f"Generated WireGuard config for {client_ip}")
        
        return jsonify({
            'status': 'success',
            'wg_config': wg_config,
            'config_path': config_path
        })
        
    except Exception as e:
        logger.error(f"Error handling auth: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    })

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('wireguard', exist_ok=True)
    
    # Start the server
    app.run(
        host=config['api']['host'], 
        port=config['api']['port'],
        debug=config['api']['debug']
    ) 