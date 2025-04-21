import os
import json
import logging
import subprocess
from flask import Flask, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
socketio = SocketIO(app)

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

config = load_config()

def setup_wireguard():
    """Set up the WireGuard interface"""
    try:
        # Check if interface exists
        subprocess.run(['ip', 'link', 'show', config['wireguard']['interface']], 
                      check=True, capture_output=True)
        logger.info(f"WireGuard interface {config['wireguard']['interface']} already exists")
    except subprocess.CalledProcessError:
        # Create WireGuard interface
        logger.info(f"Creating WireGuard interface {config['wireguard']['interface']}")
        subprocess.run(['ip', 'link', 'add', config['wireguard']['interface'], 'type', 'wireguard'], 
                      check=True)
        
        # Set up IP address
        subprocess.run(['ip', 'address', 'add', 
                       f"{config['wireguard']['server_ip']}/24", 
                       'dev', config['wireguard']['interface']], 
                      check=True)
        
        # Configure WireGuard
        with open(config['wireguard']['server_private_key'], 'r') as f:
            private_key = f.read().strip()
        
        subprocess.run(['wg', 'set', config['wireguard']['interface'],
                       'listen-port', str(config['wireguard']['port']),
                       'private-key', private_key], 
                      check=True)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', config['wireguard']['interface'], 'up'], 
                      check=True)
        
        # Set up NAT
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 
                       config['wireguard']['physical_interface'],
                       '-j', 'MASQUERADE'], 
                      check=True)
        
        logger.info("WireGuard interface setup completed successfully")

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    })

@app.route('/config')
def get_config():
    return jsonify(config)

if __name__ == '__main__':
    # Setup WireGuard interface
    setup_wireguard()
    
    # Get configuration values
    host = config['api']['host']
    port = config['api']['port']
    debug = config['api']['debug']
    
    # Start the server
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        ssl_context=(
            config['security']['cert_path'],
            config['security']['key_path']
        ) if config['security']['ssl_enabled'] else None
    ) 