import os
import json
import logging
import subprocess
from flask import Flask, jsonify, request
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

def check_wireguard_interface():
    """Check if WireGuard interface exists and is configured correctly"""
    try:
        # Check if interface exists
        result = subprocess.run(['ip', 'link', 'show', config['wireguard']['interface']], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"WireGuard interface {config['wireguard']['interface']} does not exist")
            return False

        # Check if interface has correct IP
        result = subprocess.run(['ip', 'addr', 'show', config['wireguard']['interface']],
                              capture_output=True, text=True)
        if config['wireguard']['server_ip'] not in result.stdout:
            logger.error(f"WireGuard interface {config['wireguard']['interface']} has incorrect IP")
            return False

        # Check if NAT is configured
        result = subprocess.run(['iptables', '-t', 'nat', '-L', 'POSTROUTING'],
                              capture_output=True, text=True)
        if config['wireguard']['physical_interface'] not in result.stdout:
            logger.warning("NAT rule not found, adding it...")
            setup_nat()

        return True
    except Exception as e:
        logger.error(f"Error checking WireGuard interface: {e}")
        return False

def setup_nat():
    """Set up NAT for WireGuard traffic"""
    try:
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 
                       config['wireguard']['physical_interface'],
                       '-j', 'MASQUERADE'], 
                      check=True)
        logger.info("NAT rule added successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add NAT rule: {e}")
        raise

def add_peer(public_key, allowed_ips, persistent_keepalive=25):
    """Add a new WireGuard peer"""
    try:
        # Add the peer
        subprocess.run(['wg', 'set', config['wireguard']['interface'],
                       'peer', public_key,
                       'allowed-ips', allowed_ips,
                       'persistent-keepalive', str(persistent_keepalive)],
                      check=True)
        
        # Save the configuration
        subprocess.run(['wg-quick', 'save', config['wireguard']['interface']],
                      check=True)
        
        logger.info(f"Added peer with public key: {public_key}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add peer: {e}")
        return False

def remove_peer(public_key):
    """Remove a WireGuard peer"""
    try:
        subprocess.run(['wg', 'set', config['wireguard']['interface'],
                       'peer', public_key, 'remove'],
                      check=True)
        
        # Save the configuration
        subprocess.run(['wg-quick', 'save', config['wireguard']['interface']],
                      check=True)
        
        logger.info(f"Removed peer with public key: {public_key}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to remove peer: {e}")
        return False

def list_peers():
    """List all WireGuard peers"""
    try:
        result = subprocess.run(['wg', 'show', config['wireguard']['interface']],
                              capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to list peers: {e}")
        return None

@app.route('/health')
def health_check():
    wg_status = check_wireguard_interface()
    return jsonify({
        'status': 'healthy' if wg_status else 'degraded',
        'version': '1.0.0',
        'wireguard': {
            'interface': config['wireguard']['interface'],
            'status': 'up' if wg_status else 'down'
        }
    })

@app.route('/config')
def get_config():
    return jsonify(config)

@app.route('/peers', methods=['GET'])
def get_peers():
    peers = list_peers()
    if peers is None:
        return jsonify({'error': 'Failed to list peers'}), 500
    return jsonify({'peers': peers})

@app.route('/peers', methods=['POST'])
def create_peer():
    data = request.get_json()
    if not data or 'public_key' not in data or 'allowed_ips' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if add_peer(data['public_key'], data['allowed_ips']):
        return jsonify({'status': 'success'}), 201
    return jsonify({'error': 'Failed to add peer'}), 500

@app.route('/peers/<public_key>', methods=['DELETE'])
def delete_peer(public_key):
    if remove_peer(public_key):
        return jsonify({'status': 'success'}), 200
    return jsonify({'error': 'Failed to remove peer'}), 500

if __name__ == '__main__':
    # Verify WireGuard interface
    if not check_wireguard_interface():
        logger.error("WireGuard interface check failed. Please ensure WireGuard is properly configured.")
        exit(1)
    
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