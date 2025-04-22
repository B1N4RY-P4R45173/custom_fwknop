import os
import json
import logging
import subprocess
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from dotenv import load_dotenv
from OpenSSL import crypto
from datetime import datetime, timedelta

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

def generate_self_signed_cert():
    """Generate self-signed SSL certificate if it doesn't exist"""
    cert_dir = os.path.dirname(config['security']['cert_path'])
    os.makedirs(cert_dir, exist_ok=True)
    
    # Generate key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Generate certificate
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Save certificate
    with open(config['security']['cert_path'], "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Save private key
    with open(config['security']['key_path'], "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info("Generated self-signed SSL certificate")

def get_ssl_context():
    """Get SSL context, generating self-signed certificate if needed"""
    if not config['security']['ssl_enabled']:
        return None
    
    cert_path = config['security']['cert_path']
    key_path = config['security']['key_path']
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logger.warning("SSL certificate not found, generating self-signed certificate")
        generate_self_signed_cert()
    
    return (cert_path, key_path)

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
            logger.warning("NAT rule not found. The application needs root privileges to add NAT rules.")
            logger.warning("Please run the application with sudo or add the NAT rule manually:")
            logger.warning(f"sudo iptables -t nat -A POSTROUTING -o {config['wireguard']['physical_interface']} -j MASQUERADE")
            return True  # Continue even without NAT rule

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
        logger.warning("The application needs root privileges to add NAT rules.")
        logger.warning("Please run the application with sudo or add the NAT rule manually:")
        logger.warning(f"sudo iptables -t nat -A POSTROUTING -o {config['wireguard']['physical_interface']} -j MASQUERADE")
        return False

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
    
    # Get SSL context
    ssl_context = get_ssl_context() if config['security']['ssl_enabled'] else None
    
    # Start the server
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        ssl_context=ssl_context
    ) 