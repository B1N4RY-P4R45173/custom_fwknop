from flask import Flask
from flask_socketio import SocketIO
import json
import logging
import os
import subprocess
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app)

# Configure logging
logging.basicConfig(
    filename='logs/gateway.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
with open('config/config.json', 'r') as f:
    config = json.load(f)

def setup_wireguard():
    """Initialize WireGuard interface if it doesn't exist"""
    try:
        # Check if interface exists
        subprocess.run(['ip', 'link', 'show', config['wireguard']['interface']], 
                      check=True, capture_output=True)
    except subprocess.CalledProcessError:
        # Interface doesn't exist, create it
        logger.info("Creating WireGuard interface")
        subprocess.run(['ip', 'link', 'add', config['wireguard']['interface'], 'type', 'wireguard'], 
                      check=True)
        subprocess.run(['ip', 'address', 'add', config['wireguard']['server_ip'] + '/24', 
                       'dev', config['wireguard']['interface']], check=True)
        subprocess.run(['ip', 'link', 'set', config['wireguard']['interface'], 'up'], check=True)
        
        # Configure WireGuard
        subprocess.run(['wg', 'set', config['wireguard']['interface'], 
                       'listen-port', str(config['wireguard']['port']),
                       'private-key', config['wireguard']['server_private_key']], check=True)

def add_peer(public_key, allowed_ips, client_ip):
    """Add a new WireGuard peer"""
    try:
        subprocess.run(['wg', 'set', config['wireguard']['interface'], 
                       'peer', public_key,
                       'allowed-ips', allowed_ips], check=True)
        logger.info(f"Added peer for {client_ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add peer: {str(e)}")
        return False

def remove_peer(public_key):
    """Remove a WireGuard peer"""
    try:
        subprocess.run(['wg', 'set', config['wireguard']['interface'], 
                       'peer', public_key, 'remove'], check=True)
        logger.info(f"Removed peer {public_key}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to remove peer: {str(e)}")
        return False

@socketio.on('connect', namespace='/gateway')
def handle_connect():
    """Handle controller connection"""
    logger.info("Controller connected")
    socketio.emit('status', {'status': 'connected'}, namespace='/gateway')

@socketio.on('disconnect', namespace='/gateway')
def handle_disconnect():
    """Handle controller disconnection"""
    logger.info("Controller disconnected")

@socketio.on('new_client', namespace='/gateway')
def handle_new_client(data):
    """Handle new client configuration"""
    try:
        client_ip = data['client_ip']
        wg_config = data['wg_config']
        
        # Add the new peer
        if add_peer(wg_config['peer']['public_key'], 
                   wg_config['peer']['allowed_ips'],
                   client_ip):
            logger.info(f"Successfully configured client {client_ip}")
            socketio.emit('client_added', {
                'client_ip': client_ip,
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }, namespace='/gateway')
        else:
            logger.error(f"Failed to configure client {client_ip}")
            socketio.emit('client_added', {
                'client_ip': client_ip,
                'status': 'failed',
                'timestamp': datetime.now().isoformat()
            }, namespace='/gateway')
            
    except Exception as e:
        logger.error(f"Error handling new client: {str(e)}")
        socketio.emit('error', {
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }, namespace='/gateway')

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('wireguard', exist_ok=True)
    
    # Setup WireGuard
    setup_wireguard()
    
    # Start the server
    socketio.run(app, 
                host=config['api']['host'], 
                port=config['api']['port'],
                debug=config['api']['debug']) 