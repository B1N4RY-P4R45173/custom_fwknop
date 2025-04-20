# fwknop - Single Packet Authorization

A Python implementation of Single Packet Authorization (SPA) for securing network services. This tool allows you to open firewall ports only to authenticated clients using encrypted packets.

## Features

- Encrypted SPA packets using AES-CBC
- HMAC authentication
- Keepalive mechanism for maintaining open ports
- Support for both TCP and UDP protocols
- Daemon mode for server
- Test mode for client
- Configurable timeouts and intervals
- IP whitelisting support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/fwknop.git
cd fwknop
```

2. Install required Python packages:
```bash
pip3 install -r requirements.txt
```

3. Create and activate a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate
```

4. Install the required packages in the virtual environment:
```bash
pip3 install -r requirements.txt
```

## Configuration

1. Copy the example config files:
```bash
cp client_config.json.example client_config.json
cp server_config.json.example server_config.json
```

2. Edit the client configuration (`client_config.json`):
```json
{
    "server_ip": "your_server_ip",
    "server_port": 62201,
    "source_ip": "your_client_ip",
    "target_port": 22,
    "protocol": "tcp",
    "encryption_key": "your_encryption_key",
    "hmac_key": "your_hmac_key",
    "keepalive_interval": 240
}
```

3. Edit the server configuration (`server_config.json`):
```json
{
    "listen_port": 62201,
    "log_file": "/var/log/fwknop.log",
    "encryption_key": "your_encryption_key",
    "hmac_key": "your_hmac_key",
    "allowed_ips": ["your_client_ip/32"],
    "default_rule_timeout": 300,
    "cleanup_interval": 60
}
```

Make sure to:
- Use the same encryption and HMAC keys on both client and server
- Set appropriate allowed IP ranges in the server config
- Set correct server IP in the client config

## Usage

### Server

Start the server:
```bash
# Normal mode
sudo python3 fwknop_server.py

# Daemon mode
sudo python3 fwknop_server.py --daemon

# Custom port
sudo python3 fwknop_server.py -p 12345

# Verbose output
sudo python3 fwknop_server.py -v

# Show help
python3 fwknop_server.py -h
```

### Client

Send an SPA packet:
```bash
# Basic usage (must specify access port)
python3 fwknop_client.py -A 80

# Specify protocol (TCP/UDP)
python3 fwknop_client.py -A 53 -P udp

# Custom source IP
python3 fwknop_client.py -A 80 -s 192.168.1.100

# Custom keepalive interval (in seconds)
python3 fwknop_client.py -A 80 -k 120  # 2 minutes

# Test mode (no actual changes)
python3 fwknop_client.py -A 80 --test

# Verbose output
python3 fwknop_client.py -A 80 -v

# Show help
python3 fwknop_client.py -h
```

## Example Scenarios

1. Allow SSH access:
```bash
# On server
sudo python3 fwknop_server.py

# On client
python3 fwknop_client.py -A 22
```

2. Allow HTTP access with custom keepalive:
```bash
# On server
sudo python3 fwknop_server.py --daemon

# On client
python3 fwknop_client.py -A 80 -k 300  # 5 minutes
```

3. Allow DNS access (UDP):
```bash
# On server
sudo python3 fwknop_server.py -p 12345

# On client
python3 fwknop_client.py -A 53 -P udp -p 12345
```

## Security Considerations

1. Always use strong encryption and HMAC keys
2. Keep the server config file secure
3. Use appropriate IP whitelisting
4. Monitor the log file for suspicious activity
5. Consider using a dedicated user for the server process

## Troubleshooting

1. Check the server log file:
```bash
tail -f /var/log/fwknop.log
```

2. Use verbose mode to debug:
```bash
# Server
sudo python3 fwknop_server.py -v

# Client
python3 fwknop_client.py -A 80 -v
```

3. Test mode to verify configuration:
```bash
python3 fwknop_client.py -A 80 --test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 