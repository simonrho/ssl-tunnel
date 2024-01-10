import argparse
import json
import os
import shutil
import socket
import sys
import tarfile
import tempfile
import requests
from pathlib import Path

try:
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization    
except Exception as e:
    sys.exit(f'❌ Module import Error: {e}')

from ..utils.certificate_management import *
from ..utils.logging_config import logger
from ..utils.validators import *
from .global_resources import *

DEFAULT_CONFIG_SERVER = {
    "server": {
        "tun_name": "ssl-tunnel",
        "listen_address": "0.0.0.0",
        "listen_port": 443,
        "trust_store": "/etc/ssl-tunnel/trust-store",
        "cert_file": "/etc/ssl-tunnel/server.pem",
        "key_file": "/etc/ssl-tunnel/server.key",
        "max_clients": 256,
        "keepalive_idle": 10,
        "keepalive_interval": 10,
        "keepalive_count": 3,
        "route_prefix_length": 32,
        "route_suppress": False,
        "disable_auto_reconnect": False,
        "operation_mode": "l3",
        "no_flood": False,
        "no_auth": False
    }
}

DEFAULT_CONFIG_CLIENT = {
    "client": {
        "tun_name": "ssl-tunnel",
        "server_port": 443,
        "trust_store": "/etc/ssl-tunnel/trust-store",
        "cert_file": "/etc/ssl-tunnel/client.pem",
        "key_file": "/etc/ssl-tunnel/client.key",
        "max_clients": 256,
        "keepalive_idle": 10,
        "keepalive_interval": 10,
        "keepalive_count": 3,
        "route_prefix_length": 32,
        "route_suppress": False,
        "disable_auto_reconnect": False,
        "operation_mode": "l3",
        "no_flood": False,
        "no_auth": False
    }
}

def read_config_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except:
        return {}

def get_public_ip():
    try:
        response = requests.get('http://ifconfig.me')
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to get public IP: {e}")

def resolve_fqdn(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return None

def move_file(src, dst, overwrite=False):
    if os.path.exists(dst) and not overwrite:
        logger.warning(f"🚨 File {dst} already exists. Skipping exporting to prevent overwriting.")
        return False
    else:
        shutil.move(src, dst)
        return True

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            logger.info(f"📂 Created directory: {directory}")
        except OSError as e:
            logger.error(f"❌ Failed to create directory {directory}: {e}")
            sys.exit(1)

def check_conflict_in_common_name(name, trust_store_path):
    for cert_file in Path(trust_store_path).glob('*.pem'):
        with open(cert_file, 'rb') as f:
            cert = load_pem_x509_certificate(f.read(), default_backend())
            if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == name:
                return True
    return False



# Parse CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(description='SSL Tunnel Tool')
    parser.add_argument('--version', action='version', version=f'SSL Tunnel Tool {VERSION}', help='Show the version of the program and exit')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # Server subcommand
    server_parser = subparsers.add_parser('server', help='Commands related to SSL tunnel server')
    server_subparsers = server_parser.add_subparsers(dest='server_command', required=True)

    # Server init subcommand
    server_init_parser = server_subparsers.add_parser('init', help='Create /etc/ssl-tunnel directory and certificates')
    server_init_parser.add_argument('--overwrite', action='store_true', default=False, help='Overwrite existing certificates')

    # Server create-client subcommand
    server_create_client_parser = server_subparsers.add_parser('create-client', help="Create a new client's certificate, private key, and client config including server address and port. Also, save its public certificate to the server's trust-store.")
    server_create_client_parser.add_argument('--name', required=True, help='Name of the client')
    server_create_client_parser.add_argument('--days', type=int, default=365, help='Validity period of the certificate in days (default: 365, equivalent to 1 year)')
    server_create_client_parser.add_argument('--server-address', default='auto', help='SSL server address (default: "auto" to auto-detect)')
    server_create_client_parser.add_argument('--server-port', type=int, default=443, help='SSL server port (default: 443)')
    server_create_client_parser.add_argument('--overwrite', action='store_true', default=False, help='Overwrite an existing client profile if it exists.')
    server_create_client_parser.add_argument('--output-dir', default='.', help='Path for the client setup file (default: current directory)')

    server_start_parser = server_subparsers.add_parser('start', help="Start the SSL Tunnel Server")
    server_start_parser.add_argument('--tun-name', default='ssl-tunnel', help='TUN interface name (default: ssl-tunnel)')
    server_start_parser.add_argument('--tun-address', type=valid_cidr, default=None, help='TUN interface address in CIDR notation')
    server_start_parser.add_argument('--listen-address', default='0.0.0.0', help='Listen address for the SSL server (default: 0.0.0.0)')
    server_start_parser.add_argument('--listen-port', type=int, default=443, help='Listen port for the SSL server (default: 443)')
    server_start_parser.add_argument('--trust-store', default='/etc/ssl-tunnel/trust-store', type=validate_path, help='Path to the trust store containing CA/certificates for client verification')
    server_start_parser.add_argument('--cert-file', default='/etc/ssl-tunnel/server.pem', type=lambda f: validate_file(f, 'cert'), help='Certificate file for SSL server')
    server_start_parser.add_argument('--key-file', default='/etc/ssl-tunnel/server.key', type=lambda f: validate_file(f, 'key'), help='Key file for SSL server')
    server_start_parser.add_argument('--max-clients', type=int, default=256, help='Maximum number of clients (default: 256)')
    server_start_parser.add_argument('--keepalive-idle', type=int, default=10, help='Keepalive idle time (default: 10)')
    server_start_parser.add_argument('--keepalive-interval', type=int, default=10, help='Keepalive interval (default: 10)')
    server_start_parser.add_argument('--keepalive-count', type=int, default=3, help='Keepalive count (default: 3)')
    server_start_parser.add_argument('--route-prefix-length', type=validate_prefix_length, default=32, help='Route prefix length')
    server_start_parser.add_argument('--route-suppress', action='store_true', default=False, help='Suppress route addition')
    server_start_parser.add_argument('--operation-mode', choices=['l2', 'l3'], default='l3', help='Operation mode: l2 (Ethernet frames) or l3 (IP packets) (default: l3)')
    server_start_parser.add_argument('--mac', type=is_valid_mac_address, help='MAC address in format XX:XX:XX:XX:XX:XX (optional)')
    server_start_parser.add_argument('--no-flood', action='store_true', default=False, help='Disable broadcasting of BUM (Broadcast, Unknown unicast, Multicast) traffic to all SSL clients')
    server_start_parser.add_argument('--no-auth', action='store_true', help='Run server without SSL authentication')
    
    # Client subcommand
    client_parser = subparsers.add_parser('client', help='Commands related to SSL tunnel client')
    client_subparsers = client_parser.add_subparsers(dest='client_command', required=True)

    # Client init subcommand
    client_init_parser = client_subparsers.add_parser('init', help='Initialize the SSL tunnel client with default settings.')
    client_init_parser.add_argument('--overwrite', action='store_true', default=False, help='Overwrite an existing client config and certificate if it exists.')

    # Client load subcommand
    client_load_parser = client_subparsers.add_parser('load', help='Load, uncompress, and set up the client configuration from a .gz file.')
    client_load_parser.add_argument('--file', required=True, help='Path to the .gz file containing the client configuration and certificates')
    client_load_parser.add_argument('--overwrite', action='store_true', default=False, help='Overwrite an existing client config and certificate if it exists.')

    # Client start subcommand
    client_start_parser = client_subparsers.add_parser('start', help='Start the SSL Tunnel Client')
    client_start_parser.add_argument('--tun-name', default='ssl-tunnel', help='TUN interface name (default: ssl-tunnel)')
    client_start_parser.add_argument('--tun-address', type=valid_cidr, default=None, help='TUN interface address in CIDR notation')
    client_start_parser.add_argument('--server-address', default='', help='SSL server address')
    client_start_parser.add_argument('--server-port', type=int, default=443, help='SSL server port (default: 443)')
    client_start_parser.add_argument('--trust-store', default='/etc/ssl-tunnel/trust-store', type=validate_path, help='Path to the trust store containing CA/certificates for server verification')
    client_start_parser.add_argument('--cert-file', default='/etc/ssl-tunnel/client.pem', type=lambda f: validate_file(f, 'cert'), help='Certificate file for SSL client')
    client_start_parser.add_argument('--key-file', default='/etc/ssl-tunnel/client.key', type=lambda f: validate_file(f, 'key'), help='Key file for SSL client')
    client_start_parser.add_argument('--keepalive-idle', type=int, default=10, help='Keepalive idle time (default: 10)')
    client_start_parser.add_argument('--keepalive-interval', type=int, default=10, help='Keepalive interval (default: 10)')
    client_start_parser.add_argument('--keepalive-count', type=int, default=3, help='Keepalive count (default: 3)')
    client_start_parser.add_argument('--disable-auto-reconnect', action='store_true', default=False, help='Disable automatic reconnection if the SSL connection is closed')
    client_start_parser.add_argument('--operation-mode', choices=['l2', 'l3'], default='l3', help='Operation mode: l2 (Ethernet frames) or l3 (IP packets) (default: l3)')
    client_start_parser.add_argument('--mac', type=is_valid_mac_address, help='MAC address in format XX:XX:XX:XX:XX:XX (optional)')
    client_start_parser.add_argument('--no-auth', action='store_true', default=False, help='Run client without SSL authentication')

    # Certificate subcommand
    cert_parser = subparsers.add_parser('certificate', help='Create a self-signed certificate')
    cert_parser.add_argument('--cert-name', required=True, help='Name for the certificate (example: MyCert)')
    cert_parser.add_argument('--cert-out-file', required=True, help='File to save the certificate (example: my_cert.pem)')
    cert_parser.add_argument('--key-out-file', required=True, help='File to save the certificate key (example: my_cert.key)')
    cert_parser.add_argument('--days', type=int, default=365, help='Validity period of the certificate in days (default: 365, 1 year)')
    cert_parser.add_argument('--key-size', type=int, default=2048, help='Key size for the certificate key (default: 2048)')
    cert_parser.add_argument('--common-name', required=True, help='Common name for the certificate (usually a domain name, example: www.example.com)')
    cert_parser.add_argument('--country-name', help='Country name (2 letter code)')
    cert_parser.add_argument('--state-name', help='State or Province Name')
    cert_parser.add_argument('--locality-name', help='Locality Name (eg, city)')
    cert_parser.add_argument('--organization-name', help='Organization Name (eg, company)')
    cert_parser.add_argument('--organizational-unit-name', help='Organizational Unit Name (eg, section)')
    
    # Set default values from config or default values
    config = read_config_file('/etc/ssl-tunnel/config.json')

    cmd_line = ' '.join(sys.argv)

    if 'server start' in cmd_line:
        config = config.get('server', {})
        default_server_config = DEFAULT_CONFIG_SERVER.get('server', {})
        final_config = {**default_server_config, **config}
        server_start_parser.set_defaults(**final_config)

    if 'server create-client' in cmd_line:
        config = config.get('server', {})
        default_server_config = DEFAULT_CONFIG_SERVER.get('server', {})
        final_config = {**default_server_config, **config}
        server_create_client_parser.set_defaults(**final_config)
        
    if 'client start' in cmd_line:
        config = config.get('client', {})
        default_client_config = DEFAULT_CONFIG_CLIENT.get('client', {})
        final_config = {**default_client_config, **config}
        client_start_parser.set_defaults(**final_config)

    # Parse the arguments
    args = parser.parse_args()
        
    return args


def ssl_tunnel_init_cmd(default_config, overwrite=False):
    """
    Initialize the SSL tunnel by creating necessary directories, certificate, key, and configuration file.
    """
    
    mode = list(default_config.keys())[0]
    
    cert_path = default_config[mode]['cert_file']
    key_path = default_config[mode]['key_file']
    trust_store_path = default_config[mode]['trust_store']
    config_path = '/etc/ssl-tunnel/config.json'

    # Create directories
    for path in ['/etc/ssl-tunnel', trust_store_path]:
        if not os.path.exists(path):
            os.makedirs(path)
        elif overwrite:
            logger.info(f"🔄 Overwriting existing directory: {path}")
        else:
            logger.info(f"🚨 Directory already exists: {path}")

    # Generate certificate and key
    if not os.path.exists(cert_path) or not os.path.exists(key_path) or overwrite:
        key = SSLCertificate.create_key_pair()
        cert = SSLCertificate.create_self_signed_certificate(key, f"SSL Tunnel {mode.capitalize()}")

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))

        logger.info(f"📜 Generated certificate: {cert_path}")
        logger.info(f"🔑 Generated private key: {key_path}")
    else:
        logger.warning("🚨 Certificate and key already exist. Use --overwrite to regenerate.")

    # Create default configuration file
    if not os.path.exists(config_path) or overwrite:
        with open(config_path, 'w') as f:            
            json.dump(default_config, f, indent=4)
                
        logger.info(f"👌 Created default configuration file: {config_path}")
    else:
        logger.warning("🚨 Configuration file already exists. Use --overwrite to regenerate.")

def server_create_client_cmd(args):
    if not os.path.exists(args.trust_store):
        logger.error(f"❌ Trust store directory '{args.trust_store}' does not exist. Certificate not copied. Exiting...")
        sys.exit(1)
        
    if not os.access(args.trust_store, os.W_OK):
        logger.error(f"🚫 Write permission denied for the Trust store directory '{args.trust_store}'.")
        sys.exit(1)
        
        
    config_file = '/etc/ssl-tunnel/config.json'
    if not os.path.exists(config_file):
        logger.error(f"❌ SSL Tunnel config file '{config_file}' does not exist.")
        sys.exit(1)
        
    try:
        with open(config_file) as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f'❗ config file open error: {e}')
        sys.exit(1)
        
    server_cert_file = config.get('server', {}).get('cert_file', None)
    if server_cert_file is None:
        logger.error(f'❌ server certificate does not exist. Please initalize server using "init-server" command')
        sys.exit(1)
                
    server_address = args.server_address
    name = args.name.replace(' ', '_')

    if server_address.lower() == 'auto':
        try:
            public_ip = get_public_ip()
            fqdn = resolve_fqdn(public_ip)
            if fqdn:
                server_address = fqdn
            else:
                raise ValueError("FQDN resolution failed.")
        except Exception as e:
            logger.error(f"❗ Error: {e}")
            logger.info("🙏 Please provide a FQDN or IP address manually using the --server-address option.")
            return

    try:        
        
        if check_conflict_in_common_name(name, args.trust_store):
            if not args.overwrite:
                raise ValueError(f'A client with the common name "{name}" already exists in the trust store. Use the "--overwrite" option if necessary.')
            else:
                logger.info(f'🔄 A client with the common name "{name}" already exists in the trust store, but will be overwritten.')

        with tempfile.TemporaryDirectory() as temp_dir:
            client_key = SSLCertificate.create_key_pair()
            client_cert = SSLCertificate.create_self_signed_certificate(client_key, name, days=args.days)

            client_cert_path = Path(temp_dir) / 'client.pem'
            client_key_path = Path(temp_dir) / 'client.key'

            # Save client certificate and key
            with open(client_cert_path, 'wb') as f:
                f.write(client_cert.public_bytes(serialization.Encoding.PEM))
            with open(client_key_path, 'wb') as f:
                f.write(client_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()))

            # Copy the client certificate to the server's trust-store
            shutil.copy(client_cert_path, Path(args.trust_store) / client_cert_path.name)
                    
            # Create client config
            client_config = {
                "client": {
                    "server_address": server_address,
                    "server_port": args.server_port,
                    "operation_mode": args.operation_mode,
                    "cert_file": '/etc/ssl-tunnel/client.pem',
                    "key_file": '/etc/ssl-tunnel/client.key'
                }
            }

            config_path = Path(temp_dir) / 'config.json'
            with open(config_path, 'w') as f:
                json.dump(client_config, f, indent=4)

            # Create a tar.gz file
            tar_gz_file_path = Path(args.output_dir) / f'{name}_setup.tar.gz'
            with tarfile.open(tar_gz_file_path, "w:gz") as tar:
                tar.add(client_cert_path, arcname='client.pem')
                tar.add(client_key_path, arcname='client.key')
                tar.add(config_path, arcname='config.json')
                tar.add(server_cert_file, arcname='server.pem')

            logger.info(f'🖥️  Server address: "{server_address}:{args.server_port}" has been included in the client profile.')
            logger.info(f'👌 Client profile for "{name}" has been created and archived into "{tar_gz_file_path}".')
            logger.info("👏 The new client certificate has been copied to the server's trust store.")

    except Exception as e:
        logger.error(f'❌ Client profile creation error: {e}')
        sys.exit(1)
        
def client_load_cmd(args):
    ssl_tunnel_dir = Path('/etc/ssl-tunnel')
    trust_store_dir = ssl_tunnel_dir / 'trust-store'

    # Ensure SSL tunnel directories exist
    ssl_tunnel_dir.mkdir(parents=True, exist_ok=True)
    trust_store_dir.mkdir(parents=True, exist_ok=True)

    # List of valid file names to extract and move
    valid_files = ['client.pem', 'client.key', 'config.json', 'server.pem']

    # Extract files from the tar.gz file to a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        with tarfile.open(args.file, 'r:gz') as tar_ref:
            tar_ref.extractall(temp_dir)

        # Move extracted files to their respective directories
        for file_name in os.listdir(temp_dir):
            src_path = Path(temp_dir) / file_name
            if file_name in valid_files:
                dest_dir = ssl_tunnel_dir if file_name != 'server.pem' else trust_store_dir
                dest_path = dest_dir / file_name
                if not move_file(src_path, dest_path, args.overwrite):
                    logger.error(f"❌ Error exporting {file_name} to {dest_path}")                    
                    return

    logger.info(f"👌 Client configuration and certificates have been successfully extracted and set up.")


