#!/usr/bin/env python3

import platform
import pprint
import signal

from .core.ssl_server import *
from .core.ssl_client import *
from .core.tun_interface import *
from .core.flow_and_route_manager import *
from .core.global_resources import *
from .core.cli import *

from .utils.certificate_management import *
from .utils.validators import *
from .utils.logging_config import logger

try:
    from cryptography.hazmat.primitives import serialization
except Exception as e:
    exit(f'❌ Module import Error: {e}')

def print_mode_info(args):
    if args.command in ['server', 'client']:
        m = f' The SSL Tunnel {args.command.capitalize()} starts '
        logger.info('*' * len(m))
        logger.info(m)  
        logger.info('*' * len(m))
      
        auth_mode = 'no auth' if args.no_auth else 'auth'
        logger.info(f'🚀 Running on the {auth_mode} mode in {args.operation_mode} operation')
        
    vs = pprint.pformat(vars(args))
    logger.info(f'🚚 Execute CLI command("{args.command}") and args:\n{vs}', console=False)

def signal_handler(sig, frame):
    if not shutdown_event.is_set():
        shutdown_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    if sys.version_info < (3, 7):
        logger.error("🐍✋ Hold up! Python 3.7 or higher is required to run this program.")
        sys.exit(1)

    if not platform.system() == 'Linux':
        logger.error("🐧🚫 Whoops! This script is exclusively designed for Linux.")
        sys.exit(1)

    args = parse_args()
            
    if args.command == 'server':
        if args.server_command == 'init':
            ssl_tunnel_init_cmd(DEFAULT_CONFIG_SERVER, args.overwrite)
        elif args.server_command == 'create-client':
            server_create_client_cmd(args)
            print()
        else:
            print_mode_info(args)
            
            SSLCertificate.c_rehash(args.trust_store)
            SSLCertificate.rehash_start(args.trust_store)
            
            if not args.no_auth:
                if not args.cert_file or not args.key_file:
                    logger.error("❗ Error: --cert-file and --key-file must be provided unless --no-auth is specified.")
                    sys.exit(1)

            flow_and_route_manager = FlowAndRouteManager()

            try:
                with TunInterface(args.tun_name, args.tun_address, args.operation_mode, args.mac) as tun:
                    ssl_server = SSLServer(
                        (args.listen_address, args.listen_port),
                        args.trust_store,
                        args.cert_file,
                        args.key_file,
                        tun,
                        args.max_clients,
                        args.keepalive_idle,
                        args.keepalive_interval,
                        args.keepalive_count,
                        args.max_clients,
                        args.route_prefix_length,
                        flow_and_route_manager,
                        args.route_suppress,
                        args.no_flood,
                        no_auth=args.no_auth                    
                    )
                    threading.Thread(target=ssl_server.start, daemon=True).start()
                    ssl_server.handle_tun_port_data()
            except Exception as e:
                logger.error(f"❗ An error occurred: {e}")
            finally:
                shutdown_event.set()
                flow_and_route_manager.session_cleanup()
                logger.info("\n🅿️  SSL server stopped.")

    elif args.command == 'client':
        if args.client_command == 'load':
            client_load_cmd(args)
            print()
        elif args.client_command == 'init':
            ssl_tunnel_init_cmd(DEFAULT_CONFIG_CLIENT, args.overwrite)
            print()
        elif args.client_command == 'start':
            
            if not args.server_address:
                logger.error('🤔 Oops! The option "--server-address" is missing.')
                sys.exit(1)
            
            print_mode_info(args)
            
            SSLCertificate.c_rehash(args.trust_store)
            SSLCertificate.rehash_start(args.trust_store)
            
            if not args.no_auth:
                if not args.cert_file or not args.key_file:
                    logger.error("❗ Error: --cert-file and --key-file must be provided unless --no-auth is specified.")
                    sys.exit(1)
            
            try:        
                with TunInterface(args.tun_name, args.tun_address, args.operation_mode) as tun:
                    ssl_client = SSLClient(
                        (args.server_address, args.server_port), 
                        tun,
                        args.trust_store,                    
                        args.cert_file,
                        args.key_file,
                        args.keepalive_idle, 
                        args.keepalive_interval, 
                        args.keepalive_count,
                        args.disable_auto_reconnect,
                        no_auth=args.no_auth                    
                    )

                    while not shutdown_event.is_set():
                        if args.operation_mode == 'l2':
                            tun.cleanup_arp_cache()
                            
                        ssl_client.handle_tun_port_data()
                        
                        if not shutdown_event.is_set() and not args.disable_auto_reconnect:
                            logger.info('🔄 Auto reconnecting to the SSL server...')
                            time.sleep(3)
                        else:
                            break
                    
            except Exception as e:
                logger.error(f"❗ An error occurred: {e}")
            finally:
                shutdown_event.set()
                logger.info("🅿️  SSL client stopped.")

    elif args.command == 'certificate':
        cert_key = SSLCertificate.create_key_pair(key_size=args.key_size)
        subject_fields = {
            'COUNTRY_NAME': args.country_name,
            'STATE_OR_PROVINCE_NAME': args.state_name,
            'LOCALITY_NAME': args.locality_name,
            'ORGANIZATION_NAME': args.organization_name,
            'ORGANIZATIONAL_UNIT_NAME': args.organizational_unit_name
        }
        cert = SSLCertificate.create_self_signed_certificate(cert_key, args.cert_name, days=args.days, subject_fields=subject_fields)

        # Write certificate key and certificate to files
        with open(args.key_out_file, 'wb') as f:
            f.write(cert_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

        with open(args.cert_out_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(f"📜 Self-signed certificate created: {args.cert_out_file}")
        logger.info(f"🔑 Certificate key created: {args.key_out_file}")
        logger.info("🏁 Note: ")
        logger.info("   🔒 Secure your certificate and key files!")
        logger.info("   🛡️ Ensure that they are stored in a secure, access-controlled location,")
        logger.info("   💾 and are backed up appropriately.\n")

if __name__ == '__main__':
    main()