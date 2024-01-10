#!/usr/bin/env python3

import ipaddress
import os
import re
import select
import signal
import ssl
import sys
import struct
import time
import argparse
import socket
import subprocess
import threading

from array import array
from threading import Event

import logging
from logging.handlers import RotatingFileHandler
import sys

shutdown_event = Event()
stop_event = Event()

VERSION = '1.0'
L3 = 3
L2 = 2

class CustomLogger(logging.Logger):
    def __init__(self, name, log_file='/var/log/ssl-tunnel.log'):
        super().__init__(name)

        try:
            
            file_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)
            file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.addHandler(file_handler)
            
        except Exception as e:
            print(f'❌ Log setup error: {e}')
            sys.exit(1)

    def _log(self, level, msg, console, logfile, args, **kwargs):
        if console:
            print(msg)

        if logfile:
            super()._log(level, msg, args, **kwargs)

    def info(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.INFO, msg, console, logfile, args, **kwargs)

    def warning(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.WARNING, msg, console, logfile, args, **kwargs)

    def error(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.ERROR, msg, console, logfile, args, **kwargs)

    def critical(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.CRITICAL, msg, console, logfile, args, **kwargs)

    def debug(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.DEBUG, msg, console, logfile, args, **kwargs)


logger = CustomLogger('ssl-tunnel')


class IP:
    def __init__(self, packet):
        if len(packet) < 16:
            raise Exception("IP packet length is shorter")
        
        self.src = ipaddress.ip_address(packet[12:16])

    @staticmethod
    def is_valid(data):
        if len(data) < 4:
            return False
                
        vhl = data[0]
        length = (data[2] << 8)+ data[3]

        return vhl == 0x45 and length == len(data)

def create_udp_server(host, port, fib_table=''):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if fib_table:
            fib_id = get_fib_id(fib_table)
            if fib_id >= 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SETFIB, fib_id)
            else:
                logger.error(f'❌ fib_table name: {fib_table} -> fib id: {fib_id}')
                logger.warning(f'🚨 Failed to look up the FIB ID for "{fib_table}" - set to 0.')

        server_address = (host, port)
        sock.bind(server_address)
    except Exception as e:
        logger.error(f'❗ Error creating UDP socket: {e}')
        return None

    logger.info(f"🏃 UDP Server {host}:{port} is running...")

    return sock

def create_ssl_client_socket(host, port, no_auth, certfile, keyfile, cafile, retry_delay=3, keepidle=10, keepintvl=10, keepcnt=10, fib_table='default'):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        context = ssl.create_default_context()
        if not no_auth:
            context.check_hostname = False
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            context.load_verify_locations(cafile=cafile)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE


        i = 0
        while not shutdown_event.is_set():
            try:
                socket.setdefaulttimeout(retry_delay)                
                sock = socket.create_connection((host, port))
                sock.settimeout(None)                
                socket.setdefaulttimeout(None)

                if fib_table:
                    fib_id = get_fib_id(fib_table)
                    if fib_id >= 0:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SETFIB, fib_id)
                    else:
                        logger.error(f'❌ fib_table name: {fib_table} -> fib id: {fib_id}')
                        logger.warning(f'🚨 Failed to look up the FIB ID for "{fib_table}" - set to 0.')

                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, keepidle)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, keepintvl)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, keepcnt)

                ssock = context.wrap_socket(sock, server_hostname=host)
                logger.info(f'🔗 SSL tunnel client connects to "{host}:{port}"...')

                return ssock
            except Exception as e:
                if i < 3:
                    logger.error(f'❗ Error connecting to {host}:{port}: {e}. Retrying in {retry_delay} seconds...')
                    time.sleep(retry_delay)
                    i += 1
                else:
                    return None

    except Exception as e:
        logger.error(f'❗ Error creating SSL session: {e}')
        return None

def get_fib_id(fib_table):
    cmd = f'/usr/sbin/cli -c "show route forwarding-table table {fib_table} family inet summary extensive" '
    output = subprocess.check_output(cmd, shell=True).decode()

    pattern = r'\[Index (\d+)\]'
    match = re.search(pattern, output)

    if match:
        fib_id = int(match.group(1))
    else:
        fib_id = -1

    return fib_id

def create_raw_socket(fib_table=''):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if fib_table:
            fib_id = get_fib_id(fib_table)
            if fib_id >= 0:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SETFIB, fib_id)
            else:
                logger.warning(f'🚨 Warning: Failed to look up the FIB ID for "{fib_table}".')

        return s
    except Exception as e:
        logger.error(f"❗ Error creating raw socket: {e}")
        return None

def handle_ssl_socket(ssl_sock, raw_sock):
    # Set the SSL socket to non-blocking mode
    ssl_sock.setblocking(0)

    while not shutdown_event.is_set() and not stop_event.is_set():
        try:
            r, _, _ = select.select([ssl_sock], [], [], 1)
            if not r:
                continue

            try:
                packet = ssl_sock.recv(65535)
                
            except ssl.SSLWantReadError:
                # The operation did not complete (the same as EWOULDBLOCK)
                continue
            except ssl.SSLWantWriteError:
                # Write must be retried
                continue
            except ssl.SSLError as e:
                logger.error(f"SSL error: {e}")
                break

            if packet:
                if IP.is_valid(packet):
                    dst_ip_bytes = packet[16:20]
                    dst_ip = socket.inet_ntoa(dst_ip_bytes)
                    try:
                        raw_sock.sendto(packet, (dst_ip, 0))
                    except Exception as e:
                        logger.error(f"🛑 Raw socket is closed: {e}")
                        break
            else:
                logger.info('🛑 SSL socket is closed')
                break
        except Exception as e:
            logger.error(f"❗ Error in SSL thread: {e}")
            break

def handle_udp_socket(udp_sock, ssl_sock):
    while not shutdown_event.is_set() and not stop_event.is_set():
        try:
            if udp_sock.fileno() < 0:
                logger.error('🛑 UDP socket is invalid or closed')
                break
            
            r, _, _ = select.select([udp_sock], [], [], 1)
            if not r:                
                continue

            data, src_address = udp_sock.recvfrom(65535)

        except Exception as e:
            logger.error(f"🛑 UDP socket is closed: {e}")
            break

        dst_address = udp_sock.getsockname()

        packet = build_udp_packet(src_address, dst_address, data)
        try:
            ssl_sock.sendall(packet)
        except Exception as e:
            logger.error(f'🛑 SSL socket is closed: {e}')
            break

def build_udp_packet(src_address, dst_address, data):
    def checksum(data):
        if len(data) % 2 != 0:
            data += b'\0'

        s = sum(array('H', data))
        s = (s >> 16) + (s & 0xffff)  # Fold high into low
        s += s >> 16  # Add carry

        cs = ~s & 0xffff
        cs = ((cs >> 8) & 0x00ff) | ((cs << 8) & 0xff00)

        return cs

    def create_udp_header(src_ip, dst_ip, src_port, dest_port, data):
        udp_length = 8 + len(data)  # 8 bytes for UDP header, plus the length of the data

        # Create the UDP header with a zero checksum
        udp_header = struct.pack('!HHHH', src_port, dest_port, udp_length, 0)

        # Construct the IP pseudo-header
        source_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP

        pseudo_header = struct.pack('!4s4sBBH', source_ip, dest_ip, placeholder, protocol, udp_length)
        udp_checksum = checksum(pseudo_header + udp_header + data)
        udp_header = udp_header[:6] + struct.pack('!H', udp_checksum)
        return udp_header

    def create_ip_header(src_ip, dest_ip, data_length):
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45,               # version and header length
                                0,                  # Service Type
                                20 + data_length,   # total length: IP header is 20 bytes, plus the length of the data
                                54321,              # identification
                                0,                  # flags
                                64,                 # ttl
                                socket.IPPROTO_UDP, # protocol
                                0,                  # ip_checksum
                                src_ip,             # source IP
                                dest_ip)            # destination IP

        ip_checksum = checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

        return ip_header

    (src_ip, src_port) = src_address
    (dest_ip, dest_port) = dst_address

    udp_header = create_udp_header(src_ip, dest_ip, src_port, dest_port, data)
    ip_header = create_ip_header(src_ip, dest_ip, len(udp_header) + len(data))
    packet = ip_header + udp_header + data

    return packet

def validate_file(filename):
    if any(arg in sys.argv for arg in ['--no-auth', 'init', 'load']):
        return filename
       
    if not os.path.isfile(filename):
        raise argparse.ArgumentTypeError(f"The file {filename} does not exist.")

    return filename

def parse_args():
    parser = argparse.ArgumentParser(description="SSL Tunnel Server")
    parser.add_argument("--ssl-server-address", required=True, help="SSL server address")
    parser.add_argument("--ssl-server-port", default=443, type=int, help="SSL server port")
    parser.add_argument("--dhcp-server", required=True, help="DHCP server address")
    parser.add_argument("--dhcp-server-port", default=67, type=int, help="DHCP server port")
    parser.add_argument("--dhcp-routing-instance", default="default", help="Routing instance for the pseudo DHCP server")
    parser.add_argument("--ssl-routing-instance", default="default", help="Routing instance for the SSL client")
    parser.add_argument('--disable-auto-reconnect', action='store_true', default=False, help='Disable automatic reconnection if the SSL connection is closed')
    parser.add_argument('--no-auth', action='store_true', default=False, help='Run the client without SSL authentication')
    parser.add_argument('--cert-file', default='/var/etc/ssl-tunnel/client.pem', type=lambda f: validate_file(f), help='Certificate file for SSL client')
    parser.add_argument('--key-file', default='/var/etc/ssl-tunnel/client.key', type=lambda f: validate_file(f), help='Key file for SSL client')
    parser.add_argument('--ca-file', default='/var/etc/ssl-tunnel/server.pem', type=lambda f: validate_file(f), help='Certificate file for SSL server')

    return parser.parse_args()

def print_mode_info(args):
    m = ' The SSL Tunnel Client starts '
    logger.info('*' * len(m))
    logger.info(m)
    logger.info('*' * len(m))

    auth_mode = 'no auth' if args.no_auth else 'auth'
    logger.info(f'🚀 Running in {auth_mode} mode')

def signal_handler(sig, frame):
    logger.info('🚫 Ctrl-C pressed')
    if not shutdown_event.is_set():
        shutdown_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    logger.info(f'args: {sys.argv}', console=False)
    
    args = parse_args()
    ssl_server = args.ssl_server_address
    ssl_server_port = args.ssl_server_port
    dhcp_server = args.dhcp_server
    dhcp_server_port = args.dhcp_server_port
    ssl_routing_instance = args.ssl_routing_instance
    dhcp_routing_instance = args.dhcp_routing_instance

    print_mode_info(args)

    dhc_sock = create_udp_server(dhcp_server, dhcp_server_port, fib_table=dhcp_routing_instance)
    if dhc_sock is None:
        exit(1)

    raw_sock = create_raw_socket(fib_table=dhcp_routing_instance)
    if raw_sock is None:
        dhc_sock.close()
        exit(1)

    while not shutdown_event.is_set():
        ssl_sock = create_ssl_client_socket(ssl_server, ssl_server_port, args.no_auth, args.cert_file, args.key_file, args.ca_file, 3, fib_table=ssl_routing_instance)

        if ssl_sock is None:
            if not args.disable_auto_reconnect:
                logger.info('🔄 Auto-reconnecting to the SSL server...')
                time.sleep(3)
                continue
            else:
                logger.error('🏁 Exit')
                dhc_sock.close()
                raw_sock.close()
                sys.exit(1)

        stop_event.clear()

        udp_thread = threading.Thread(target=handle_udp_socket, args=(dhc_sock, ssl_sock), daemon=True)
        ssl_thread = threading.Thread(target=handle_ssl_socket, args=(ssl_sock, raw_sock), daemon=True)

        udp_thread.start()
        ssl_thread.start()

        while not shutdown_event.is_set() and not stop_event.is_set():
            if not udp_thread.is_alive():
                logger.info('🛑 UDP Server is terminated.')
                stop_event.set()

            if not ssl_thread.is_alive():
                logger.info('🛑 SSL Client is terminated.')
                stop_event.set()

            time.sleep(1)

        dhc_sock.close()
        raw_sock.close()
        ssl_sock.close()

        if not args.disable_auto_reconnect:
            logger.info('🔄 Auto-reconnecting to the SSL server...')
            time.sleep(3)
        else:
            logger.info('\n🅿️ Stopped the DHCP over SSL Tunnel')
            sys.exit(0)

if __name__ == "__main__":
    main()
