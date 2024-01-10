
import os
import select
import socket
import ssl
import threading
import time

from .global_resources import *
from ..utils.logging_config import logger
from .network_protocol import IP

class SSLClient:
    lock = threading.Lock()  # A lock for synchronizing access

    def __init__(self, server_address, tun, trust_store, certfile, keyfile, keepidle, keepintvl, keepcnt, disable_auto_reconnect=False, no_auth=False):
        self.tun = tun
        self.server_address = server_address
        self.trust_store = trust_store
        self.certfile = certfile
        self.keyfile = keyfile
        self.retry_delay = 3
        self.keepidle = keepidle
        self.keepintvl = keepintvl
        self.keepcnt = keepcnt
        self.disable_auto_reconnect = disable_auto_reconnect
        self.no_auth = no_auth

    def create_ssl_client_socket(self):
        try:
            context = ssl.create_default_context()
            if not self.no_auth:
                context.check_hostname = False
                context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                context.load_verify_locations(cafile=None, capath=self.trust_store)
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            address = self.server_address[0]
            port = self.server_address[1]

            i = 0
            while not shutdown_event.is_set():
                try:
                    socket.setdefaulttimeout(self.retry_delay)
                    sock = socket.create_connection(self.server_address)
                    sock.settimeout(None)
                    socket.setdefaulttimeout(None)
                    
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, self.keepidle)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.keepintvl)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, self.keepcnt)
                    server_hostname = address

                    ssock = context.wrap_socket(sock, server_hostname=server_hostname)
                    logger.info(f"🔗 SSL client established connection with {address}:{port}... Press CTRL+C to exit.")

                    return ssock
                except Exception as e:
                    if i < 3:
                        logger.error(f'❗ Error connecting to {address}:{port}: {e}. Retrying in {self.retry_delay} seconds...')
                        time.sleep(self.retry_delay)
                        i += 1
                    else:
                        return None

        except Exception as e:
            logger.error(f'❗ Error creating ssl session: {e}')
            return None

    def handle_ssl_session_data(self, ssl_sock):
        try:
            ssl_sock.do_handshake(block=True)
            server_ip, server_port = ssl_sock.getpeername()
            time.sleep(3)
        except Exception as e:
            logger.error(f"❗ SSL handshake error: {e}")
            return

        while not shutdown_event.is_set():
            try:
                try:
                    r, _, _ = select.select([ssl_sock], [], [], 1)
                    if not r:
                        continue

                    data = ssl_sock.recv(65535)

                except socket.timeout:
                    # Continue in case of a timeout
                    continue  
                except BlockingIOError as e:
                    # Handle the case when the resource is temporarily unavailable.
                    # This section could be used to pause or yield the processor.
                    # Opting to let it continue, expecting more data to arrive later.
                    # logger.info(f'🔔 Warning: BlockingIOError encountered with SSL server ({server_ip}:{server_port}): {e}')
                    continue
                except Exception as e:
                    logger.error(f"❗ SSL server ({server_ip}:{server_port}) connection error: {e}")
                    break

                if not data:
                    logger.info('🛑 SSL client socket is closed')
                    break

                if self.tun.operation_mode == 3:
                    if not IP.is_valid(data):
                        continue

                try:

                    self.tun.write(data)

                except Exception as e:
                    logger.error(f"🛑 TUN/TAP interface is closed: {e}")
                    break

            except Exception as e:
                logger.error("❗ Error in SSL thread: {e}")
                break

    def handle_tun_port_data(self):
        ssl_sock = self.create_ssl_client_socket()
        if ssl_sock is None:
            return

        ssl_client_thread = threading.Thread(target=self.handle_ssl_session_data, args=(ssl_sock,), daemon=True)
        ssl_client_thread.start()

        try:
            while not shutdown_event.is_set() and ssl_client_thread.is_alive():

                ready_to_read, ready_to_write, _ = select.select([self.tun.fd], [ssl_sock], [], 1)

                if self.tun.fd in ready_to_read:
                    try:
                        data = os.read(self.tun.fd, 65535)
                    except Exception as e:
                        logger.error(f'❗ Error: TUN/TAP interface: {e}')
                        break

                    if not data:
                        logger.info('🛑 Tun/Tap interface is closed.')
                        break

                    if self.tun.operation_mode == 3:
                        if not IP.is_valid(data):
                            continue

                    if ssl_sock in ready_to_write:
                        with self.lock:
                            ssl_sock.sendall(data)
                    else:
                        pass

        except Exception as e:
            logger.info(f'🛑 SSL socket is closed: {e}')
        finally:
            ssl_sock.close()

