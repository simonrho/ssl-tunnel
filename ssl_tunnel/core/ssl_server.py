import ipaddress
import os
import select
import socket
import ssl
import sys
from threading import Semaphore
import threading
import time

from ..utils.logging_config import logger
from .network_protocol import Ethernet, ARP, IP, ROUTE
from .global_resources import shutdown_event

class ThreadSafeSSLSocket:
    def __init__(self, wrapped_socket):
        self._wrapped_socket = wrapped_socket
        self._send_lock = threading.Lock()

    def sendall(self, data, *args, **kwargs):
        with self._send_lock:
            return self._wrapped_socket.sendall(data, *args, **kwargs)

    # Delegate other attribute accesses to the wrapped socket
    def __getattr__(self, attr):
        return getattr(self._wrapped_socket, attr)

class SSLServer:
    def __init__(self, address, trust_store, certfile, keyfile, tun, max_clients, 
                keepidle, keepintvl, keepcnt, max_incoming_connection, 
                route_prefix_length, flow_and_route_manager, route_suppress=False, no_flood=False, no_auth=False):
        self.address = address
        self.trust_store = trust_store
        self.certfile = certfile
        self.keyfile = keyfile
        self.tun = tun
        self.max_clients = max_clients
        self.keepidle = keepidle
        self.keepintvl = keepintvl
        self.keepcnt = keepcnt
        self.max_incoming_connection = max_incoming_connection
        self.route_prefix_length = route_prefix_length
        self.flow_and_route_manager = flow_and_route_manager
        self.route_suppress=route_suppress
        self.no_flood = no_flood
        self.no_auth = no_auth


    def start(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.load_verify_locations(cafile=None, capath=self.trust_store)

        if not self.no_auth:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
                  
        semaphore = Semaphore(self.max_clients)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, self.keepidle)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.keepintvl)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, self.keepcnt)
            try:
                sock.bind(self.address)
            except Exception as e:
                logger.error(f"❗ SSL Server Listen Address ({self.address[0]}:{self.address[1]}) Binding error: {str(e)}")
                shutdown_event.set()
                sys.exit(1)
            
            sock.listen(self.max_incoming_connection)
            logger.info(f"🏃 SSL server is running on {self.address[0]}:{self.address[1]}... Press CTRL+C to exit.")

            while not shutdown_event.is_set():

                readable, _, _ = select.select([sock], [], [], 1)

                if sock in readable:
                    try:
                        client_sock, addr = sock.accept()
                        
                        logger.info(f"🔗 SSL client ({addr[0]}:{addr[1]}) is connected.")
                        
                        connection = context.wrap_socket(client_sock, server_side=True)
                        thread_safe_connection = ThreadSafeSSLSocket(connection)
                        threading.Thread(target=self.handle_ssl_session_data, args=(thread_safe_connection, self.tun, semaphore, self.route_prefix_length), daemon=True).start()
                    except socket.error as e:
                        logger.error(f"❗ Socket error: {e}")
                        continue

    def handle_ssl_session_data(self, connection, tun, semaphore, route_prefix_length=32):
        arp_table = {}
        nexthop_table = {}
        route_table = {}
        client_ip, client_port = None, None
        try:
            semaphore.acquire()
            try:
                connection.do_handshake(block=True)
                client_ip, client_port = connection.getpeername()
                time.sleep(3)
            except Exception as e:
                logger.error(f"❗ SSL handshake error: {e}")
                return

            self.flow_and_route_manager.add_connection(connection)


            while not shutdown_event.is_set():
                try:
                    r, _, _ = select.select([connection], [], [], 1)
                    if not r:
                        continue
                    
                    data = connection.recv(65535)

                except socket.timeout:
                    # Continue in case of a timeout
                    continue

                except BlockingIOError as e:
                    # Handle the case when the resource is temporarily unavailable.
                    # This section could be used to pause or yield the processor.
                    # Opting to let it continue, expecting more data to arrive later.
                    # logger.info(f'🔔 Warning: BlockingIOError encountered with SSL client ({client_ip}:{client_port}): {e}')
                    continue

                except ssl.SSLError as e:
                    logger.error(f"❗ SSL error with SSL client ({client_ip}:{client_port}): {e}")
                    break

                except Exception as e:
                    logger.error(f"❗ SSL client ({client_ip}:{client_port}) connection error: {e}")
                    break

                if not data:
                    logger.error(f"❗ SSL client ({client_ip}:{client_port}) is disconnected.")
                    break

                if tun.operation_mode == 3:
                    if IP.is_valid(data):
                        try:
                            ip = IP(data)
                        except Exception as e:
                            continue
                        
                        if ip.src not in self.flow_and_route_manager.flow_table:
                            self.flow_and_route_manager.flow_table[ip.src] = connection
                            if not self.route_suppress:
                                if ip.src not in self.tun.network:
                                    prefix = ROUTE(ip.src, route_prefix_length)
                                    if prefix not in route_table:
                                        route_table[prefix] = tun
                                        self.flow_and_route_manager.host_add_route(prefix, tun)

                    try:
                        
                        tun.write(data)

                    except Exception as e:
                        logger.error("❗ Error writing to the TUN interface from SSL client ({client_ip}:{client_port}): {e}")
                        break
                else:
                    # L2 operation mode
                    try:
                        frame = Ethernet(data)
                    except Exception as e:
                        continue

                    if frame.src_mac not in self.flow_and_route_manager.flow_table:
                        self.flow_and_route_manager.flow_table[frame.src_mac] = connection

                    if frame.is_arp():
                        try:
                            arp = ARP(frame.payload)
                        except Exception as e:
                            continue
                        
                        if arp.is_request():
                            if arp.sender_ip in self.tun.network and arp.sender_ip not in arp_table:
                                arp_table[arp.sender_ip] = arp.sender_mac
                                nexthop_table[arp.sender_mac] = arp.sender_ip

                    elif not self.route_suppress and frame.is_ipv4():
                        try:
                            ip = IP(frame.payload)
                        except Exception as e:
                            continue
                        
                        if ip.src not in self.tun.network:
                            prefix = ROUTE(ip.src, route_prefix_length)
                            if prefix not in route_table:
                                nexthop = nexthop_table.get(frame.src_mac, None)
                                if nexthop:
                                    route_table[prefix] = nexthop
                                    self.flow_and_route_manager.host_add_route(prefix, tun, nexthop)

                    try:

                        tun.write(data)

                    except Exception as e:
                        logger.error("❗ Error writing to the TAP interface from SSL client ({client_ip}:{client_port}): {e}")
                        break

        finally:
            flow_count = self.flow_and_route_manager.flow_table.remove_by_value(connection)
            self.flow_and_route_manager.remove_connection(connection)

            routes = set(route_table.keys())   
            route_count = len(routes)
            for route in routes:
                self.flow_and_route_manager.host_remove_route(route)
            
            if client_ip and client_port:
                logger.info(f'🗑️ SSL client ({client_ip}:{client_port}) {flow_count} flows, {route_count} routes have been removed.')

            logger.info(f'🚫 SSL client ({client_ip}:{client_port}) has closed the connection')

            connection.close()
            semaphore.release()

    def handle_tun_port_data(self):
        while not shutdown_event.is_set():
            r, _, _ = select.select([self.tun.fd], [], [], 1)
            if not r:
                continue

            try:
                data = os.read(self.tun.fd, 65535)
            except Exception as e:
                logger.error(f'❗ Error: TUN/TAP interface: {e}')
                break

            if not data:
                break

            if self.tun.operation_mode == 3:
                packet = data
                if packet and IP.is_valid(packet):
                    dst_ip = ipaddress.ip_address(packet[16:20])
                    client = self.flow_and_route_manager.flow_table.get(dst_ip, None)
                    if client:
                        try:
                            client.sendall(packet)
                        except Exception as e:
                            continue
                    elif not self.no_flood:
                        self.flow_and_route_manager.flood_broadcast(data)
            else:
                # L2 operation mode
                try:
                    frame = Ethernet(data)
                except Exception as e:
                    continue

                # If no_flood is False and the frame is either broadcast or multicast, flood broadcast
                if not self.no_flood and (frame.is_broadcast() or frame.is_multicast()):
                    self.flow_and_route_manager.flood_broadcast(data)
                else:
                    client = self.flow_and_route_manager.flow_table.get(frame.dst_mac, None)
                    if client:
                        try:
                            client.sendall(data)
                        except Exception as e:
                            continue
                    elif not self.no_flood:
                        self.flow_and_route_manager.flood_broadcast(data)

