import ipaddress
import os
import fcntl
import socket
import struct
import threading
import time
import sys

try:
    from pyroute2 import IPRoute
except Exception as e:
    sys.exit(f'❌ Module import Error: {e}')

from ..utils.logging_config import logger

class TunInterface:
    lock = threading.Lock()  # A lock for synchronizing access

    def __init__(self, name, cidr, operation_mode='3', mac=None):
        self.name = name
        self.cidr = cidr
        self.operation_mode = 2 if operation_mode == '2' else 3

        self.mac_address = mac

        self.nl_ip = None
        self.nl_idx = None
        self.nl_link = None

        if self.cidr:
            interface = ipaddress.ip_interface(cidr)
            self.ip = ipaddress.ip_address(interface.ip) 
            self.network = interface.network
        else:
            self.network = ipaddress.ip_network('255.255.255.255/32')
            self.ip = None

        self.fd = self.create_tun_interface()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete_tun_interface()
        if self.fd:
            os.close(self.fd)

    def write(self, data):
        with self.lock:
            os.write(self.fd, data)

    def check_for_duplicate_cidr(self, cidr):
        if self.nl_ip:
            target_network = ipaddress.ip_network(cidr, strict=False)
            for interface in self.nl_ip.get_links():
                interface_name = interface.get_attr('IFLA_IFNAME')

                ip_addrs = self.nl_ip.get_addr(label=interface_name)
                for addr in ip_addrs:
                    current_ip = ipaddress.ip_address(addr.get_attr('IFA_ADDRESS'))
                    current_prefix_len = addr['prefixlen']

                    current_network = ipaddress.ip_network(f"{current_ip}/{current_prefix_len}", strict=False)
                    if current_network.network_address == target_network.network_address and \
                       current_network.prefixlen == target_network.prefixlen:
                        return interface_name
            return None
        else:
            raise Exception("❗ Netlink Iproute object not initialized")

    def cleanup_arp_cache(self):
        if self.nl_ip and self.nl_idx:
            neighbors = self.nl_ip.get_neighbours(ifindex=self.nl_idx)
            for neighbor in neighbors:
                # Check if the neighbor entry is IPv4
                if neighbor.get('family') == socket.AF_INET:
                    self.nl_ip.neigh('delete', dst=neighbor.get_attr('NDA_DST'), lladdr=neighbor.get_attr('NDA_LLADDR'), ifindex=self.nl_idx)

    def create_tun_interface(self):
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_TAP = 0x0002
        IFF_NO_PI = 0x1000

        flags = IFF_NO_PI
        if self.operation_mode == 3:
            flags |= IFF_TUN
        elif self.operation_mode == 2:
            flags |= IFF_TAP

        try:
            tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            ifr = struct.pack('16sH', self.name.encode(), flags)
            fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        except Exception as e:
            new_error_message = f"Tunnel interface: {str(e)} - could be a duplicated naming issue"
            raise type(e)(new_error_message) from None


        time.sleep(1)

        self.nl_ip = IPRoute()
        idx = self.nl_ip.link_lookup(ifname=self.name)
        
        if idx:
            self.nl_idx = idx[0]

            if self.cidr:
                duplicated_interface_name = self.check_for_duplicate_cidr(self.cidr)                    
                if duplicated_interface_name is not None:
                    raise Exception(f"Duplicate network found for {self.cidr} on {duplicated_interface_name}")
                
                self.nl_ip.addr('add', index=self.nl_idx, address=str(self.ip), mask=self.network.prefixlen)

            if self.operation_mode == 2:
                self.nl_link = self.nl_ip.get_links(self.nl_idx)[0]                
                if self.mac_address:
                    self.nl_ip.link('set', index=self.nl_idx, address=self.mac_address)
                else:
                    self.mac_address = self.nl_link.get_attr('IFLA_ADDRESS')

            self.nl_ip.link('set', index=self.nl_idx, state='up')
        else:
            logger.warning(f'🔔 Warning: Failed to configure {self.cidr} on tunnel interface {self.name}.')
        
        # The system tries to use an IP address that is in the same subnet as the target of the ARP request
        setting_path = f"/proc/sys/net/ipv4/conf/{self.name}/arp_announce"
        with open(setting_path, 'w') as f:
            f.write(str(1))

        return tun_fd

    def delete_tun_interface(self):
        if self.nl_ip:
            self.nl_ip.link('set', index=self.nl_idx, state='down')
            self.nl_ip.link('delete', index=self.nl_idx)
            self.nl_ip.close()
