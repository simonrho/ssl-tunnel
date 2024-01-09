import ipaddress


class Ethernet:
    def __init__(self, frame):
        if len(frame) < 14:
            raise Exception("Ethernet frame length is shorter")
        
        self.dst_mac = frame[0:6]
        self.src_mac = frame[6:12]
        self.eth_type = ((frame[12] << 8) & 0xff00)| frame[13]
        self.payload = frame[14:]

    def is_broadcast(self):
        return self.dst_mac == b'\xff\xff\xff\xff\xff\xff'

    def is_multicast(self):
        # Check if the least significant bit of the first byte is 1
        return (self.dst_mac[0] & 1) == 1

    def is_arp(self):
        return self.eth_type == 0x0806

    def is_ipv4(self):
        return self.eth_type == 0x0800

class ARP:
    def __init__(self, packet):
        if len(packet) < 28:
            raise Exception("Arp packet length is shorter")
        
        self.opcode = int.from_bytes(packet[6:8], 'big')
        self.sender_mac = packet[8:14]
        self.sender_ip = ipaddress.ip_address(packet[14:18])
        self.target_mac =packet[18:24]
        self.target_ip = ipaddress.ip_address(packet[24:28])

    def is_request(self):
        return self.opcode == 1

    def is_reply(self):
        return self.opcode == 2

    def is_garp_reply(self):
        return self.is_reply() and self.sender_ip == self.target_ip


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

class MAC:
    def __init__(self, mac):
        if isinstance(mac, bytes):
            self.mac = mac
        else:
            self.mac = bytes.fromhex(mac.replace(':', ''))

    def __str__(self):
        return ':'.join(f'{byte:02x}' for byte in self.mac)

class ROUTE:
    def __init__(self, ip, prefix_length=32):
        self.ip = ip
        self.prefix_length = prefix_length
        self.prefix = ((int(ip) & 0xffffffff << (32-prefix_length)) << 8) | prefix_length
        
    def __str__(self):
        route = ipaddress.ip_address(self.prefix >> 8)
        return f'{route}/{self.prefix & 0xff}'

