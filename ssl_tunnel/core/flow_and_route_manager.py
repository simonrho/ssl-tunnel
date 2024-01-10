

# BiMap class
from collections import defaultdict
import socket
import sys
import threading

try:
    from pyroute2 import IPDB
except Exception as e:
    sys.exit(f'❌ Module import Error: {e}')

from ..utils.logging_config import logger

class BiMap:
    def __init__(self):
        self.dict = {}  # Key to value mapping
        self.value_to_key = defaultdict(set)  # Value to keys mapping
        self.lock = threading.Lock()  # A lock for synchronizing access

    def __setitem__(self, key, value):
        with self.lock:
            if key in self.dict and self.dict[key] == value:
                return

            if key in self.dict:
                old_value = self.dict[key]
                self.value_to_key[old_value].discard(key)
                if not self.value_to_key[old_value]:
                    del self.value_to_key[old_value]

            self.dict[key] = value
            self.value_to_key[value].add(key)

    def remove_by_value(self, value):
        with self.lock:
            keys = list(self.value_to_key[value])
            n = len(keys)
            for key in keys:
                del self.dict[key]
            del self.value_to_key[value]
            return n

    def __delitem__(self, key):
        with self.lock:
            value = self.dict.pop(key, None)
            if value is not None:
                self.value_to_key[value].discard(key)
                if not self.value_to_key[value]:
                    del self.value_to_key[value]

    def __getitem__(self, key):
        with self.lock:
            return self.dict[key]

    def __contains__(self, key):
        with self.lock:
            return key in self.dict

    def get(self, key, default=None):
        with self.lock:
            return self.dict.get(key, default)

    def get_keys_by_value(self, value):
        with self.lock:
            return list(self.value_to_key.get(value, set()))

    def keys(self):
        with self.lock:
            return list(self.dict.keys())

    def unique_values(self):
        with self.lock:
            return list(self.value_to_key.keys())
        
class FlowAndRouteManager:
    def __init__(self):
        self.flow_table = BiMap()
        self.active_connections = set()
        self.connection_lock = threading.Lock()

    def add_connection(self, connection):
        with self.connection_lock:
            self.active_connections.add(connection)

    def remove_connection(self, connection):
        with self.connection_lock:
            if connection in self.active_connections:
                self.active_connections.remove(connection)

    def host_add_route(self, route, tun, nexthop=None):
        route = str(route)

        with IPDB() as ipdb:
            if route not in ipdb.routes:
                try:
                    route_spec = {'dst': route}
                    if nexthop:
                        route_spec['gateway'] = str(nexthop)
                    else:
                        route_spec['oif'] = ipdb.interfaces[tun.name].index
                    ipdb.routes.add(route_spec).commit()
                except Exception as e:
                    if 'File exists' in str(e):
                        pass
                    else:
                        logger.warning(f'🔔 Warning: Failed to add a route({route}): {e}')
                    return False
        return True

    def host_remove_route(self, route):
        route = str(route)
        with IPDB() as ipdb:
            if route in ipdb.routes:
                try:
                    ipdb.routes[route].remove().commit()
                except Exception as e:
                    logger.warning(f'🔔 Warning: Failed to remove a route({route}): {e}')
                    return False
        return True

    def session_cleanup(self):
        for conn in self.flow_table.unique_values():
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except Exception as e:
                logger.error("❗ Error closing connection: {e}")

    def flood_broadcast(self, frame):
        with self.connection_lock:
            for client in self.active_connections:
                try:
                    client.sendall(bytes(frame))
                except Exception as e:
                    client_ip, client_port = client.getpeername()
                    logger.error(f'🛑 SSL client {client_ip}:{client_port} closed on the broadcast: {e}')

