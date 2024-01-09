import argparse
import ipaddress
import os
import re
import sys

try:
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend

except Exception as e:
    sys.exit(f'❌ Module import Error: {e}')

def valid_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return s
    except ValueError:
        raise argparse.ArgumentTypeError("Address must be a valid CIDR notation")

def validate_file(filename, file_type=None):
    if any(arg in sys.argv for arg in ['--no-auth', 'init', 'load']):
        return filename
       
    if not os.path.isfile(filename):
        raise argparse.ArgumentTypeError(f"The file {filename} does not exist.")

    try:
        with open(filename, 'rb') as f:
            file_content = f.read()

        if file_type == 'cert':
            load_pem_x509_certificate(file_content, backend=default_backend())
        elif file_type == 'key':
            load_pem_private_key(file_content, password=None, backend=default_backend())

    except Exception as e:
        raise argparse.ArgumentTypeError(f"The file {filename} is not a valid {file_type} file: {e}")

    return filename

def validate_path(path):
    if any(arg in sys.argv for arg in ['--no-auth', 'init', 'load']):
        return path
    
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"The trust store directory {path} does not exist.")
    return path
    
def validate_prefix_length(value):
    min_val, max_val = 8, 32
    try:
        ivalue = int(value)
        if ivalue < min_val or ivalue > max_val:
            raise argparse.ArgumentTypeError(f"Prefix length must be between {min_val} and {max_val}.")
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"Prefix length must be an integer between {min_val} and {max_val}.")

def is_valid_mac_address(value):
    """ Validate the MAC address format. """

    # Check for valid MAC address format
    if not re.match("[0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$", value):
        raise argparse.ArgumentTypeError(f"Invalid MAC address format: {value}")

    # Check for broadcast MAC address
    if value.lower() == "ff:ff:ff:ff:ff:ff":
        raise argparse.ArgumentTypeError("Broadcast MAC address (FF:FF:FF:FF:FF:FF) is not allowed")

    # Check for multicast MAC address
    if re.match("[13579bdfBDF][0-9a-fA-F]([-:])([0-9a-fA-F]{2}\\1){4}[0-9a-fA-F]{2}", value):
        raise argparse.ArgumentTypeError("Multicast MAC address is not allowed")

    # Check for all-zero MAC address
    if value == "00:00:00:00:00:00":
        raise argparse.ArgumentTypeError("All-zero MAC address (00:00:00:00:00:00) is not allowed")

    return value

# Helper function to check if a file exists
def check_file_exists(file_path, file_description):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The specified {file_description} '{file_path}' does not exist.")

# Helper function to validate CA certificate and key files
def validate_ca_files(ca_cert_path, ca_key_path):
    try:
        with open(ca_cert_path, 'rb') as f:
            load_pem_x509_certificate(f.read(), backend=default_backend())

    except Exception as e:
        raise ValueError(f"Validation failed for CA certificate file '{ca_cert_path}': {e}")
    
    try:
        with open(ca_key_path, 'rb') as f:
            load_pem_private_key(f.read(), password=None, backend=default_backend())
    except Exception as e:
        raise ValueError(f"Validation failed for CA key file '{ca_key_path}': {e}")
