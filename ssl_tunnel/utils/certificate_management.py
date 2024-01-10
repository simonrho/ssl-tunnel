import os
import subprocess
import sys


try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes    
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    
    import datetime

    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent

    from ..utils.logging_config import logger

except Exception as e:
    sys.exit(f'❌ Module import Error: {e}')


class SSLCertificate:
    @staticmethod
    def create_key_pair(key_size=2048):
        # Generate a private key
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()              
        )

    @staticmethod
    def create_self_signed_certificate(key, name, days=365, subject_fields=None):
        # Create a self-signed certificate
        try:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, name),
            ] + ([x509.NameAttribute(getattr(NameOID, field), value) for field, value in (subject_fields or {}).items()]))
            
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
            )
            
            cert = builder.sign(key, hashes.SHA256(), default_backend()) 
            return cert
        except Exception as e:
            sys.exit(f'❗ self-signed certificate generation error:{e}')


    class PEMFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            if isinstance(event, FileCreatedEvent) and event.src_path.endswith('.pem'):
                logger.info(f"🔍 New .pem file detected: {event.src_path}", console=False)
                SSLCertificate.c_rehash(os.path.dirname(event.src_path))

    @staticmethod
    def c_rehash(cert_directory):
        command = ["c_rehash", cert_directory]
        subprocess.run(command, capture_output=True, text=True)
        
    @staticmethod
    def rehash_start(path):
        event_handler = SSLCertificate.PEMFileHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=False)
        observer.start()
        

