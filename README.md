 # README for SSL Tunnel Tool

 ## Overview
 SSL Tunnel Tool is a Python-based utility for creating secure SSL tunnels. It can be used to set up SSL servers and clients for secure communication over untrusted networks. The tool supports both Layer 2 (Ethernet frames) and Layer 3 (IP packets) operation modes.

 ## Features
 - Secure SSL tunnel creation for servers and clients.
 - Support for both Layer 2 and Layer 3 operation modes.
 - Automatic certificate and configuration management.
 - Supports auto-reconnect for clients.
 - Logging and error handling capabilities.

 ## Installation Command
 Copy and paste the following command:
 ```bash
 pip install ssl-tunnel
 ```

 ## Usage

 ### Server Commands
 - Initialize the server with default settings and certificates:
   ```bash
   ssl_tunnel server init [--overwrite]
   ```
 - Create a client certificate and config:
   ```bash
   ssl_tunnel server create-client --name [CLIENT_NAME] [--days [DAYS]] [--server-address [ADDRESS]] [--server-port [PORT]] [--overwrite] [--output-dir [DIR]]
   ```
 - Start the SSL server:
   ```bash
   ssl_tunnel server start [OPTIONS]
   ```

 ### Client Commands
 - Initialize the client with default settings:
   ```bash
   ssl_tunnel client init [--overwrite]
   ```
 - Load, uncompress, and set up the client configuration from a `.gz` file:
   ```bash
   ssl_tunnel client load --file [FILE_PATH] [--overwrite]
   ```
 - Start the SSL client:
   ```bash
   ssl_tunnel client start [OPTIONS]
   ```

 ### Certificate Commands
 - Create a self-signed certificate:
   ```bash
   ssl_tunnel certificate --cert-name [NAME] --cert-out-file [OUT_FILE] --key-out-file [KEY_FILE] [--days [DAYS]] [--key-size [SIZE]] --common-name [COMMON_NAME] [OTHER_OPTIONS]
   ```

 ### Options
 - `[OPTIONS]` includes various flags and parameters that you can pass to customize the server or client. Refer to the script's help for more details:
   ```bash
   ssl_tunnel --help
   ```

 ## Logs
 Logs are stored in `/var/log/ssl-tunnel.log`. Make sure the script has the necessary permissions to create and write to this file.

 ## Note
 Ensure that all certificates and keys are securely stored and backed up. Proper access control should be maintained for sensitive files.

 ## Example

 ### A Linux Server Running the SSL Tunnel Server
 Initialize the server and generate default certificates and configurations:
 ```bash
 sudo ssl_tunnel server init
 ```
 Output:
 ```
 📜 Generated certificate: /etc/ssl-tunnel/server.pem
 🔑 Generated private key: /etc/ssl-tunnel/server.key
 👌 Created default configuration file: /etc/ssl-tunnel/config.json
 ```

 Create a client profile with a certificate and configuration:
 ```bash
 sudo ssl_tunnel server create-client --name client1 --output-dir ./
 ```
 Output:
 ```
 🖥️ Server address: "ec2-3-138-125-203.us-east-2.compute.amazonaws.com:443" has been included in the client profile.
 👌 Client profile for "client1" has been created and archived into "client1_setup.tar.gz".
 👏 The new client certificate has been copied to the server's trust store.
 ```

 Start the SSL Tunnel Server:
 ```bash
 sudo ssl_tunnel server start
 ```
 Output:
 ```
 ******************************
  The SSL Tunnel Server starts 
 ******************************
 📌 Running on the auth mode in l3 operation
 🚀 SSL server is running on 0.0.0.0:443... Press CTRL+C to exit.
 ```

 ### A Linux Server Running the SSL Tunnel Client
 Load the client configuration and certificates from a provided `.gz` file:
 ```bash
 sudo ssl_tunnel client load --file ./client1_setup.tar.gz
 ```
 Output:
 ```
 👌 Client configuration and certificates have been successfully extracted and set up.
 ```
