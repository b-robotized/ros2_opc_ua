# Server Certificates

This folder contains self-signed certificates and keys for the `example_opcua_server` to enable `Sign` and `SignAndEncrypt` security policies.

## Files

- `server_cert.der`: The server's X.509 certificate in DER format.
- `server_key.der`: The server's private key in DER format.
- `server_cert.pem` / `server_key.pem`: PEM versions (intermediate files used for generation).

## How to generate new certificates

You can regenerate these certificates using OpenSSL:

```bash
# 1. Generate PEM certificate and private key
openssl req -x509 -newkey rsa:2048 \
  -keyout server_key.pem \
  -out server_cert.pem \
  -days 365 -nodes \
  -subj "/CN=ros2_opc_ua example server/O=ROS 2/C=DE"

# 2. Convert Certificate to DER format
openssl x509 -outform der -in server_cert.pem -out server_cert.der

# 3. Convert Private Key to DER format
openssl rsa -outform der -in server_key.pem -out server_key.der
```

## How to use with example_opcua_server

To enable security policies (Sign/SignAndEncrypt), pass the paths to the DER files as ROS 2 parameters:

```bash
ros2 run opcua_bringup example_opcua_server --ros-args \
    -p security.policy:=Sign \
    -p security.certificate_path:=$(ros2 pkg prefix opcua_bringup)/share/opcua_bringup/config/server_cert.der \
    -p security.private_key_path:=$(ros2 pkg prefix opcua_bringup)/share/opcua_bringup/config/server_key.der
```

**Note:** Ensure you have installed the config folder or reference the source path if running from source without install rules for this folder.

If running from the source directory directly:

```bash
ros2 run opcua_bringup example_opcua_server --ros-args \
    -p security.policy:=Sign \
    -p security.certificate_path:=./src/ros2_opc_ua/opcua_bringup/config/server_cert.der \
    -p security.private_key_path:=./src/ros2_opc_ua/opcua_bringup/config/server_key.der
```
