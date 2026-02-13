# OPC UA Bringup

This package provides tools and examples for bringing up OPC UA servers and clients in a ROS 2 environment.

## Example OPC UA Server

The `example_opcua_server` is a demonstration server that supports:
-   **Security Policies**: None, Sign, SignAndEncrypt.
-   **Authentication**: Anonymous, Username/Password, Certificate.
-   **Simulated Nodes**: Publishes simulated sensor data (scalar and array) and accepts commands.

### Running the Server

#### Option 1: Using ROS 2 Launch (Recommended)

This is the easiest way to start the server as it automatically handles the certificate paths.

```bash
# Start with default settings (Sign policy, Anonymous allowed)
ros2 launch opcua_bringup example_server.launch.xml

# Start with 'SignAndEncrypt' policy
ros2 launch opcua_bringup example_server.launch.xml security_policy:=SignAndEncrypt

# Disable Anonymous access
ros2 launch opcua_bringup example_server.launch.xml allow_anonymous:=false
```

#### Option 2: Using ROS 2 Run

You can run the executable directly, but you must provide the paths to the certificates if you use a secure policy.

**Note:** The certificates are installed in the `share/opcua_bringup/config` directory.

```bash
# Run with 'Sign' policy (adjust paths if you are running from source)
ros2 run opcua_bringup example_opcua_server --ros-args \
    -p security.policy:=Sign \
    -p security.certificate_path:=$(ros2 pkg prefix opcua_bringup)/share/opcua_bringup/config/server_cert.der \
    -p security.private_key_path:=$(ros2 pkg prefix opcua_bringup)/share/opcua_bringup/config/server_key.der
```

### Certificates

The server requires X.509 certificates for secure communication (`Sign` or `SignAndEncrypt`).
A set of self-signed certificates (valid for 100 years) is provided in the `config/` directory and is installed to `share/opcua_bringup/config/`.

If you need to regenerate them, see `config/README.md`.
