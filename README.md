# OPC UA hardware interface for ROS2

This package provides a `ros2_control` **SystemInterface** for communicating with machines using the standard `OPC UA`.

The package is built upon the [official open62541pp library](https://github.com/open62541pp/open62541pp).

Currently, the hardware interface acts an OPC UA Client that sets the value of single state interface `my_integer/my_integer_interface` from the server.

---

## Requirements
* ROS 2 (Jazzy Jalisco or newer)
* [open62541pp vendor ](https://github.com/b-robotized/open62541pp_vendor) package

---

## Configuration

The OPC UA server allows connections from users with specific credentials that could be managed through the `<ros2_control>` tag of your robot's URDF file.

The credentials defined in this example are:
* `username: admin`
* `password: ua_password`

For the demonstration, these values are hardcoded inside the `server.cpp` file.

Please note that if your credentials are different, you have to add them to the `server.cpp` to allow connection:
```
AccessControlCustom accessControl{
        true, // allow anonymous
        {
            Login{String{"admin"}, String{"ua_password"}},
        }};

```
It is also possible to give them Admin rights by using the aatribute `isAdmin`.

---

##  Instructions

### Running the Example Server

The `example_opcua_server` is a demonstration server that supports:
-   **Security Policies**: None, Sign, SignAndEncrypt.
-   **Authentication**: Anonymous, Username/Password, Certificate.
-   **Simulated Nodes**: Publishes simulated sensor data (scalar and array) and accepts commands.

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

#### Generating new certificates

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

### Running the ROS 2 Control Node

Once the server is running, launch the `control node`:
```
ros2 launch opcua_bringup opcua_bringup.launch.xml
```

Use the `controller_manager/introspection` topic to inspect the value of the state interface:
```
ros2 topic echo /controller_manager/introspection_data/full
```
