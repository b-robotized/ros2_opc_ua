# OPC UA hardware interface for ROS2

This package provides a `ros2_control` **SystemInterface** for communicating with machines using the standard `OPC UA`.

The package is built upon the [official open62541pp library](https://github.com/open62541pp/open62541pp).

Currently, the hardware interface acts an OPC UA Client that sets the value of single state interface `my_integer/my_integer_interface` from the server.

---

## Requirements
* ROS 2 (Jazzy Jalisco or newer)
* [open62541pp vendor ](https://github.com/b-robotized/open62541pp_vendor) package

---

## Notes

With the current implementation:

### 1.UA Node Identifiers

The UA Node Identifiers declared inside the `URDF` should be **numeric**: `NodeIdType::Numeric`.

### 2. Command Interfaces and UA Arrays
For ROS2 **Command interfaces** mapped to OPC UA **Arrays**, **all** the indexes should be declared inside the `URDF`.

Otherwise, write requests for that specific Array are not sent to the server.(e.g: `buttonArray_2` in the example URDF).
This is done to prevent corrupting the remaining uncommanded indices.

### 3. Tracking last command value
 To avoid spamming write requests, the last commanded value is tracked for each ROS2 interface.
 A write request is sent only when the command value changes.



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

### Certificate Setup

The package supports two certificate configurations:

#### 1. Simple Self-Signed Certificates (Testing Only)

Self-signed certificates (valid for 100 years) are provided in `config/` directory for quick testing. These work for insecure mode or when certificate verification is disabled.

#### 2. Certificate Chain with CA (Recommended for Secure Communication)

A complete PKI setup is provided in `config/pki/` with:
- **Root CA** (`ca_cert.der`) - Signs both server and client certificates
- **Server Certificate** (`server_cert.der`, `server_key.der`) - Signed by CA
- **Client Certificate** (`client_cert.der`, `client_key.der`) - Signed by CA

**Running with Verified Certificates:**

```bash
# Terminal 1: Start server with CA-based client verification
ros2 launch opcua_bringup example_server_secure.launch.xml

# Terminal 2: Start client with proper certificates
ros2 launch opcua_bringup opcua_bringup_secure.launch.xml
```

#### Generating Your Own Certificate Chain

To create a new certificate chain:

```bash
cd config/pki

# 1. Generate Root CA
openssl genrsa -out ca_key.pem 2048
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 36500 -out ca_cert.pem \
  -subj "/C=DE/O=ROS 2/CN=ros2_opc_ua Root CA"

# 2. Generate Server Certificate (create server_san.cnf first - see config/pki/)
openssl genrsa -out server_key.pem 2048
openssl req -new -key server_key.pem -out server_csr.pem -config server_san.cnf
openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out server_cert.pem -days 36500 -sha256 \
  -extensions v3_req -extfile server_san.cnf

# 3. Generate Client Certificate (create client_san.cnf first - see config/pki/)
openssl genrsa -out client_key.pem 2048
openssl req -new -key client_key.pem -out client_csr.pem -config client_san.cnf
openssl x509 -req -in client_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out client_cert.pem -days 36500 -sha256 \
  -extensions v3_req -extfile client_san.cnf

# 4. Convert to DER format (required by open62541)
openssl x509 -outform der -in ca_cert.pem -out ca_cert.der
openssl x509 -outform der -in server_cert.pem -out server_cert.der
openssl rsa -outform der -in server_key.pem -out server_key.der
openssl x509 -outform der -in client_cert.pem -out client_cert.der
openssl rsa -outform der -in client_key.pem -out client_key.der
```

**Important:** The SAN configuration files (`server_san.cnf`, `client_san.cnf`) must include the correct `ApplicationURI` for certificate validation to succeed.

### Running the ROS 2 Control Node

Once the server is running, launch the `control node`:
```
ros2 launch opcua_bringup opcua_bringup.launch.xml
```

Use the `controller_manager/introspection` topic to inspect the value of the state interface:
```
ros2 topic echo /controller_manager/introspection_data/full
```

Send the command to the controller and you should see the commands being changes in the server
```
ros2 topic pub /opcua_controller/commands control_msgs/msg/DynamicInterfaceGroupValues "{interface_groups: ['robot_command'], interface_values: [{interface_names: ['commandPos_0', 'commandPos_1', 'my_integer_interface'], values: [1.0, 0.0, 28.0]}]}" --once
```
