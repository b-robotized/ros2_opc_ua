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

Run the OPC UA server first: 
```
ros2 run opcua_bringup opcua_server 
```

Then launch the `control node`: 
```
ros2 launch opcua_bringup opcua_bringup.launch.xml 
```

Use the `controller_manager/introspection` topic to inspect the value of the state interface: 
```
ros2 topic echo /controller_manager/introspection_data/full 
```  

