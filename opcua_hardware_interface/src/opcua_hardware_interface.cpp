#include <algorithm> // std::transform
#include <charconv>  //std::from_chars
#include <cmath>     //  std::isnan
#include <cstdint>
#include <limits>
#include <regex>
#include <vector>

#include "hardware_interface/types/hardware_interface_type_values.hpp"
#include "opcua_hardware_interface/opcua_hardware_interface.hpp"
#include "opcua_hardware_interface/opcua_helpers.hpp"
#include "rclcpp/rclcpp.hpp"

namespace opcua_hardware_interface
{
hardware_interface::CallbackReturn
OPCUAHardwareInterface::on_init(const hardware_interface::HardwareComponentParams & /*params*/)
{
    return CallbackReturn::SUCCESS;
}

hardware_interface::CallbackReturn
OPCUAHardwareInterface::on_configure(const rclcpp_lifecycle::State & /*previous_state*/)
{

    if (!configure_ua_client())
    {
        RCLCPP_FATAL(getLogger(), "Failed to configure OPC UA client from URDF parameters.");
        return hardware_interface::CallbackReturn::ERROR;
    }

    // Prepare the correpondances between the state_interfaces and the UA nodes
    populate_state_interfaces_node_ids();
    populate_command_interfaces_node_ids();

    populate_read_items();

    return CallbackReturn::SUCCESS;
}

// Create an OPC UA client and connect it to the server
bool OPCUAHardwareInterface::configure_ua_client()
{

    RCLCPP_INFO(getLogger(), "Configuring OPC UA Client...");
    const auto &params = info_.hardware_parameters;

    try
    {

        std::string ip_address = params.at("ip");
        std::string port_number = params.at("port");
        std::string username = params.at("user");
        std::string password = params.at("password");

        // Validate the format of the Ip Address using regular expressions
        // Src:
        // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp?page=1&tab=scoredesc#tab-top
        const std::regex pattern("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$");
        if (!std::regex_match(ip_address, pattern))
        {
            RCLCPP_FATAL(getLogger(), "\tInvalid format for 'ip'. Expected 'x.x.x.x'.");
            return false;
        }

        // Set the OPC Server URL
        std::string endpoint_url = "opc.tcp://" + ip_address + ":" + port_number + "/";

        // Find all servers
        const auto servers = client.findServers(endpoint_url);
        opcua_helpers::print_servers_info(servers, getLogger());

        if (!username.empty())
        {
            client.config().setUserIdentityToken(opcua::UserNameIdentityToken{username, password});
        }
        // Connect to the server using the credentials from the URDF
        RCLCPP_INFO(getLogger(), "\tConnection to the Endpoint URL: %s...", endpoint_url.c_str());
        client.connect(endpoint_url);

        // Connection failed
        if (!client.isConnected())
        {
            RCLCPP_FATAL(getLogger(), "\tCould not connect to the server.");
            return false;
        }

        RCLCPP_INFO(getLogger(), "\tConnection successful!");
    }
    catch (const std::out_of_range &ex)
    {
        RCLCPP_FATAL(getLogger(), "\tMissing required URDF <hardware> parameter: %s", ex.what());
        return false;
    }
    catch (const std::exception &ex)
    {
        RCLCPP_FATAL(getLogger(), "\tError during UA connection: %s", ex.what());
        return false;
    }

    return true;
}

hardware_interface::CallbackReturn
OPCUAHardwareInterface::on_activate(const rclcpp_lifecycle::State & /*previous_state*/)
{
    return CallbackReturn::SUCCESS;
}

hardware_interface::CallbackReturn
OPCUAHardwareInterface::on_deactivate(const rclcpp_lifecycle::State & /*previous_state*/)
{
    return CallbackReturn::SUCCESS;
}

void OPCUAHardwareInterface::populate_state_interfaces_node_ids()
{
    RCLCPP_INFO(getLogger(), "\tEstablishing correspondances between State interfaces and UA Nodes... ");

    auto init_state_interface_ua_nodes = [&](const auto &type_state_interfaces_)
    {
        for (const auto &[name, descr] : type_state_interfaces_)
        {

            std::string ua_ns_str;
            std::string ua_id_str;
            UAType ua_type;
            size_t num_elements = 1;
            size_t index = 0; // By default the OPC UA element is considered scalar

            // Check if all necessary parameters exist
            try
            {
                ua_ns_str = descr.interface_info.parameters.at("ua_ns");
                ua_id_str = descr.interface_info.parameters.at("ua_identifier");
                ua_type = strToUAType(descr.interface_info.parameters.at("ua_type"));

                // Check if state_interface refers to an OPC UA Array element
                if (descr.interface_info.parameters.count("n_elements"))
                {
                    num_elements = std::stoul(descr.interface_info.parameters.at("n_elements"));
                }
                if (descr.interface_info.parameters.count("index"))
                {
                    index = std::stoul(descr.interface_info.parameters.at("index"));
                }
            }
            catch (const std::exception &e)
            {
                RCLCPP_ERROR(getLogger(), "Error parsing PLC parameters for state interface '%s': %s. Check URDF.",
                             name.c_str(), e.what());
                continue;
            }

            StateInterfaceUANode current_state_interface_ua_node;

            // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and uint32_t
            [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(),
                                                                current_state_interface_ua_node.ua_ns);
            [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(),
                                                                current_state_interface_ua_node.ua_identifier);
            current_state_interface_ua_node.ua_type = ua_type;
            current_state_interface_ua_node.num_elements = num_elements;

            // Find if a state_interface with the same NodeId was already processed
            auto same_nodeid_state_interface_node =
                [&current_state_interface_ua_node](const auto &state_interface_ua_node)
            {
                return (state_interface_ua_node.ua_ns == current_state_interface_ua_node.ua_ns) &&
                       (state_interface_ua_node.ua_identifier == current_state_interface_ua_node.ua_identifier);
            };
            auto it = std::find_if(state_interfaces_nodes.begin(), state_interfaces_nodes.end(),
                                   same_nodeid_state_interface_node);

            // OPC UA Array was already processed
            if (it != state_interfaces_nodes.end())
            {
                it->state_interface_names.emplace(std::make_pair(index, name));
            }
            else
            {
                // Add the name to the current interface_ua_node instead
                current_state_interface_ua_node.state_interface_names.emplace(std::make_pair(index, name));
                state_interfaces_nodes.push_back(current_state_interface_ua_node);
            }
        }
    };

    //  Go through all types of state interfaces defined in the URDF : joint, sensor, gpio
    init_state_interface_ua_nodes(joint_state_interfaces_);
    init_state_interface_ua_nodes(gpio_state_interfaces_);
    init_state_interface_ua_nodes(sensor_state_interfaces_);
}

void OPCUAHardwareInterface::populate_command_interfaces_node_ids()
{
    RCLCPP_INFO(getLogger(), "\tEstablishing correspondances between Command interfaces and UA Nodes... ");

    auto init_command_interface_ua_nodes = [&](const auto &type_command_interfaces_)
    {
        for (const auto &[name, descr] : type_command_interfaces_)
        {
            std::string ua_ns_str;
            std::string ua_id_str;
            std::string fallback_name = "";
            UAType ua_type;
            size_t num_elements = 1;
            size_t index = 0;

            // Check if all necessary parameters exist
            try
            {
                ua_ns_str = descr.interface_info.parameters.at("ua_ns");
                ua_id_str = descr.interface_info.parameters.at("ua_identifier");
                ua_type = strToUAType(descr.interface_info.parameters.at("ua_type"));

                // Check if state_interface refers to an OPC UA Array element
                if (descr.interface_info.parameters.count("n_elements"))
                {
                    num_elements = std::stoul(descr.interface_info.parameters.at("n_elements"));
                }
                if (descr.interface_info.parameters.count("index"))
                {
                    index = std::stoul(descr.interface_info.parameters.at("index"));
                }
            }
            catch (const std::exception &e)
            {
                RCLCPP_ERROR(getLogger(), "Error parsing PLC parameters for command interface '%s': %s. Check URDF.",
                             name.c_str(), e.what());
                continue;
            }

            CommandInterfaceUANode current_command_interface_ua_node;

            // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and uint32_t
            [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(),
                                                                current_command_interface_ua_node.ua_ns);
            [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(),
                                                                current_command_interface_ua_node.ua_identifier);
            current_command_interface_ua_node.ua_type = ua_type;
            current_command_interface_ua_node.num_elements = num_elements;

            /* Fallback State Interface Name = State interface with the same NodeId */
            auto same_nodeid_state_interface_node =
                [&current_command_interface_ua_node](const auto &state_interface_ua_node)
            {
                return (state_interface_ua_node.ua_ns == current_command_interface_ua_node.ua_ns) &&
                       (state_interface_ua_node.ua_identifier == current_command_interface_ua_node.ua_identifier);
            };
            auto it_fallback =
                find_if(state_interfaces_nodes.begin(), state_interfaces_nodes.end(), same_nodeid_state_interface_node);

            // Found a fallback state interface:
            if (it_fallback != state_interfaces_nodes.end())
            {
                fallback_name = it_fallback->state_interface_names.at(index);
                // current_command_interface_ua_node.fallback_state_interface_names.emplace(std::make_pair(index,
                // fallback_name));
                RCLCPP_INFO(getLogger(), "\tThe following command interface: %s has a fallback state interface: %s.",
                            name.c_str(), fallback_name.c_str());
            }

            /* Find if a command_interface with the same NodeId was already processed */
            auto same_nodeid_command_interface_node =
                [&current_command_interface_ua_node](const auto &command_interface_ua_node)
            {
                return (command_interface_ua_node.ua_ns == current_command_interface_ua_node.ua_ns) &&
                       (command_interface_ua_node.ua_identifier == current_command_interface_ua_node.ua_identifier);
            };
            auto it = std::find_if(command_interfaces_nodes.begin(), command_interfaces_nodes.end(),
                                   same_nodeid_command_interface_node);

            // OPC UA Array was already processed, only populate command_interface_name and fallback_name maps
            if (it != command_interfaces_nodes.end())
            {
                it->command_interface_names.emplace(std::make_pair(index, name));
                it->fallback_state_interface_names.emplace(std::make_pair(index, fallback_name));
            }
            else
            {
                // Create a whole interfaceUANode element and add it to the command_interfaces_nodes vector
                current_command_interface_ua_node.command_interface_names.emplace(std::make_pair(index, name));
                current_command_interface_ua_node.fallback_state_interface_names.emplace(
                    std::make_pair(index, fallback_name));
                command_interfaces_nodes.push_back(current_command_interface_ua_node);
            }
        }
    };

    // Go through all types of command interfaces defined in the URDF : joint, gpio
    init_command_interface_ua_nodes(joint_command_interfaces_);
    init_command_interface_ua_nodes(gpio_command_interfaces_);
}

void OPCUAHardwareInterface::populate_read_items()
{
    read_items.clear();
    read_items.reserve(state_interfaces_nodes.size());

    for (const auto &state_node : state_interfaces_nodes)
    {
        opcua::ReadValueId read_value;
        opcua::NodeId node_id(state_node.ua_ns, state_node.ua_identifier);

        read_value->nodeId = node_id;
        read_value->attributeId = UA_ATTRIBUTEID_VALUE; // (c.f wrapper.md line 94)
        read_items.push_back(read_value);
    }
}

hardware_interface::return_type OPCUAHardwareInterface::read(const rclcpp::Time & /*time*/,
                                                             const rclcpp::Duration & /*period*/)
{

    bool any_item_read_failed = false;

    // Client lost connection to the UA server
    if (!client.isConnected())
    {
        RCLCPP_ERROR(getLogger(), "Hardware interface lost connection to the server during read operation.");
        any_item_read_failed = true;
    }

    // Perform ONE Read Request with all the desired NodeIds
    opcua::ReadRequest request(opcua::RequestHeader{},          // default header
                               0.0,                             // maxAge
                               opcua::TimestampsToReturn::Both, // or Neither
                               read_items                       // Span<const ReadValueId>
    );

    // Response will contain all the OPC UA variables with the same NodeIds
    opcua::ReadResponse response;

    try
    {
        response = opcua::services::read(client, request); // (c.f attribute.hpp line 45)
    }
    catch (const std::exception &e)
    {
        RCLCPP_ERROR(getLogger(), "OPC UA read failed: %s", e.what());
        any_item_read_failed = true;
    }

    const auto &results = response.results();

    // There is missing information
    if (results.size() != state_interfaces_nodes.size())
    {
        RCLCPP_ERROR(getLogger(), "Read result size mismatch: expected %zu, got %zu", state_interfaces_nodes.size(),
                     results.size());
        any_item_read_failed = true;
    }

    // Turn the results into an opcua::Variant
    for (size_t k = 0; k < results.size(); ++k)
    {
        const auto &state_interface_ua_node = state_interfaces_nodes[k];
        const auto &read_result = results[k]; // DataType class (c.f types.hpp line 1671)

        // Check if there was an issue while reading that specific UA value
        if (read_result.hasStatus() && read_result.status() != UA_STATUSCODE_GOOD)
        {
            RCLCPP_ERROR_THROTTLE(getLogger(), *get_clock(), 1000, "Bad read status for node (%u, %u)",
                                  state_interface_ua_node.ua_ns, state_interface_ua_node.ua_identifier);

            any_item_read_failed = true;
            continue;
        }

        const opcua::Variant &ua_variant = read_result.value();

        std::string interface_name;
        double interface_value;
        std::vector<double> values;

        // OPC UA variable is scalar
        if (ua_variant.isScalar())
        {
            interface_value = get_interface_value(state_interface_ua_node.ua_type, ua_variant);
            interface_name = state_interface_ua_node.state_interface_names.at(0);

            if (std::isnan(interface_value))
            {
                RCLCPP_ERROR_THROTTLE(getLogger(), *get_clock(), 1000,
                                      "Unhandled or UNKNOWN UA type (%d) for the interface '%s' during read.",
                                      static_cast<int>(state_interface_ua_node.ua_type), interface_name.c_str());
                any_item_read_failed = true;
            }
            set_state(interface_name, interface_value);
        }

        // OPC UA variable is array
        if (ua_variant.isArray())
        {
            // const auto &ua_var = ua_variant.get();
            auto ua_size = ua_variant.arrayLength();
            const UA_DataType *type = ua_variant.type();

            // Check if the UA number of elements == ROS2 number of elements
            if (ua_size != state_interface_ua_node.num_elements)
            {
                RCLCPP_FATAL(getLogger(),
                             "\tState interface declared for nodeId (%u, %u) number of elements does not match the UA "
                             "Array size on the server side.",
                             state_interface_ua_node.ua_ns, state_interface_ua_node.ua_identifier);
                any_item_read_failed = true;
            }

            // TODO : Find a more concise way to write to vectors

            if (type == &UA_TYPES[UA_TYPES_BOOLEAN])
            {
                auto values_vector = ua_variant.to<std::vector<bool>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_BYTE])
            {
                auto values_vector = ua_variant.to<std::vector<uint8_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_INT16])
            {
                auto values_vector = ua_variant.to<std::vector<int16_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_UINT16])
            {
                auto values_vector = ua_variant.to<std::vector<uint16_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_INT32])
            {
                auto values_vector = ua_variant.to<std::vector<int32_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_UINT32])
            {
                auto values_vector = ua_variant.to<std::vector<uint32_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_INT64])
            {
                auto values_vector = ua_variant.to<std::vector<int64_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_UINT64])
            {
                auto values_vector = ua_variant.to<std::vector<uint64_t>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_FLOAT])
            {
                auto values_vector = ua_variant.to<std::vector<float>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }

            if (type == &UA_TYPES[UA_TYPES_DOUBLE])
            {
                auto values_vector = ua_variant.to<std::vector<double>>();
                for (size_t i = 0; i < values_vector.size(); i++)
                {
                    interface_name = state_interface_ua_node.state_interface_names.at(i);
                    interface_value = static_cast<double>(values_vector[i]);
                    set_state(interface_name, interface_value);
                }
            }
            //! Other types (e.g Unknown) are not treated
        }
    }

    return any_item_read_failed ? hardware_interface::return_type::ERROR : hardware_interface::return_type::OK;
}

hardware_interface::return_type OPCUAHardwareInterface::write(const rclcpp::Time & /*time*/,
                                                              const rclcpp::Duration & /*period*/)
{

    bool any_item_write_failed = false;

    // Client lost connection to the UA server
    if (!client.isConnected())
    {
        RCLCPP_ERROR(getLogger(), "Hardware interface lost connection to the server during write operation.");
        any_item_write_failed = true;
    }

    // There are no command interfaces to write to
    if (command_interfaces_nodes.size() == 0)
    {
        return hardware_interface::return_type::OK;
    }

    // Reserve space for write request items
    write_items.reserve(command_interfaces_nodes.size());

    for (const auto &command_interface_ua_node : command_interfaces_nodes)
    {
        opcua::Variant ua_variant; // will be used to write the value to the OPC UA server

        // if the command interface is scalar
        if (command_interface_ua_node.num_elements == 1)
        {
            std::string command_interface_name = command_interface_ua_node.command_interface_names.at(0);
            std::string fallback_name = command_interface_ua_node.fallback_state_interface_names.at(0);

            // store the current val and reset the ros-side command value
            double val = get_command(command_interface_name);
            set_command(command_interface_name, std::numeric_limits<double>::quiet_NaN());

            if (std::isnan(val))
            {
                // if the original value was NaN and there exist a state interface of the same name, write corresponding
                // state interface
                if (!fallback_name.empty())
                {
                    val = get_state(fallback_name);
                }

                // if we STILL don't have a fallback value on, don't update the write buffer.
                // the last valid command is written
                if (std::isnan(val))
                {
                    continue;
                }
            }
            ua_variant = get_scalar_command_variant(command_interface_ua_node.ua_type, val);
        }
        else // if the command interface is an array
        {
            std::vector<double> command_vector = get_command_vector(command_interface_ua_node);

            if (command_vector.empty())
            {
                continue; // Do no send a Write Request
            }

            ua_variant = get_array_command_variant(command_interface_ua_node.ua_type, command_vector);
        }

        // Send a request containing all the OPCUA node Ids we want to write
        opcua::ua::WriteValue write_value; // (c.f types.hpp line 1429)
        write_value.nodeId() = opcua::NodeId(command_interface_ua_node.ua_ns, command_interface_ua_node.ua_identifier);
        write_value->attributeId = UA_ATTRIBUTEID_VALUE;
        write_value.value() = opcua::DataValue(ua_variant);

        write_items.push_back(std::move(write_value));
    }

    if (!write_items.empty())
    {
        // Make a single global request to write items
        opcua::ua::WriteRequest request{opcua::RequestHeader(), write_items};
        opcua::ua::WriteResponse response = opcua::services::write(client, request);

        const auto &results = response.results();
        for (size_t i = 0; i < results.size(); ++i)
        {
            // Issue detected during write
            if (results[i] != UA_STATUSCODE_GOOD)
            {
                RCLCPP_ERROR(getLogger(), "\tOPC UA write failed for node %zu with status 0x%08X", i,
                             static_cast<uint32_t>(results[i]));
                any_item_write_failed = true;
            }
        }
    }

    return any_item_write_failed ? hardware_interface::return_type::ERROR : hardware_interface::return_type::OK;
}

hardware_interface::CallbackReturn
OPCUAHardwareInterface::on_shutdown(const rclcpp_lifecycle::State & /*previous_state*/)
{
    RCLCPP_INFO(getLogger(), "Disconnecting OPC UA client...");

    // Disconnect and close the connection to the server.
    client.disconnect();
    return hardware_interface::CallbackReturn::SUCCESS;
}

UAType OPCUAHardwareInterface::strToUAType(const std::string &type_str)
{

    if (type_str == "UA_Boolean")
        return UAType::UA_Boolean;
    if (type_str == "UA_Byte")
        return UAType::UA_Byte;
    if (type_str == "UA_Int16")
        return UAType::UA_Int16;
    if (type_str == "UA_UInt16")
        return UAType::UA_UInt16;
    if (type_str == "UA_Int32")
        return UAType::UA_Int32;
    if (type_str == "UA_UInt32")
        return UAType::UA_UInt32;
    if (type_str == "UA_Int64")
        return UAType::UA_Int64;
    if (type_str == "UA_UInt64")
        return UAType::UA_UInt64;
    if (type_str == "UA_Float")
        return UAType::UA_Float;
    if (type_str == "UA_Double")
        return UAType::UA_Double;

    RCLCPP_ERROR(getLogger(), "Unknown UA type string: '%s'", type_str.c_str());
    return UAType::UNKNOWN;
}

// Helper function that returns the ROS2 interface_value depending on the OPC UA type
double OPCUAHardwareInterface::get_interface_value(UAType ua_type, const opcua::Variant &ua_variant)
{
    double interface_value;

    switch (ua_type)
    {
    case UAType::UA_Boolean:
    {
        bool val = ua_variant.to<bool>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Byte:
    {
        uint8_t val = ua_variant.to<uint8_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Int16:
    {
        int16_t val = ua_variant.to<int16_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_UInt16:
    {
        uint16_t val = ua_variant.to<uint16_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Int32:
    {
        int32_t val = ua_variant.to<int32_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_UInt32:
    {
        uint32_t val = ua_variant.to<uint32_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Int64:
    {
        int64_t val = ua_variant.to<int64_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_UInt64:
    {
        uint64_t val = ua_variant.to<uint64_t>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Float:
    {
        float val = ua_variant.to<float>();
        interface_value = static_cast<double>(val);
        break;
    }

    case UAType::UA_Double:
    {
        interface_value = ua_variant.to<double>();
        break;
    }

    case UAType::UNKNOWN:
    default:
        interface_value = std::numeric_limits<double>::quiet_NaN();
        break;
    }
    return interface_value;
}

// If an interface refers to an array, get all the commands and store them inside a vector
std::vector<double> OPCUAHardwareInterface::get_command_vector(const CommandInterfaceUANode &command_ua_node)
{
    std::vector<double> command_vector;
    double current_command;
    std::string current_command_interface_name;
    std::string current_fallback_interface_name;

    for (size_t i = 0; i < command_ua_node.num_elements; ++i)
    {
        current_command_interface_name = command_ua_node.command_interface_names.at(i);
        current_fallback_interface_name = command_ua_node.fallback_state_interface_names.at(i);

        current_command = get_command(current_command_interface_name);

        set_command(current_command_interface_name, std::numeric_limits<double>::quiet_NaN());

        if (std::isnan(current_command))
        {
            if (!current_fallback_interface_name.empty())
            {
                current_command = get_state(current_fallback_interface_name);
            }

            if (std::isnan(current_command))
            {
                continue;
            }
        }
        command_vector.push_back(current_command);
    }
    return command_vector;
}

// The UAVariant contains the data that will be sent to the server as an write request
opcua::Variant OPCUAHardwareInterface::get_scalar_command_variant(UAType ua_type, double val)
{
    opcua::Variant ua_variant;
    switch (ua_type)
    {
    case UAType::UA_Boolean:
    {
        bool ua_value = static_cast<bool>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Byte:
    {
        uint8_t ua_value = static_cast<uint8_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Int16:
    {
        int16_t ua_value = static_cast<int16_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_UInt16:
    {
        uint16_t ua_value = static_cast<uint16_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Int32:
    {
        int32_t ua_value = static_cast<int32_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_UInt32:
    {
        uint32_t ua_value = static_cast<uint32_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Int64:
    {
        int64_t ua_value = static_cast<int64_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_UInt64:
    {
        uint64_t ua_value = static_cast<uint64_t>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Float:
    {
        float ua_value = static_cast<float>(val);
        ua_variant = ua_value;
        break;
    }

    case UAType::UA_Double:
    {
        double ua_value = val;
        ua_variant = ua_value;
        break;
    }

    case UAType::UNKNOWN:
    default:
        RCLCPP_ERROR_THROTTLE(getLogger(), *get_clock(), 1000,
                              "Unhandled or UNKNOWN UA type for the interface during write.");

        // TODO: Add a flag to return the error inside write
        //  return hardware_interface::return_type::ERROR;
        break;
    }

    return ua_variant;
}

opcua::Variant OPCUAHardwareInterface::get_array_command_variant(UAType ua_type, std::vector<double> &command_array)
{
    opcua::Variant command_variant;

    switch (ua_type)
    {
    case UAType::UA_Boolean:
    {
        std::vector<bool> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<bool>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Byte:
    {
        std::vector<uint8_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<uint8_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Int16:
    {
        std::vector<int16_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<int16_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_UInt16:
    {
        std::vector<uint16_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<uint16_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Int32:
    {
        std::vector<int32_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<int32_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_UInt32:
    {
        std::vector<uint32_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<uint32_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Int64:
    {
        std::vector<int64_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<int64_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_UInt64:
    {
        std::vector<uint64_t> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<uint64_t>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Float:
    {
        std::vector<float> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<float>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UA_Double:
    {
        std::vector<double> ua_vals;
        ua_vals.reserve(command_array.size());

        for (double command_value : command_array)
        {
            if (!std::isnan(command_value))
            {
                ua_vals.push_back(static_cast<double>(command_value));
            }
        }

        command_variant = ua_vals;
        break;
    }

    case UAType::UNKNOWN:
    default:
        RCLCPP_ERROR_THROTTLE(getLogger(), *get_clock(), 1000,
                              "Unhandled or UNKNOWN UA type for the interface during write.");
        // TODO: Add a flag to return an error inside the write function
        //  return hardware_interface::return_type::ERROR;
        break;
    }

    return command_variant;
}

} // namespace opcua_hardware_interface

#include "pluginlib/class_list_macros.hpp"

PLUGINLIB_EXPORT_CLASS(opcua_hardware_interface::OPCUAHardwareInterface, hardware_interface::SystemInterface)