#include <limits>
#include <vector>
#include <cstdint>
#include <algorithm> // std::transform
#include <regex>
#include <charconv> //std::from_chars

#include "opcua_hardware_interface/opcua_hardware_interface.hpp"
#include "hardware_interface/types/hardware_interface_type_values.hpp"
#include "rclcpp/rclcpp.hpp"

namespace opcua_hardware_interface
{
    hardware_interface::CallbackReturn OPCUAHardwareInterface::on_init(
        const hardware_interface::HardwareComponentParams & /*params*/)
    {
        logging_throttle_clock_ = std::make_shared<rclcpp::Clock>(RCL_STEADY_TIME);

        return CallbackReturn::SUCCESS;
    }

    hardware_interface::CallbackReturn OPCUAHardwareInterface::on_configure(
        const rclcpp_lifecycle::State & /*previous_state*/)
    {

        if (!configure_ua_client())
        {
            RCLCPP_FATAL(getLogger(), "Failed to configure OPC UA client from URDF parameters.");
            return hardware_interface::CallbackReturn::ERROR;
        }

        // Prepare the correpondances between the state_interfaces and the UA nodes
        populate_state_interfaces_node_ids();
        populate_command_interfaces_node_ids();

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
            // Src: https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp?page=1&tab=scoredesc#tab-top
            const std::regex pattern("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$");
            if (!std::regex_match(ip_address, pattern))
            {
                RCLCPP_FATAL(getLogger(), "\tInvalid format for 'ip'. Expected 'x.x.x.x'.");
                return false;
            }

            // Set the OPC Server URL
            std::string endpoint_url = "opc.tcp://" + ip_address + ":" + port_number + "/";

            if (!username.empty())
            {
                client.config().setUserIdentityToken(
                    opcua::UserNameIdentityToken{username, password});
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

    hardware_interface::CallbackReturn OPCUAHardwareInterface::on_activate(
        const rclcpp_lifecycle::State & /*previous_state*/)
    {
        return CallbackReturn::SUCCESS;
    }

    hardware_interface::CallbackReturn OPCUAHardwareInterface::on_deactivate(
        const rclcpp_lifecycle::State & /*previous_state*/)
    {
        return CallbackReturn::SUCCESS;
    }

    void OPCUAHardwareInterface::populate_state_interfaces_node_ids()
    {
        RCLCPP_INFO(getLogger(), "\tEstablishing correspondances between State interfaces and UA Nodes... ");

        // Go through all types of state interfaces defined in the URDF : joint, sensor, gpio
        auto init_state_interface_ua_nodes =
            [&](const auto &type_state_interfaces_)
        {
            for (const auto &[name, descr] : type_state_interfaces_)
            {
                StateInterfaceUANode state_interface_ua_node;

                state_interface_ua_node.state_interface_name = name;

                // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and uint32_t
                std::string ua_ns_str = descr.interface_info.parameters.at("ua_ns");
                [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(), state_interface_ua_node.ua_ns);

                std::string ua_id_str = descr.interface_info.parameters.at("ua_identifier");
                [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(), state_interface_ua_node.ua_identifier);

                state_interface_ua_node.ua_type = strToUAType(descr.interface_info.parameters.at("ua_type"));

                state_interfaces_nodes.push_back(state_interface_ua_node);

                // std::cout << "state_interface_ua_node : " << state_interface_ua_node.state_interface_name << std::endl;
                // std::cout << "state_interface_ua_node.ua_ns : " << state_interface_ua_node.ua_ns << std::endl;
                // std::cout << "state_interface_ua_node.ua_identifier : " << state_interface_ua_node.ua_identifier << std::endl;
            }
        };

        init_state_interface_ua_nodes(joint_state_interfaces_);
        init_state_interface_ua_nodes(gpio_state_interfaces_);
        init_state_interface_ua_nodes(sensor_state_interfaces_);
    }

    void OPCUAHardwareInterface::populate_command_interfaces_node_ids()
    {
        RCLCPP_INFO(getLogger(), "\tEstablishing correspondances between Command interfaces and UA Nodes... ");

        // Go through all types of command interfaces defined in the URDF : joint, gpio
        auto init_command_interface_ua_nodes =
            [&](const auto &type_command_interfaces_)
        {
            for (const auto &[name, descr] : type_command_interfaces_)
            {
                CommandInterfaceUANode command_interface_ua_node;
                command_interface_ua_node.command_interface_name = name;

                // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and uint32_t
                std::string ua_ns_str = descr.interface_info.parameters.at("ua_ns");
                [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(), command_interface_ua_node.ua_ns);

                std::string ua_id_str = descr.interface_info.parameters.at("ua_identifier");
                [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(), command_interface_ua_node.ua_identifier);

                command_interface_ua_node.ua_type = strToUAType(descr.interface_info.parameters.at("ua_type"));

                // Look for the fallback_state_interface with the same NodeId
                command_interface_ua_node.fallback_state_interface_name = "";
                auto same_nodeid_state_interface_node = [&command_interface_ua_node](const auto &state_interface_ua_node)
                {
                    return (state_interface_ua_node.ua_ns == command_interface_ua_node.ua_ns) && (state_interface_ua_node.ua_identifier == command_interface_ua_node.ua_identifier);
                };
                auto it = find_if(state_interfaces_nodes.begin(), state_interfaces_nodes.end(),
                                  same_nodeid_state_interface_node);

                // Found a fallback state interface:
                if (it != state_interfaces_nodes.end())
                {
                    command_interface_ua_node.fallback_state_interface_name = it->state_interface_name;
                    RCLCPP_INFO(getLogger(), "\tThe following command interface: %s has a fallback state interface: %s.", command_interface_ua_node.command_interface_name.c_str(), command_interface_ua_node.fallback_state_interface_name.c_str());
                }

                command_interfaces_nodes.push_back(command_interface_ua_node);

                // std::cout << "command_interface_ua_node : " << command_interface_ua_node.command_interface_name << std::endl;
                // std::cout << "command_interface_ua_node.ua_ns : " << command_interface_ua_node.ua_ns << std::endl;
                // std::cout << "command_interface_ua_node.ua_identifier : " << command_interface_ua_node.ua_identifier << std::endl;
            }
        };

        init_command_interface_ua_nodes(joint_command_interfaces_);
        init_command_interface_ua_nodes(gpio_command_interfaces_);
    }

    hardware_interface::return_type OPCUAHardwareInterface::read(
        const rclcpp::Time & /*time*/, const rclcpp::Duration & /*period*/)
    {

        bool any_item_read_failed = false;

        for (const auto &state_interface_ua_node : state_interfaces_nodes)
        {
            opcua::NodeId state_interface_node_id(state_interface_ua_node.ua_ns, state_interface_ua_node.ua_identifier);
            opcua::Node current_state_interface_node{client, state_interface_node_id};
            opcua::Variant value_variant = current_state_interface_node.readValue();

            switch (state_interface_ua_node.ua_type)
            {
            case UAType::UA_Boolean:
            {
                bool val = value_variant.to<bool>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Byte:
            {
                uint8_t val = value_variant.to<uint8_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Int16:
            {
                int16_t val = value_variant.to<int16_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_UInt16:
            {
                uint16_t val = value_variant.to<uint16_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Int32:
            {
                int32_t val = value_variant.to<int32_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_UInt32:
            {
                uint32_t val = value_variant.to<uint32_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Int64:
            {
                int64_t val = value_variant.to<int64_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_UInt64:
            {
                uint64_t val = value_variant.to<uint64_t>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Float:
            {
                float val = value_variant.to<float>();
                set_state(state_interface_ua_node.state_interface_name, static_cast<double>(val));
                break;
            }

            case UAType::UA_Double:
            {
                double val = value_variant.to<double>();
                set_state(state_interface_ua_node.state_interface_name, val);
                break;
            }

            case UAType::UNKNOWN:
            default:
                RCLCPP_ERROR_THROTTLE(getLogger(), *logging_throttle_clock_, 1000,
                                      "Unhandled or UNKNOWN UA type (%d) for the interface '%s' during read.",
                                      static_cast<int>(state_interface_ua_node.ua_type), state_interface_ua_node.state_interface_name.c_str());
                set_state(state_interface_ua_node.state_interface_name, std::numeric_limits<double>::quiet_NaN());
                any_item_read_failed = true;
                break;
            }
        }

        return any_item_read_failed ? hardware_interface::return_type::ERROR : hardware_interface::return_type::OK;
    }

    hardware_interface::return_type OPCUAHardwareInterface::write(
        const rclcpp::Time & /*time*/, const rclcpp::Duration & /*period*/)
    {

        bool any_item_write_failed = false;
        // There are no command interfaces to write to
        if (command_interfaces_nodes.size() == 0)
        {
            return hardware_interface::return_type::OK;
        }

        for (const auto &command_interface_ua_node : command_interfaces_nodes)
        {
            opcua::NodeId command_interface_node_id(1, 1);
            opcua::Node current_command_interface_node{client, command_interface_node_id};
            opcua::Variant ua_variant; // will be used to write the value to the OPC UA server

            // store the current val and reset the ros-side command value
            double val = get_command(command_interface_ua_node.command_interface_name);
            set_command(command_interface_ua_node.command_interface_name, std::numeric_limits<double>::quiet_NaN());

            if (std::isnan(val))
            {
                // if the original value was NaN and there exist a state interface of the same name, write corresponding state interface
                if (!command_interface_ua_node.fallback_state_interface_name.empty())
                {
                    val = get_state(command_interface_ua_node.fallback_state_interface_name);
                }

                // if we STILL don't have a fallback value on, don't update the write buffer.
                // the last valid command is written
                if (std::isnan(val))
                {
                    continue;
                }
            }

            switch (command_interface_ua_node.ua_type)
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
                RCLCPP_ERROR_THROTTLE(getLogger(), *logging_throttle_clock_, 1000,
                                      "Unhandled or UNKNOWN UA type for the interface '%s' during write.",
                                      command_interface_ua_node.command_interface_name.c_str());
                return hardware_interface::return_type::ERROR;
                break;
            }

            // Write the value to the OPC UA server
            current_command_interface_node.writeValue(ua_variant);
        }
        return any_item_write_failed ? hardware_interface::return_type::ERROR : hardware_interface::return_type::OK;
    }

    hardware_interface::CallbackReturn OPCUAHardwareInterface::on_shutdown(
        const rclcpp_lifecycle::State & /*previous_state*/)
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

} // namespace opcua_hardware_interface

#include "pluginlib/class_list_macros.hpp"

PLUGINLIB_EXPORT_CLASS(
    opcua_hardware_interface::OPCUAHardwareInterface, hardware_interface::SystemInterface)