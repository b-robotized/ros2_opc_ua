// Copyright (c) 2026, b»robotized group
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef OPCUA_HARDWARE_INTERFACE__OPCUA_HARDWARE_INTERFACE_HPP_
#define OPCUA_HARDWARE_INTERFACE__OPCUA_HARDWARE_INTERFACE_HPP_

#include <limits>
#include <map>
#include <string>
#include <vector>

#include "hardware_interface/handle.hpp"
#include "hardware_interface/hardware_info.hpp"
#include "hardware_interface/system_interface.hpp"
#include "hardware_interface/types/hardware_interface_return_values.hpp"
#include "rclcpp/macros.hpp"
#include "rclcpp_lifecycle/state.hpp"

#include <open62541pp/client.hpp>
#include <open62541pp/node.hpp>

namespace opcua_hardware_interface
{
enum class UAType
{
  UA_Boolean,
  UA_Byte,
  UA_Int16,
  UA_UInt16,
  UA_Int32,
  UA_UInt32,
  UA_Int64,
  UA_UInt64,
  UA_Float,
  UA_Double,
  UNKNOWN
};

struct ROSInterfaceMapping
{
  size_t index;      // Index in the OPC UA Array
  std::string name;  // ROS Interface Name
};

struct ROSInterfaceUANode
{
  opcua::NodeId node_id;
  UAType ua_type;
  size_t num_elements;  // size of array on server
  std::vector<ROSInterfaceMapping> mappings;
};

class OPCUAHardwareInterface : public hardware_interface::SystemInterface
{
public:
  hardware_interface::CallbackReturn on_init(
    const hardware_interface::HardwareComponentParams & params);

  hardware_interface::CallbackReturn on_configure(
    const rclcpp_lifecycle::State & previous_state) override;

  hardware_interface::CallbackReturn on_activate(
    const rclcpp_lifecycle::State & previous_state) override;

  hardware_interface::CallbackReturn on_deactivate(
    const rclcpp_lifecycle::State & previous_state) override;

  hardware_interface::CallbackReturn on_shutdown(
    const rclcpp_lifecycle::State & previous_state) override;

  hardware_interface::return_type read(
    const rclcpp::Time & time, const rclcpp::Duration & period) override;

  hardware_interface::return_type write(
    const rclcpp::Time & time, const rclcpp::Duration & period) override;

private:
  rclcpp::Logger getLogger() { return rclcpp::get_logger("OPCUAHardwareInterface"); }

  // ========= OPC UA ==============================
  // OPC UA type helper
  UAType strToUAType(const std::string & type_str);
  size_t UAToROS2Type(UAType ua_type);

  opcua::Client client;
  bool configure_ua_client();

  void populate_state_interfaces_node_ids();
  void populate_command_interfaces_node_ids();

  void populate_read_items();

  double get_interface_value(UAType ua_type, const opcua::Variant & ua_variant);

  std::vector<double> get_command_vector(const ROSInterfaceUANode & command_ua_node);
  opcua::Variant get_scalar_command_variant(UAType ua_type, double val);
  opcua::Variant get_array_command_variant(UAType ua_type, std::vector<double> & command_array);

  std::vector<ROSInterfaceUANode>
    state_interfaces_nodes;  // Contains the node IDs corresponding to the state interfaces.
  std::vector<ROSInterfaceUANode>
    command_interfaces_nodes;  // Contains the node IDs corresponding to the command interfaces.

  std::vector<opcua::ReadValueId>
    read_items;  // Contains the NodeIds corresponding to our state interfaces
  std::vector<opcua::ua::WriteValue> write_items;

  // Template functions for processing read and write data
  template <typename T>
  bool process_read_data(const opcua::Variant & ua_variant, const ROSInterfaceUANode & state_node);

  template <typename T>
  bool process_write_node(
    const ROSInterfaceUANode & node, std::vector<opcua::ua::WriteValue> & write_values_vec);

  // Client identification and security (set once during configure_ua_client)
  std::string app_uri_;
  std::string app_name_;
  std::string endpoint_url_;
  bool has_client_certificate_;
  opcua::ByteString client_cert_;
  opcua::ByteString client_key_;
  opcua::ByteString ca_cert_;
};

}  // namespace opcua_hardware_interface

#endif  // OPCUA_HARDWARE_INTERFACE__OPCUA_HARDWARE_INTERFACE_HPP_
