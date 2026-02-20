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

#include <algorithm>  // std::transform
#include <charconv>   // std::from_chars
#include <cmath>      //  std::isnan
#include <cstdint>
#include <fstream>
#include <limits>
#include <regex>
#include <vector>

#include "hardware_interface/types/hardware_interface_type_values.hpp"
#include "opcua_hardware_interface/opcua_hardware_interface.hpp"
#include "opcua_hardware_interface/opcua_helpers.hpp"
#include "open62541/client_config_default.h"
#include "open62541pp/plugin/create_certificate.hpp"
#include "rclcpp/rclcpp.hpp"

namespace opcua_hardware_interface
{
// Helper to read file content
static opcua::ByteString readFile(const std::string & path)
{
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file)
  {
    return opcua::ByteString{};
  }
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  if (size <= 0)
  {
    return opcua::ByteString{};
  }

  std::vector<char> buffer(static_cast<size_t>(size));
  if (file.read(buffer.data(), size))
  {
    return opcua::ByteString(std::string_view(buffer.data(), static_cast<size_t>(size)));
  }
  return opcua::ByteString{};
}

hardware_interface::CallbackReturn OPCUAHardwareInterface::on_init(
  const hardware_interface::HardwareComponentParams & /*params*/)
{
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

  populate_read_items();

  return CallbackReturn::SUCCESS;
}

// Create an OPC UA client and connect it to the server
bool OPCUAHardwareInterface::configure_ua_client()
{
  RCLCPP_INFO(getLogger(), "Configuring OPC UA Client...");
  const auto & params = info_.hardware_parameters;

  try
  {
    std::string ip_address = params.at("ip");
    std::string port_number = params.at("port");
    std::string username = params.count("user") ? params.at("user") : "";
    std::string password = params.count("password") ? params.at("password") : "";
    std::string cert_path =
      params.count("security.certificate_path") ? params.at("security.certificate_path") : "";
    std::string key_path =
      params.count("security.private_key_path") ? params.at("security.private_key_path") : "";
    std::string ca_cert_path =
      params.count("security.ca_certificate_path") ? params.at("security.ca_certificate_path") : "";

    // Set Application URI and Name once (used throughout)
    app_uri_ = "urn:ros2_opc_ua.client.hw_itf:" + info_.name;
    app_name_ = "ros2_opc_ua client - ros2_control Hardware Interface - " + info_.name;

    // Validate the format of the Ip Address using regular expressions
    const std::regex pattern("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$");
    if (!std::regex_match(ip_address, pattern))
    {
      RCLCPP_FATAL(getLogger(), "\tInvalid format for 'ip'. Expected 'x.x.x.x'.");
      return false;
    }

    // Set the OPC Server URL
    endpoint_url_ = "opc.tcp://" + ip_address + ":" + port_number;

    const auto servers = client.findServers(endpoint_url_);
    opcua_helpers::print_servers_info(servers, getLogger());

    // Get Endpoints to select the best one
    auto endpoints = client.getEndpoints(endpoint_url_);
    if (endpoints.empty())
    {
      RCLCPP_FATAL(getLogger(), "No endpoints found at %s", endpoint_url_.c_str());
      return false;
    }

    // Only process certificates if we have endpoints with secure connections
    bool has_secure_endpoints = false;
    for (const auto & endpoint : endpoints)
    {
      if (
        endpoint.securityMode() == opcua::MessageSecurityMode::Sign ||
        endpoint.securityMode() == opcua::MessageSecurityMode::SignAndEncrypt)
      {
        has_secure_endpoints = true;
        break;
      }
    }

    has_client_certificate_ = false;
    // Skip certificate handling if no secure endpoints exist
    if (has_secure_endpoints)
    {
      // Try loading from file first
      if (!cert_path.empty() && !key_path.empty())
      {
        client_cert_ = readFile(cert_path);
        client_key_ = readFile(key_path);
        if (!client_cert_.empty() && !client_key_.empty())
        {
          RCLCPP_INFO(getLogger(), "Loaded client certificate from %s", cert_path.c_str());
        }
        else
        {
          RCLCPP_WARN(
            getLogger(), "Failed to read client certificate/key files from %s", cert_path.c_str());
        }
      }

      // Try loading CA certificate for server verification
      if (!ca_cert_path.empty())
      {
        ca_cert_ = readFile(ca_cert_path);
        if (!ca_cert_.empty())
        {
          RCLCPP_INFO(
            getLogger(), "Loaded CA certificate from %s (%zu bytes)", ca_cert_path.c_str(),
            ca_cert_.length());
        }
        else
        {
          RCLCPP_WARN(
            getLogger(), "Failed to read CA certificate file from %s", ca_cert_path.c_str());
        }
      }

      // If no certificate loaded, generate one
      if (client_cert_.empty() || client_key_.empty())
      {
        RCLCPP_INFO(getLogger(), "Generating self-signed client certificate...");
        try
        {
          std::string cn_full = "CN=" + info_.name;
          std::string dns_full = "DNS:localhost";
          std::string uri_full = "URI:" + app_uri_;

          std::vector<opcua::String> subject = {opcua::String(cn_full), opcua::String("O=ROS 2")};
          std::vector<opcua::String> subjectAltName = {
            opcua::String(dns_full), opcua::String(uri_full)};

          auto result = opcua::createCertificate(subject, subjectAltName);
          client_cert_ = std::move(result.certificate);
          client_key_ = std::move(result.privateKey);
          RCLCPP_INFO(
            getLogger(), "Generated client certificate (%zu bytes)", client_cert_.length());
        }
        catch (const std::exception & e)
        {
          RCLCPP_ERROR(getLogger(), "Client certificate generation failed: %s.", e.what());
        }
      }

      // Set encryption if we have a certificate
      if (!client_cert_.empty() && !client_key_.empty())
      {
        // Prepare trustList and revocationList for UA_ClientConfig_setDefaultEncryption
        const UA_ByteString * trustList = nullptr;
        size_t trustListSize = 0;

        if (!ca_cert_.empty())
        {
          trustList = ca_cert_.handle();
          trustListSize = 1;
          RCLCPP_INFO(getLogger(), "Using CA certificate for server verification (trustList)");
        }

        UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(
          client.config().handle(), *client_cert_.handle(), *client_key_.handle(), trustList,
          trustListSize, nullptr, 0);

        if (retval != UA_STATUSCODE_GOOD)
        {
          RCLCPP_ERROR(
            getLogger(), "Failed to set default encryption: %s", UA_StatusCode_name(retval));
        }
        else
        {
          has_client_certificate_ = true;
          RCLCPP_INFO(getLogger(), "Client encryption configured successfully!");

          // Configure certificate verification based on CA availability
          if (!ca_cert_.empty())
          {
            // CA certificate is provided, always enable verification
            RCLCPP_INFO(getLogger(), "Certificate verification ENABLED with CA trustlist.");
          }
          else
          {
            // No CA certificate provided - disable verification (trust all certificates)
            client.config()->certificateVerification.clear = +[](UA_CertificateVerification *) {};
            client.config()->certificateVerification.verifyCertificate =
              +[](const UA_CertificateVerification *, const UA_ByteString *) -> UA_StatusCode
            { return UA_STATUSCODE_GOOD; };

            RCLCPP_WARN(
              getLogger(),
              "Certificate verification DISABLED (no CA certificate provided, trust all). "
              "This is INSECURE and should only be used for testing! "
              "Provide 'security.ca_certificate_path' to enable verification.");
          }
        }
      }
      else
      {
        RCLCPP_WARN(
          getLogger(), "No client certificate available. Will only use None security mode.");
      }
    }
    else
    {
      RCLCPP_INFO(getLogger(), "No secure endpoints found. Skipping certificate configuration.");
    }

    // Simplified Selection Logic: Just use Security Level (highest = best)
    const opcua::ua::EndpointDescription * selectedEndpoint = nullptr;
    const opcua::ua::UserTokenPolicy * selectedTokenPolicy = nullptr;
    uint8_t bestSecurityLevel = 0;

    for (const auto & endpoint : endpoints)
    {
      // Skip secure endpoints if we don't have a client certificate
      if (
        !has_client_certificate_ &&
        (endpoint.securityMode() == opcua::MessageSecurityMode::Sign ||
         endpoint.securityMode() == opcua::MessageSecurityMode::SignAndEncrypt))
      {
        continue;  // Skip this endpoint
      }

      // Check if we can authenticate with this endpoint
      const opcua::ua::UserTokenPolicy * candidatePolicy = nullptr;

      for (const auto & tokenPolicy : endpoint.userIdentityTokens())
      {
        if (!username.empty())
        {
          if (tokenPolicy.tokenType() == opcua::UserTokenType::Username)
          {
            candidatePolicy = &tokenPolicy;
            break;
          }
        }
        else if (!cert_path.empty())
        {
          if (tokenPolicy.tokenType() == opcua::UserTokenType::Certificate)
          {
            candidatePolicy = &tokenPolicy;
            break;
          }
        }
        else
        {
          if (tokenPolicy.tokenType() == opcua::UserTokenType::Anonymous)
          {
            candidatePolicy = &tokenPolicy;
            break;
          }
        }
      }

      // Select endpoint with highest security level
      if (candidatePolicy && endpoint.securityLevel() >= bestSecurityLevel)
      {
        bestSecurityLevel = endpoint.securityLevel();
        selectedEndpoint = &endpoint;
        selectedTokenPolicy = candidatePolicy;
      }
    }

    if (!selectedEndpoint || !selectedTokenPolicy)
    {
      RCLCPP_FATAL(getLogger(), "Could not find a suitable endpoint for provided credentials.");
      return false;
    }

    // Configure Client
    client.config()->securityMode =
      static_cast<UA_MessageSecurityMode>(selectedEndpoint->securityMode());
    UA_String_clear(&client.config()->securityPolicyUri);
    UA_String_copy(
      selectedEndpoint->securityPolicyUri().handle(), &client.config()->securityPolicyUri);

    // Set Application URI and Name using member variables (must match certificate SAN)
    UA_String_clear(&client.config()->clientDescription.applicationUri);
    client.config()->clientDescription.applicationUri = UA_STRING_ALLOC(app_uri_.c_str());
    UA_LocalizedText_clear(&client.config()->clientDescription.applicationName);
    client.config()->clientDescription.applicationName =
      UA_LOCALIZEDTEXT_ALLOC("en", app_name_.c_str());

    RCLCPP_INFO(getLogger(), "Client Application URI set to: %s", app_uri_.c_str());

    // Set User Identity
    if (selectedTokenPolicy->tokenType() == opcua::UserTokenType::Username)
    {
      UA_UserNameIdentityToken * identityToken = UA_UserNameIdentityToken_new();
      identityToken->userName = UA_STRING_ALLOC(username.c_str());
      identityToken->password = UA_STRING_ALLOC(password.c_str());
      // Use the policyId from the server
      UA_String_copy(selectedTokenPolicy->policyId().handle(), &identityToken->policyId);

      UA_ExtensionObject_clear(&client.config()->userIdentityToken);
      UA_ExtensionObject_setValue(
        &client.config()->userIdentityToken, identityToken,
        &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
    }
    else if (
      has_client_certificate_ &&
      selectedTokenPolicy->tokenType() == opcua::UserTokenType::Certificate)
    {
      UA_X509IdentityToken * identityToken = UA_X509IdentityToken_new();
      UA_String_copy(selectedTokenPolicy->policyId().handle(), &identityToken->policyId);

      // Pass the loaded certificate data if available
      if (!client_cert_.empty())
      {
        UA_ByteString_copy(client_cert_.handle(), &identityToken->certificateData);
      }

      UA_ExtensionObject_clear(&client.config()->userIdentityToken);
      UA_ExtensionObject_setValue(
        &client.config()->userIdentityToken, identityToken, &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]);
    }
    else
    {
      // Anonymous
      UA_AnonymousIdentityToken * identityToken = UA_AnonymousIdentityToken_new();
      UA_String_copy(selectedTokenPolicy->policyId().handle(), &identityToken->policyId);
      UA_ExtensionObject_clear(&client.config()->userIdentityToken);
      UA_ExtensionObject_setValue(
        &client.config()->userIdentityToken, identityToken,
        &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
    }

    // Print Client Configuration with security details
    opcua_helpers::print_client_info(
      client, getLogger(), client_cert_, client_key_, ca_cert_, selectedEndpoint->securityLevel());

    // Connect to the server using the credentials from the URDF
    RCLCPP_INFO(getLogger(), "\tConnection to the Endpoint URL: %s...", endpoint_url_.c_str());
    client.connect(endpoint_url_);

    // Connection failed
    if (!client.isConnected())
    {
      RCLCPP_FATAL(getLogger(), "\tCould not connect to the server.");
      return false;
    }

    RCLCPP_INFO(getLogger(), "\tConnection successful!");
  }
  catch (const std::out_of_range & ex)
  {
    RCLCPP_FATAL(getLogger(), "\tMissing required URDF <hardware> parameter: %s", ex.what());
    return false;
  }
  catch (const std::exception & ex)
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
  RCLCPP_INFO(
    getLogger(), "\tEstablishing correspondences between State interfaces and UA Nodes... ");

  auto init_state_interface_ua_nodes = [&](const auto & type_state_interfaces_)
  {
    for (const auto & [name, descr] : type_state_interfaces_)
    {
      std::string ua_ns_str;
      std::string ua_id_str;
      UAType ua_type;
      size_t num_elements = 1;
      size_t index = 0;  // By default the OPC UA element is considered scalar

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
      catch (const std::exception & e)
      {
        RCLCPP_ERROR(
          getLogger(), "Error parsing PLC parameters for state interface '%s': %s. Check URDF.",
          name.c_str(), e.what());
        continue;
      }

      ROSInterfaceUANode current_state_interface_ua_node;
      uint16_t ua_ns;
      uint32_t ua_identifier;

      // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and
      // uint32_t
      [[maybe_unused]] auto [ptr1, ec1] =
        std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(), ua_ns);
      [[maybe_unused]] auto [ptr2, ec2] =
        std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(), ua_identifier);

      opcua::NodeId node_id(ua_ns, ua_identifier);
      current_state_interface_ua_node.node_id = node_id;
      current_state_interface_ua_node.ua_type = ua_type;
      current_state_interface_ua_node.num_elements = num_elements;

      // Find if a state_interface with the same NodeId was already processed
      auto same_nodeid_state_interface_node =
        [&current_state_interface_ua_node](const auto & state_interface_ua_node)
      { return (state_interface_ua_node.node_id == current_state_interface_ua_node.node_id); };

      auto it = std::find_if(
        state_interfaces_nodes.begin(), state_interfaces_nodes.end(),
        same_nodeid_state_interface_node);

      ROSInterfaceMapping state_mapping;
      state_mapping.name = name;
      state_mapping.index = index;

      // OPC UA Array was already processed
      if (it != state_interfaces_nodes.end())
      {
        it->mappings.push_back(state_mapping);
      }
      else
      {
        // Add the name to the current interface_ua_node instead
        current_state_interface_ua_node.mappings.push_back(state_mapping);
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
  RCLCPP_INFO(
    getLogger(), "\tEstablishing correspondences between Command interfaces and UA Nodes... ");

  auto init_command_interface_ua_nodes = [&](const auto & type_command_interfaces_)
  {
    for (const auto & [name, descr] : type_command_interfaces_)
    {
      std::string ua_ns_str;
      std::string ua_id_str;
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
      catch (const std::exception & e)
      {
        RCLCPP_ERROR(
          getLogger(), "Error parsing PLC parameters for command interface '%s': %s. Check URDF.",
          name.c_str(), e.what());
        continue;
      }

      ROSInterfaceUANode current_command_interface_ua_node;
      uint16_t ua_ns;
      uint32_t ua_identifier;

      [[maybe_unused]] auto [ptr1, ec1] =
        std::from_chars(ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(), ua_ns);
      [[maybe_unused]] auto [ptr2, ec2] =
        std::from_chars(ua_id_str.data(), ua_id_str.data() + ua_id_str.size(), ua_identifier);

      opcua::NodeId node_id(ua_ns, ua_identifier);
      current_command_interface_ua_node.node_id = node_id;
      current_command_interface_ua_node.ua_type = ua_type;
      current_command_interface_ua_node.num_elements = num_elements;

      /* Find if a command_interface with the same NodeId was already processed */
      auto same_nodeid_command_interface_node =
        [&current_command_interface_ua_node](const auto & command_interface_ua_node)
      { return (command_interface_ua_node.node_id == current_command_interface_ua_node.node_id); };

      auto it = std::find_if(
        command_interfaces_nodes.begin(), command_interfaces_nodes.end(),
        same_nodeid_command_interface_node);

      ROSInterfaceMapping command_interface_mapping;
      command_interface_mapping.index = index;
      command_interface_mapping.name = name;

      // OPC UA Array was already processed, only populate command_interface_name
      if (it != command_interfaces_nodes.end())
      {
        it->mappings.push_back(command_interface_mapping);
      }
      else
      {
        // Create a new interfaceUANode object and add it to the command_interfaces_nodes vec
        current_command_interface_ua_node.mappings.push_back(command_interface_mapping);
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

  for (const auto & state_node : state_interfaces_nodes)
  {
    opcua::ReadValueId read_value;

    read_value->nodeId = state_node.node_id;
    read_value->attributeId = UA_ATTRIBUTEID_VALUE;  // (c.f wrapper.md line 94)
    read_items.push_back(read_value);
  }
}

hardware_interface::return_type OPCUAHardwareInterface::read(
  const rclcpp::Time & /*time*/, const rclcpp::Duration & /*period*/)
{
  bool any_item_read_failed = false;

  // Client lost connection to the UA server
  if (!client.isConnected())
  {
    RCLCPP_ERROR(
      getLogger(), "Hardware interface lost connection to the server during read operation.");
    any_item_read_failed = true;
  }

  // Perform ONE Read Request with all the desired NodeIds
  opcua::ReadRequest request(
    opcua::RequestHeader{},           // default header
    0.0,                              // maxAge
    opcua::TimestampsToReturn::Both,  // or Neither
    read_items                        // Span<const ReadValueId>
  );

  // Response will contain all the OPC UA variables with the same NodeIds
  opcua::ReadResponse response;

  try
  {
    response = opcua::services::read(client, request);  // (c.f attribute.hpp line 45)
  }
  catch (const std::exception & e)
  {
    RCLCPP_ERROR(getLogger(), "OPC UA read failed: %s", e.what());
    any_item_read_failed = true;
  }

  const auto & results = response.results();

  // There is missing information
  if (results.size() != state_interfaces_nodes.size())
  {
    RCLCPP_ERROR(
      getLogger(), "Read result size mismatch: expected %zu, got %zu",
      state_interfaces_nodes.size(), results.size());
    any_item_read_failed = true;
  }

  // Turn the results into an opcua::Variant
  for (size_t k = 0; k < results.size(); ++k)
  {
    const auto & state_node = state_interfaces_nodes[k];
    const auto & read_result = results[k];  // DataType class (c.f types.hpp line 1671)

    // Check if there was an issue while reading that specific UA value
    if (read_result.hasStatus() && read_result.status() != UA_STATUSCODE_GOOD)
    {
      RCLCPP_ERROR_THROTTLE(
        getLogger(), *get_clock(), 1000, "Bad read status for node (%u, %u)",
        state_node.node_id.namespaceIndex(), state_node.node_id.identifier<uint32_t>());

      any_item_read_failed = true;
      continue;
    }

    const opcua::Variant & ua_variant = read_result.value();

    switch (state_node.ua_type)
    {
      case UAType::UA_Boolean:
        any_item_read_failed = process_read_data<bool>(ua_variant, state_node);
        break;
      case UAType::UA_Byte:
        any_item_read_failed = process_read_data<uint8_t>(ua_variant, state_node);
        break;
      case UAType::UA_Int16:
        any_item_read_failed = process_read_data<int16_t>(ua_variant, state_node);
        break;
      case UAType::UA_UInt16:
        any_item_read_failed = process_read_data<uint16_t>(ua_variant, state_node);
        break;
      case UAType::UA_Int32:
        any_item_read_failed = process_read_data<int32_t>(ua_variant, state_node);
        break;
      case UAType::UA_UInt32:
        any_item_read_failed = process_read_data<uint32_t>(ua_variant, state_node);
        break;
      case UAType::UA_Int64:
        any_item_read_failed = process_read_data<int64_t>(ua_variant, state_node);
        break;
      case UAType::UA_UInt64:
        any_item_read_failed = process_read_data<uint64_t>(ua_variant, state_node);
        break;
      case UAType::UA_Float:
        any_item_read_failed = process_read_data<float>(ua_variant, state_node);
        break;
      case UAType::UA_Double:
        any_item_read_failed = process_read_data<double>(ua_variant, state_node);
        break;
      default:
        RCLCPP_ERROR_THROTTLE(getLogger(), *get_clock(), 2000, "Unknown UA type in read.");
        any_item_read_failed = true;
        break;
    }
  }
  return any_item_read_failed ? hardware_interface::return_type::ERROR
                              : hardware_interface::return_type::OK;
}

hardware_interface::return_type OPCUAHardwareInterface::write(
  const rclcpp::Time & /*time*/, const rclcpp::Duration & /*period*/)
{
  bool any_item_write_failed = false;

  // Client lost connection to the UA server
  if (!client.isConnected())
  {
    RCLCPP_ERROR(
      getLogger(), "Hardware interface lost connection to the server during write operation.");
    any_item_write_failed = true;
  }

  // There are no command interfaces to write to
  if (command_interfaces_nodes.size() == 0)
  {
    return hardware_interface::return_type::OK;
  }

  write_items.clear();
  // Reserve space for write request items
  write_items.reserve(command_interfaces_nodes.size());

  for (const auto & command_node : command_interfaces_nodes)
  {
    switch (command_node.ua_type)
    {
      case UAType::UA_Boolean:
        any_item_write_failed = process_write_node<bool>(command_node, write_items);
        break;
      case UAType::UA_Byte:
        any_item_write_failed = process_write_node<uint8_t>(command_node, write_items);
        break;
      case UAType::UA_Int16:
        any_item_write_failed = process_write_node<int16_t>(command_node, write_items);
        break;
      case UAType::UA_UInt16:
        any_item_write_failed = process_write_node<uint16_t>(command_node, write_items);
        break;
      case UAType::UA_Int32:
        any_item_write_failed = process_write_node<int32_t>(command_node, write_items);
        break;
      case UAType::UA_UInt32:
        any_item_write_failed = process_write_node<uint32_t>(command_node, write_items);
        break;
      case UAType::UA_Int64:
        any_item_write_failed = process_write_node<int64_t>(command_node, write_items);
        break;
      case UAType::UA_UInt64:
        any_item_write_failed = process_write_node<uint64_t>(command_node, write_items);
        break;
      case UAType::UA_Float:
        any_item_write_failed = process_write_node<float>(command_node, write_items);
        break;
      case UAType::UA_Double:
        any_item_write_failed = process_write_node<double>(command_node, write_items);
        break;
      default:
        continue;
    }
  }

  if (!write_items.empty())
  {
    // Make a single global request to write items
    opcua::ua::WriteRequest request{opcua::RequestHeader(), write_items};
    opcua::ua::WriteResponse response = opcua::services::write(client, request);

    const auto & results = response.results();
    for (size_t i = 0; i < results.size(); ++i)
    {
      // Issue detected during write
      if (results[i] != UA_STATUSCODE_GOOD)
      {
        RCLCPP_ERROR(
          getLogger(), "\tOPC UA write failed for node %zu with status 0x%08X", i,
          static_cast<uint32_t>(results[i]));
        any_item_write_failed = true;
      }
    }
  }

  return any_item_write_failed ? hardware_interface::return_type::ERROR
                               : hardware_interface::return_type::OK;
}

hardware_interface::CallbackReturn OPCUAHardwareInterface::on_shutdown(
  const rclcpp_lifecycle::State & /*previous_state*/)
{
  RCLCPP_INFO(getLogger(), "Disconnecting OPC UA client...");

  // Disconnect and close the connection to the server.
  client.disconnect();
  return hardware_interface::CallbackReturn::SUCCESS;
}

UAType OPCUAHardwareInterface::strToUAType(const std::string & type_str)
{
  if (type_str == "UA_Boolean")
  {
    return UAType::UA_Boolean;
  }
  if (type_str == "UA_Byte")
  {
    return UAType::UA_Byte;
  }
  if (type_str == "UA_Int16")
  {
    return UAType::UA_Int16;
  }
  if (type_str == "UA_UInt16")
  {
    return UAType::UA_UInt16;
  }
  if (type_str == "UA_Int32")
  {
    return UAType::UA_Int32;
  }
  if (type_str == "UA_UInt32")
  {
    return UAType::UA_UInt32;
  }
  if (type_str == "UA_Int64")
  {
    return UAType::UA_Int64;
  }
  if (type_str == "UA_UInt64")
  {
    return UAType::UA_UInt64;
  }
  if (type_str == "UA_Float")
  {
    return UAType::UA_Float;
  }
  if (type_str == "UA_Double")
  {
    return UAType::UA_Double;
  }

  RCLCPP_ERROR(getLogger(), "Unknown UA type string: '%s'", type_str.c_str());
  return UAType::UNKNOWN;
}

// returns true if any state interface value was not set properly
template <typename T>
bool OPCUAHardwareInterface::process_read_data(
  const opcua::Variant & ua_variant, const ROSInterfaceUANode & state_node)
{
  // Scalars
  if (ua_variant.isScalar())
  {
    // For scalar interfaces, mappings consists of only one element with index 0
    if (state_node.mappings.size() > 1 || state_node.mappings[0].index != 0)
    {
      RCLCPP_ERROR(
        getLogger(), "\tMismatch: Array State Interface %s is mapped to Scalar OPC UA value.",
        state_node.mappings[0].name.c_str());
      return true;
    }

    // Set the interface with the value read from the UA server
    T val = ua_variant.to<T>();
    set_state(state_node.mappings[0].name, static_cast<double>(val));
    return false;
  }

  // Arrays
  if (ua_variant.isArray())
  {
    auto ua_size = ua_variant.arrayLength();

    // Check first if the UA number of elements == ROS2 number of elements
    if (ua_size != state_node.num_elements)
    {
      RCLCPP_FATAL(
        getLogger(),
        "\tNumber of State Interfaces mapped to node ID (%u, %u) does not match the UA "
        "Array size on the server "
        "side.",
        state_node.node_id.namespaceIndex(), state_node.node_id.identifier<uint32_t>());
      return true;
    }

    auto values = ua_variant.to<std::vector<T>>();

    // Iterate only active mappings
    for (const auto & map : state_node.mappings)
    {
      // Make sure that the index stays within UA array bounds
      if (map.index < values.size())
      {
        set_state(map.name, static_cast<double>(values[map.index]));
      }
      else
      {
        RCLCPP_ERROR(
          getLogger(),
          "\tState Interface %s mapping index %zu is out of bounds. No matching UA array index "
          "found.",
          map.name.c_str(), map.index);
      }
    }
  }
  return false;
}

template <typename T>
bool OPCUAHardwareInterface::process_write_node(
  const ROSInterfaceUANode & node, std::vector<opcua::ua::WriteValue> & write_items_vector)
{
  // prepare the buffer
  std::vector<double> commands_to_send(node.num_elements, std::numeric_limits<double>::quiet_NaN());

  // fill the buffer
  for (const auto & map : node.mappings)
  {
    if (map.index >= commands_to_send.size())
    {
      RCLCPP_WARN(
        getLogger(),
        "\tCommand interface %s index %zu exceeds number of elements declared in URDF.",
        map.name.c_str(), map.index);
      continue;
    }

    double val = get_command(map.name);

    commands_to_send[map.index] = val;
  }

  // If ANY element in the array is NaN, we abort the entire write.
  // This is because we cannot partial-write without `indexRange`, and writing NaNs (which cast to
  // 0) would corrupt uncommanded indices.
  // TODO(habartakh): Implement OPC UA `indexRange` support to allow sparse/partial updates.
  /// This is an extension for later, maybe
  for (double val : commands_to_send)
  {
    if (std::isnan(val))
    {
      return true;  // write item failure
    }
  }

  opcua::Variant ua_variant;

  // scalar
  if (node.num_elements == 1)
  {
    ua_variant = opcua::Variant(static_cast<T>(commands_to_send[0]));
  }
  // array
  else
  {
    std::vector<T> ua_vals;
    ua_vals.reserve(commands_to_send.size());
    for (double v : commands_to_send)
    {
      ua_vals.push_back(static_cast<T>(v));
    }
    ua_variant = opcua::Variant(ua_vals);
  }

  // Fill write_items_vec with all the node IDs and corresponding data we want to write
  opcua::ua::WriteValue wv;
  wv.nodeId() = node.node_id;
  wv->attributeId = UA_ATTRIBUTEID_VALUE;
  wv.value() = opcua::DataValue(ua_variant);
  write_items_vector.push_back(std::move(wv));

  return false;  // no write items failure
}

// Explicit instantiations for template functions
template bool OPCUAHardwareInterface::process_read_data<bool>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<uint8_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<int16_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<uint16_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<int32_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<uint32_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<int64_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<uint64_t>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<float>(
  const opcua::Variant &, const ROSInterfaceUANode &);
template bool OPCUAHardwareInterface::process_read_data<double>(
  const opcua::Variant &, const ROSInterfaceUANode &);

template bool OPCUAHardwareInterface::process_write_node<bool>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<uint8_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<int16_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<uint16_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<int32_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<uint32_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<int64_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<uint64_t>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<float>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);
template bool OPCUAHardwareInterface::process_write_node<double>(
  const ROSInterfaceUANode &, std::vector<opcua::ua::WriteValue> &);

}  // namespace opcua_hardware_interface

#include "pluginlib/class_list_macros.hpp"

PLUGINLIB_EXPORT_CLASS(
  opcua_hardware_interface::OPCUAHardwareInterface, hardware_interface::SystemInterface)
