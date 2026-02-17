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

      StateInterfaceUANode current_state_interface_ua_node;

      // Use C++ 17 from_chars to convert the URDF string parameters into uint16_t and
      // uint32_t
      [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(
        ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(),
        current_state_interface_ua_node.ua_ns);
      [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(
        ua_id_str.data(), ua_id_str.data() + ua_id_str.size(),
        current_state_interface_ua_node.ua_identifier);
      current_state_interface_ua_node.ua_type = ua_type;
      current_state_interface_ua_node.num_elements = num_elements;

      // Find if a state_interface with the same NodeId was already processed
      auto same_nodeid_state_interface_node =
        [&current_state_interface_ua_node](const auto & state_interface_ua_node)
      {
        return (state_interface_ua_node.ua_ns == current_state_interface_ua_node.ua_ns) &&
               (state_interface_ua_node.ua_identifier ==
                current_state_interface_ua_node.ua_identifier);
      };
      auto it = std::find_if(
        state_interfaces_nodes.begin(), state_interfaces_nodes.end(),
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
  RCLCPP_INFO(
    getLogger(), "\tEstablishing correspondences between Command interfaces and UA Nodes... ");

  auto init_command_interface_ua_nodes = [&](const auto & type_command_interfaces_)
  {
    for (const auto & [name, descr] : type_command_interfaces_)
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
      catch (const std::exception & e)
      {
        RCLCPP_ERROR(
          getLogger(), "Error parsing PLC parameters for command interface '%s': %s. Check URDF.",
          name.c_str(), e.what());
        continue;
      }

      CommandInterfaceUANode current_command_interface_ua_node;

      [[maybe_unused]] auto [ptr1, ec1] = std::from_chars(
        ua_ns_str.data(), ua_ns_str.data() + ua_ns_str.size(),
        current_command_interface_ua_node.ua_ns);
      [[maybe_unused]] auto [ptr2, ec2] = std::from_chars(
        ua_id_str.data(), ua_id_str.data() + ua_id_str.size(),
        current_command_interface_ua_node.ua_identifier);
      current_command_interface_ua_node.ua_type = ua_type;
      current_command_interface_ua_node.num_elements = num_elements;

      /* Fallback State Interface Name = State interface with the same NodeId */
      auto same_nodeid_state_interface_node =
        [&current_command_interface_ua_node](const auto & state_interface_ua_node)
      {
        return (state_interface_ua_node.ua_ns == current_command_interface_ua_node.ua_ns) &&
               (state_interface_ua_node.ua_identifier ==
                current_command_interface_ua_node.ua_identifier);
      };
      auto it_fallback = find_if(
        state_interfaces_nodes.begin(), state_interfaces_nodes.end(),
        same_nodeid_state_interface_node);

      // Found a fallback state interface:
      if (it_fallback != state_interfaces_nodes.end())
      {
        fallback_name = it_fallback->state_interface_names.at(index);
        // current_command_interface_ua_node.fallback_state_interface_names.emplace(std::make_pair(index,
        // fallback_name));
        RCLCPP_INFO(
          getLogger(), "\tThe following command interface: %s has a fallback state interface: %s.",
          name.c_str(), fallback_name.c_str());
      }

      /* Find if a command_interface with the same NodeId was already processed */
      auto same_nodeid_command_interface_node =
        [&current_command_interface_ua_node](const auto & command_interface_ua_node)
      {
        return (command_interface_ua_node.ua_ns == current_command_interface_ua_node.ua_ns) &&
               (command_interface_ua_node.ua_identifier ==
                current_command_interface_ua_node.ua_identifier);
      };
      auto it = std::find_if(
        command_interfaces_nodes.begin(), command_interfaces_nodes.end(),
        same_nodeid_command_interface_node);

      // OPC UA Array was already processed, only populate command_interface_name and
      // fallback_name maps
      if (it != command_interfaces_nodes.end())
      {
        it->command_interface_names.emplace(std::make_pair(index, name));
        it->fallback_state_interface_names.emplace(std::make_pair(index, fallback_name));
      }
      else
      {
        // Create a whole interfaceUANode element and add it to the command_interfaces_nodes
        // vector
        current_command_interface_ua_node.command_interface_names.emplace(
          std::make_pair(index, name));
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

  for (const auto & state_node : state_interfaces_nodes)
  {
    opcua::ReadValueId read_value;
    opcua::NodeId node_id(state_node.ua_ns, state_node.ua_identifier);

    read_value->nodeId = node_id;
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
    const auto & state_interface_ua_node = state_interfaces_nodes[k];
    const auto & read_result = results[k];  // DataType class (c.f types.hpp line 1671)

    // Check if there was an issue while reading that specific UA value
    if (read_result.hasStatus() && read_result.status() != UA_STATUSCODE_GOOD)
    {
      RCLCPP_ERROR_THROTTLE(
        getLogger(), *get_clock(), 1000, "Bad read status for node (%u, %u)",
        state_interface_ua_node.ua_ns, state_interface_ua_node.ua_identifier);

      any_item_read_failed = true;
      continue;
    }

    const opcua::Variant & ua_variant = read_result.value();

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
        RCLCPP_ERROR_THROTTLE(
          getLogger(), *get_clock(), 1000,
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
      const UA_DataType * type = ua_variant.type();

      // Check if the UA number of elements == ROS2 number of elements
      if (ua_size != state_interface_ua_node.num_elements)
      {
        RCLCPP_FATAL(
          getLogger(),
          "\tState interface declared for nodeId (%u, %u) number of elements "
          "does not match the UA "
          "Array size on the server side.",
          state_interface_ua_node.ua_ns, state_interface_ua_node.ua_identifier);
        any_item_read_failed = true;
      }

      // TODO(habartakh) : Find a more concise way to write to vectors

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

  // Reserve space for write request items
  write_items.reserve(command_interfaces_nodes.size());

  for (const auto & command_interface_ua_node : command_interfaces_nodes)
  {
    opcua::Variant ua_variant;  // will be used to write the value to the OPC UA server
    std::string command_interface_name = command_interface_ua_node.command_interface_names.at(0);

    // if the command interface is scalar
    if (command_interface_ua_node.num_elements == 1)
    {
      // store the current val and reset the ros-side command value
      double val = get_command(command_interface_name);
      set_command(command_interface_name, std::numeric_limits<double>::quiet_NaN());

      if (std::isnan(val))
      {
        continue;
      }
      ua_variant = get_scalar_command_variant(command_interface_ua_node.ua_type, val);

      RCLCPP_INFO(
          getLogger(),
          "Sending data to server. IF: %s  | %f", command_interface_name.c_str(), val);
    }
    else  // if the command interface is an array
    {
      std::vector<double> command_vector = get_command_vector(command_interface_ua_node);

      if (command_vector.empty())
      {
        continue;  // Do no send a Write Request
      }

      ua_variant = get_array_command_variant(command_interface_ua_node.ua_type, command_vector);
    }

    // Send a request containing all the OPCUA node Ids we want to write
    opcua::ua::WriteValue write_value;  // (c.f types.hpp line 1429)
    write_value.nodeId() =
      opcua::NodeId(command_interface_ua_node.ua_ns, command_interface_ua_node.ua_identifier);
    write_value->attributeId = UA_ATTRIBUTEID_VALUE;
    write_value.value() = opcua::DataValue(ua_variant);

    write_items.push_back(std::move(write_value));
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

// Helper function that returns the ROS2 interface_value depending on the OPC UA type
double OPCUAHardwareInterface::get_interface_value(
  UAType ua_type, const opcua::Variant & ua_variant)
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
std::vector<double> OPCUAHardwareInterface::get_command_vector(
  const CommandInterfaceUANode & command_ua_node)
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
      return command_vector; // if any command in an array is NaN, skip writing this cycle
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
      RCLCPP_ERROR_THROTTLE(
        getLogger(), *get_clock(), 1000,
        "Unhandled or UNKNOWN UA type for the interface during write.");

      // TODO(habartakh): Add a flag to return the error inside write
      break;
  }

  return ua_variant;
}

opcua::Variant OPCUAHardwareInterface::get_array_command_variant(
  UAType ua_type, std::vector<double> & command_array)
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
      RCLCPP_ERROR_THROTTLE(
        getLogger(), *get_clock(), 1000,
        "Unhandled or UNKNOWN UA type for the interface during write.");
      // TODO(habartakh): Add a flag to return an error inside the write function
      break;
  }

  return command_variant;
}

}  // namespace opcua_hardware_interface

#include "pluginlib/class_list_macros.hpp"

PLUGINLIB_EXPORT_CLASS(
  opcua_hardware_interface::OPCUAHardwareInterface, hardware_interface::SystemInterface)
