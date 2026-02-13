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

#include <cmath>
#include <fstream>  // for file checks
#include <iostream>
#include <vector>

#include <open62541pp/node.hpp>
#include <open62541pp/plugin/accesscontrol_default.hpp>
#include <open62541pp/server.hpp>
#include <open62541pp/types.hpp>
#include "open62541pp/callback.hpp"

// Include create_certificate if available, otherwise we will use external files
#include <open62541pp/config.hpp>
#if UAPP_HAS_CREATE_CERTIFICATE
#include <open62541pp/plugin/create_certificate.hpp>
#endif

#include "rclcpp/rclcpp.hpp"

using opcua::AccessControlDefault;
using opcua::AccessLevel;
using opcua::ua::DataTypeId;
using opcua::ua::EndpointDescription;

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

// Custom access control based on AccessControlDefault.
class AccessControlCustom : public AccessControlDefault
{
public:
  using AccessControlDefault::AccessControlDefault;  // inherit constructors
  AccessControlCustom(
    bool allow_anonymous, const std::initializer_list<opcua::Login> & logins, rclcpp::Logger logger)
  : AccessControlDefault(allow_anonymous, logins), logger_(logger)
  {
  }

  opcua::StatusCode activateSession(
    opcua::Session & session, const EndpointDescription & endpointDescription,
    const opcua::ByteString & secureChannelRemoteCertificate,
    const opcua::ExtensionObject & userIdentityToken) override
  {
    // Check for unsafe configuration: UserName + SecurityMode::None
    const auto * token = userIdentityToken.decodedData<opcua::ua::UserNameIdentityToken>();
    if (token != nullptr)
    {
      if (endpointDescription.securityMode() == opcua::MessageSecurityMode::None)
      {
        RCLCPP_WARN(
          logger_,
          "Security Warning: UserName authentication used over insecure channel (SecurityMode: "
          "None)! This is not safe.");
      }
    }

    // Grant admin rights if user is logged in as "admin"
    // Store attribute "isAdmin" as session attribute to use it in access callbacks
    const auto * userToken = userIdentityToken.decodedData<opcua::ua::UserNameIdentityToken>();
    const bool isAdmin = (userToken != nullptr && userToken->userName() == "admin");
    if (isAdmin)
    {
      std::cout << "User has admin rights: " << isAdmin << std::endl;
      session.setSessionAttribute({0, "isAdmin"}, opcua::Variant{isAdmin});
    }

    // Handle Certificate Authentication (for logging purposes)
    const auto * certToken = userIdentityToken.decodedData<opcua::ua::X509IdentityToken>();
    if (certToken != nullptr)
    {
      std::cout << "User authenticated via Certificate." << std::endl;
    }

    return AccessControlDefault::activateSession(
      session, endpointDescription, secureChannelRemoteCertificate, userIdentityToken);
  }

  opcua::Bitmask<AccessLevel> getUserAccessLevel(
    opcua::Session & session, const opcua::NodeId & /*nodeId */) override
  {
    const bool isAdmin = session.getSessionAttribute({0, "isAdmin"}).scalar<bool>();
    return isAdmin ? AccessLevel::CurrentRead | AccessLevel::CurrentWrite
                   : AccessLevel::CurrentRead;
  }

private:
  rclcpp::Logger logger_;
};

int main(int argc, char ** argv)
{
  rclcpp::init(argc, argv);
  auto node = std::make_shared<rclcpp::Node>("opcua_server_node");

  // Hardcode configuration for demonstration purposes as requested
  // Certificates path (using the generated 100-year valid certs)
  std::string cert_path = "src/ros2_opc_ua/opcua_bringup/config/server_cert.der";
  std::string key_path = "src/ros2_opc_ua/opcua_bringup/config/server_key.der";

  // Try to resolve package path if running from install to find config
  try
  {
    std::ifstream f(cert_path);
    if (!f.good())
    {
      RCLCPP_WARN(
        node->get_logger(), "Certificate not found at %s, checking if running from install...",
        cert_path.c_str());
    }
  }
  catch (...)
  {
  }

  opcua::ByteString certificate = readFile(cert_path);
  opcua::ByteString privateKey = readFile(key_path);

  if (certificate.empty() || privateKey.empty())
  {
    RCLCPP_ERROR(
      node->get_logger(), "Failed to load certificates from %s. Please run from workspace root.",
      cert_path.c_str());
    return 1;
  }

  // Create server config with encryption support (Sign/SignAndEncrypt + None)
  // This constructor automatically adds policies: None, Basic128Rsa15, Basic256, Basic256Sha256
  auto config_ptr = std::make_unique<opcua::ServerConfig>(
    4840, certificate, privateKey, opcua::Span<const opcua::ByteString>{},
    opcua::Span<const opcua::ByteString>{});

  opcua::ServerConfig & config = *config_ptr;

  // Use handle to access the open62541 methods
  UA_ServerConfig * ua_server_config = config.handle();

  // Set Endpoint URL to bind to all interfaces
  std::string url = "opc.tcp://0.0.0.0:4840";

  if (ua_server_config->serverUrlsSize > 0)
  {
    for (size_t i = 0; i < ua_server_config->serverUrlsSize; i++)
    {
      UA_String_clear(&ua_server_config->serverUrls[i]);
    }
    UA_free(ua_server_config->serverUrls);
  }
  ua_server_config->serverUrls = reinterpret_cast<UA_String *>(UA_malloc(sizeof(UA_String)));
  ua_server_config->serverUrlsSize = 1;
  ua_server_config->serverUrls[0] = UA_STRING_ALLOC(url.c_str());

  config.setApplicationName("ros2_opc_ua server example");
  config.setApplicationUri("urn:open62541pp.server.application:ros2_opc_ua");

  // Configure User Token Policies - using defaults plus AccessControl logic for now
  // as manual configuration of policies via low-level API is version dependent.
  // The ServerConfig constructor with certificates enables standard security policies.

  AccessControlCustom accessControl{
    true,  // allow anonymous
    {
      opcua::Login{opcua::String{"admin"}, opcua::String{"ua_password"}},
    },
    node->get_logger()};

  config.setAccessControl(accessControl);
  config->allowNonePolicyPassword = true;  // Allow UserName on None policy

  opcua::Server server{std::move(config)};

  // Add a variable node to the Objects node
  opcua::Node parentNode{server, opcua::ObjectId::ObjectsFolder};

  opcua::Node myIntegerNode = parentNode.addVariable(
    {1, 1},                      // nodeId (ns=1 ; s=1)
    "The Answer",                // browse name
    opcua::VariableAttributes{}  // attributes (c.f node.hpp line 156)
      .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
      .setDisplayName({"en-US", "The Answer"})
      .setDescription({"en-US", "Answer to the Ultimate Question of Life"})
      .setDataType<int>()
      .setValueRank(opcua::ValueRank::Scalar)
      .setValue(opcua::Variant{42}));

  std::vector<float> currentPos{0.15, -1.25};
  opcua::Node currentPosNode = parentNode.addVariable(
    {1, 10}, "Current Position Array",
    opcua::VariableAttributes{}
      .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
      .setDisplayName({"en-US", "Array of current position"})
      .setDataType(DataTypeId::Float)
      .setArrayDimensions({0})                       // single dimension but unknown in size
      .setValueRank(opcua::ValueRank::OneDimension)  // (c.f common.hpp line 157)
      .setValue(opcua::Variant{currentPos}));

  std::vector<UA_Boolean> commandPos = {UA_FALSE, UA_TRUE};
  // std::bool is not supported, UA_Boolean is uint8_t
  opcua::Node commandPosNode = parentNode.addVariable(
    {1, 11}, "Command Position Array",
    opcua::VariableAttributes{}
      .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
      .setDisplayName({"en-US", "Array of boolean command position"})
      .setDataType(DataTypeId::Boolean)
      .setArrayDimensions({0})                       //! single dimension but unknown in size
      .setValueRank(opcua::ValueRank::OneDimension)  //! (c.f common.hpp line 157)
      .setValue(opcua::Variant{commandPos}));

  // Add a callback fucnction to simulate change over time
  size_t counter = 0;
  const double interval = 500;  // milliseconds
  float angle;
  const opcua::CallbackId id1 = opcua::addRepeatedCallback(
    server,
    [&]
    {
      if (counter % 10 == 0)
      {
        commandPos[0] = !commandPos[0];
        commandPos[1] = !commandPos[1];
      }
      angle = static_cast<float>(counter) * 0.01f;
      currentPos[0] = std::sin(angle);
      currentPos[1] = std::cos(angle);

      ++counter;
      std::cout << "commandPos is: [ " << commandPos[0] << " , " << commandPos[1] << " ]"
                << std::endl;
      std::cout << "CurrentPos is: [ " << currentPos[0] << " , " << currentPos[1] << " ]"
                << std::endl;

      commandPosNode.writeValue(opcua::Variant(commandPos));
      currentPosNode.writeValue(opcua::Variant(currentPos));
    },
    interval);

  // Read the initial value (attribute) from the node
  auto answerVal = myIntegerNode.readValue();
  std::cout << "The answer is: " << answerVal.to<int>() << std::endl;

  auto currentPosVal = currentPosNode.readValue().to<std::vector<float>>();
  std::cout << "The curentPos is: [ " << currentPosVal.at(0) << " , " << currentPosVal.at(1)
            << " ]." << std::endl;

  auto commandPosVal = commandPosNode.readValue().to<std::vector<bool>>();
  std::cout << "The commandPos is: [ " << commandPosVal.at(0) << " , " << commandPosVal.at(1)
            << " ]." << std::endl;

  RCLCPP_INFO(node->get_logger(), "Server running. Press Ctrl+C to stop.");

  // Run the server loop manually to integrate with ROS 2 spin
  while (rclcpp::ok())
  {
    server.runIterate();
    rclcpp::spin_some(node);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  RCLCPP_INFO(node->get_logger(), "Stopping server...");

  opcua::removeCallback(server, id1);
  rclcpp::shutdown();
}
