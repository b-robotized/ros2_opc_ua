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

// Constants
static const char * APP_NAME = "ros2_opc_ua server example";
static const char * APP_URI = "urn:open62541pp.server.application:ros2_opc_ua";

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

  // Declare parameters
  // bool allow_anonymous = node->declare_parameter("allow_anonymous", true); // always allowed in
  // this example
  std::string security_policy =
    node->declare_parameter("security.policy", "Sign");  // None, Sign, SignAndEncrypt
  std::string cert_path = node->declare_parameter("security.certificate_path", "");
  std::string key_path = node->declare_parameter("security.private_key_path", "");
  bool auto_generate_certs = node->declare_parameter("security.auto_generate_certificates", false);

  // If paths are empty, try to find them in the package share directory or source dir as fallback
  // (Though typically launch file provides them)
  if (cert_path.empty() || key_path.empty())
  {
    // Fallback for running without launch file in dev environment
    cert_path = "src/ros2_opc_ua/opcua_bringup/config/server_cert.der";
    key_path = "src/ros2_opc_ua/opcua_bringup/config/server_key.der";
    RCLCPP_WARN(
      node->get_logger(), "No certificate paths provided. Using fallback dev paths: %s",
      cert_path.c_str());
  }

  opcua::ByteString certificate;
  opcua::ByteString privateKey;

  // Load or Generate Certificates
  // We ALWAYS try to load or generate certificates if possible, because even for "None" security
  // policy or "Sign" (without Encrypt), we might want to have certificates configured to support
  // all endpoints. The 'security.policy' parameter mainly guides whether we enforce them or error
  // out if missing, but if we can load them, we should.

  // Try loading from file
  try
  {
    std::ifstream f(cert_path);
    if (f.good())
    {
      certificate = readFile(cert_path);
      privateKey = readFile(key_path);
      RCLCPP_INFO(node->get_logger(), "Loaded certificate from %s", cert_path.c_str());
    }
    else if (!cert_path.empty())  // Only warn if path was explicitly set or defaulted non-empty
    {
      RCLCPP_WARN(node->get_logger(), "Certificate not found at %s", cert_path.c_str());
    }
  }
  catch (...)
  {
  }

  // If loading failed and auto-generate is enabled
  if ((certificate.empty() || privateKey.empty()) && auto_generate_certs)
  {
    RCLCPP_INFO(node->get_logger(), "Generating self-signed certificate...");
    try
    {
      auto result = opcua::createCertificate(
        {{"CN", APP_NAME}, {"O", "ROS 2"}}, {{"DNS", "localhost"}, {"URI", APP_URI}});
      certificate = std::move(result.certificate);
      privateKey = std::move(result.privateKey);
    }
    catch (const std::exception & e)
    {
      RCLCPP_ERROR(node->get_logger(), "Certificate generation failed: %s", e.what());
      return 1;
    }
  }

  // Check requirements based on requested policy
  if (security_policy != "None" && (certificate.empty() || privateKey.empty()))
  {
    RCLCPP_ERROR(
      node->get_logger(),
      "Security Policy '%s' requested but no valid certificate found or generated. Exiting.",
      security_policy.c_str());
    return 1;
  }

  // Create server config
  std::unique_ptr<opcua::ServerConfig> config_ptr;

  if (!certificate.empty() && !privateKey.empty())
  {
    // Config with encryption
    config_ptr = std::make_unique<opcua::ServerConfig>(
      4840, certificate, privateKey, opcua::Span<const opcua::ByteString>{},
      opcua::Span<const opcua::ByteString>{});
  }
  else
  {
    // Config without encryption (only None)
    config_ptr = std::make_unique<opcua::ServerConfig>();
  }

  opcua::ServerConfig & config = *config_ptr;

  // Use handle to access the open62541 methods
  UA_ServerConfig * ua_server_config = config.handle();

  // Set Endpoint URL to bind to all interfaces
  std::string url = "opc.tcp://127.0.0.1:4840";

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

  config.setApplicationName(APP_NAME);
  config.setApplicationUri(APP_URI);

  // Configure User Token Policies - using defaults plus AccessControl logic for now
  // as manual configuration of policies via low-level API is version dependent.
  // The ServerConfig constructor with certificates enables standard security policies.

  // Manually update the security levels of the endpoints to allow clients to select the best one
  // open62541 default logic often sets them based on policy URI length or similar,
  // but we want to enforce standard recommendation: SignAndEncrypt > Sign > None.
  for (size_t i = 0; i < ua_server_config->endpointsSize; ++i)
  {
    UA_EndpointDescription * endpoint = &ua_server_config->endpoints[i];
    if (endpoint->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
    {
      endpoint->securityLevel = 115;
    }
    else if (endpoint->securityMode == UA_MESSAGESECURITYMODE_SIGN)
    {
      endpoint->securityLevel = 65;
    }
    else
    {
      endpoint->securityLevel = 0;
    }

    // Force standard Policy IDs for User Token Policies
    for (size_t j = 0; j < endpoint->userIdentityTokensSize; ++j)
    {
      UA_UserTokenPolicy * policy = &endpoint->userIdentityTokens[j];
      if (policy->tokenType == UA_USERTOKENTYPE_USERNAME)
      {
        UA_String_clear(&policy->policyId);

        // Construct PolicyID based on Security Policy
        // Format: UserName_<Algorithm>_Token
        std::string policyUri(
          reinterpret_cast<char *>(policy->securityPolicyUri.data),
          policy->securityPolicyUri.length);
        std::string algorithm = "None";

        if (policyUri.find("Basic128Rsa15") != std::string::npos)
        {
          algorithm = "Basic128Rsa15";
        }
        else if (policyUri.find("Basic256Sha256") != std::string::npos)
        {
          algorithm = "Basic256Sha256";
        }
        else if (policyUri.find("Basic256") != std::string::npos)
        {
          algorithm = "Basic256";
        }
        else if (policyUri.find("Aes128_Sha256_RsaOaep") != std::string::npos)
        {
          algorithm = "Aes128Sha256RsaOaep";
        }
        else if (policyUri.find("Aes256_Sha256_RsaPss") != std::string::npos)
        {
          algorithm = "Aes256Sha256RsaPss";
        }

        // Special case for None
        if (algorithm == "None")
        {
          // For None security policy, the username token is usually unencrypted or encrypted with
          // None (?) Actually, OPC UA spec says UserName token policy usually has a security policy
          // URI associated with it. If the endpoint is None, the token policy must be None or use a
          // specific policy if available. open62541 default for None endpoint is UserName with None
          // policy. Let's call it UserName_None_Token or similar if we want consistent naming, but
          // standard usually implies encryption. If the user wants specific names, we enforce them.
          // If algorithm is None, we might skip "Token" suffix or keep it.
          policy->policyId = UA_STRING_ALLOC("UserName_None_Token");
        }
        else
        {
          std::string newId = "UserName_" + algorithm + "_Token";
          policy->policyId = UA_STRING_ALLOC(newId.c_str());
        }
      }
    }
  }

  AccessControlCustom accessControl{
    true,  // allow anonymous (always allowed)
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
