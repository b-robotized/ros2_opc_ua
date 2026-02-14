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
#include <map>
#include <vector>

#include <open62541pp/client.hpp>
#include <open62541pp/node.hpp>
#include <open62541pp/plugin/accesscontrol_default.hpp>
#include <open62541pp/server.hpp>
#include <open62541pp/types.hpp>
#include "open62541pp/callback.hpp"

// Include create_certificate if available, otherwise we will use external files
#include <open62541pp/config.hpp>
#include <open62541pp/plugin/create_certificate.hpp>

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

// Helpers for printing
static std::string toString(UA_MessageSecurityMode mode)
{
  switch (mode)
  {
    case UA_MESSAGESECURITYMODE_INVALID:
      return "Invalid";
    case UA_MESSAGESECURITYMODE_NONE:
      return "None";
    case UA_MESSAGESECURITYMODE_SIGN:
      return "Sign";
    case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT:
      return "Sign and Encrypt";
    default:
      return "Unknown";
  }
}

static std::string toString(UA_UserTokenType type)
{
  switch (type)
  {
    case UA_USERTOKENTYPE_ANONYMOUS:
      return "Anonymous";
    case UA_USERTOKENTYPE_USERNAME:
      return "UserName";
    case UA_USERTOKENTYPE_CERTIFICATE:
      return "Certificate";
    case UA_USERTOKENTYPE_ISSUEDTOKEN:
      return "IssuedToken";
    default:
      return "Unknown";
  }
}

static std::string to_string(const UA_String & s)
{
  if (s.length == 0)
  {
    return "";
  }
  return std::string(reinterpret_cast<char *>(s.data), s.length);
}

static void print_server_endpoints(const UA_ServerConfig * config, const rclcpp::Logger & logger)
{
  std::stringstream ss;
  ss << "\nServer Configuration:\n";

  // Application Info
  ss << "\tName:             " << to_string(config->applicationDescription.applicationName.text)
     << "\n"
     << "\tApplication URI:  " << to_string(config->applicationDescription.applicationUri) << "\n"
     << "\tProduct URI:      " << to_string(config->applicationDescription.productUri) << "\n";

  // Endpoints
  if (config->endpointsSize > 0)
  {
    ss << "\tEndpoints:\n";
    for (size_t i = 0; i < config->endpointsSize; ++i)
    {
      const UA_EndpointDescription & endpoint = config->endpoints[i];
      ss << "\t  Endpoint[" << i << "]:\n"
         << "\t  - Endpoint URL:      " << to_string(endpoint.endpointUrl) << "\n"
         << "\t  - Transport profile: " << to_string(endpoint.transportProfileUri) << "\n"
         << "\t  - Security mode:     " << toString(endpoint.securityMode) << "\n"
         << "\t  - Security profile:  " << to_string(endpoint.securityPolicyUri) << "\n"
         << "\t  - Security level:    " << static_cast<int>(endpoint.securityLevel)
         << (endpoint.securityLevel == 0 ? " (None)" : "") << "\n";

      // Certificate info
      if (endpoint.serverCertificate.length > 0)
      {
        ss << "\t  - Certificate:       Present (" << endpoint.serverCertificate.length
           << " bytes)\n";
      }
      else
      {
        ss << "\t  - Certificate:       None\n";
      }

      ss << "\t  - User identity tokens:\n";

      for (size_t j = 0; j < endpoint.userIdentityTokensSize; ++j)
      {
        const UA_UserTokenPolicy & token = endpoint.userIdentityTokens[j];
        ss << "\t    - PolicyId: " << to_string(token.policyId)
           << ", TokenType: " << toString(token.tokenType)
           << ", SecurityPolicy: " << to_string(token.securityPolicyUri) << "\n";
      }
    }
  }
  else
  {
    ss << "\tNo endpoints configured.\n";
  }
  RCLCPP_INFO_STREAM(logger, ss.str());
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
  std::string cert_path = node->declare_parameter("security.certificate_path", "");
  std::string key_path = node->declare_parameter("security.private_key_path", "");

  opcua::ByteString loadedCertificate;
  opcua::ByteString loadedPrivateKey;
  opcua::ByteString generatedCertificate;
  opcua::ByteString generatedPrivateKey;

  // Storage to track which certificate is used for which policy
  std::map<std::string, std::string> certificateMapping;

  // 1. Try to load from file if paths are provided
  if (!cert_path.empty() && !key_path.empty())
  {
    try
    {
      std::ifstream f(cert_path);
      if (f.good())
      {
        loadedCertificate = readFile(cert_path);
        loadedPrivateKey = readFile(key_path);
        RCLCPP_INFO(
          node->get_logger(), "Loaded certificate from %s (%zu bytes)", cert_path.c_str(),
          loadedCertificate.length());
      }
      else
      {
        RCLCPP_WARN(node->get_logger(), "Certificate file not found at %s", cert_path.c_str());
      }
    }
    catch (...)
    {
      RCLCPP_WARN(node->get_logger(), "Error reading certificate files.");
    }
  }

  // 2. Always generate self-signed certificate
  RCLCPP_INFO(node->get_logger(), "Generating self-signed certificate...");
  try
  {
    auto result = opcua::createCertificate(
      {{"CN", APP_NAME}, {"O", "ROS 2"}}, {{"DNS", "localhost"}, {"URI", APP_URI}});
    generatedCertificate = std::move(result.certificate);
    generatedPrivateKey = std::move(result.privateKey);
    RCLCPP_INFO(
      node->get_logger(), "Generated certificate (%zu bytes)", generatedCertificate.length());
  }
  catch (const std::exception & e)
  {
    RCLCPP_ERROR(node->get_logger(), "Certificate generation failed: %s", e.what());
  }

  // 3. Select primary certificate (prefer loaded)
  const opcua::ByteString * primaryCert = nullptr;
  const opcua::ByteString * primaryKey = nullptr;
  std::string primarySource;

  if (!loadedCertificate.empty() && !loadedPrivateKey.empty())
  {
    primaryCert = &loadedCertificate;
    primaryKey = &loadedPrivateKey;
    primarySource = "LOADED";
    RCLCPP_INFO(
      node->get_logger(), "Using LOADED certificate as primary for stronger security policies.");
  }
  else if (!generatedCertificate.empty() && !generatedPrivateKey.empty())
  {
    primaryCert = &generatedCertificate;
    primaryKey = &generatedPrivateKey;
    primarySource = "GENERATED";
    RCLCPP_INFO(node->get_logger(), "Using GENERATED certificate as primary.");
  }
  else
  {
    RCLCPP_ERROR(
      node->get_logger(),
      "No valid certificates available. Security policies will be limited to None.");
  }

  // Create server config
  std::unique_ptr<opcua::ServerConfig> config_ptr;

  if (primaryCert && primaryKey && !primaryCert->empty() && !primaryKey->empty())
  {
    // Config with encryption
    config_ptr = std::make_unique<opcua::ServerConfig>(
      4840, *primaryCert, *primaryKey, opcua::Span<const opcua::ByteString>{},
      opcua::Span<const opcua::ByteString>{});

    // Record which policies use primary cert (default: all)
    certificateMapping["#None"] = primarySource;
    certificateMapping["#Basic256Sha256"] = primarySource;
    certificateMapping["#Aes256_Sha256_RsaPss"] = primarySource;
    certificateMapping["#Aes128_Sha256_RsaOaep"] = primarySource;
  }
  else
  {
    // Config without encryption (only None)
    RCLCPP_WARN(
      node->get_logger(),
      "Starting server without certificates. Only 'None' security policy will be available.");
    config_ptr = std::make_unique<opcua::ServerConfig>();
    certificateMapping["#None"] = "NONE";
  }

  opcua::ServerConfig & config = *config_ptr;

  // Use handle to access the open62541 methods
  UA_ServerConfig * ua_server_config = config.handle();

  // OVERRIDE: If BOTH certificates are available, use GENERATED for weaker policies
  if (
    !loadedCertificate.empty() && !loadedPrivateKey.empty() && !generatedCertificate.empty() &&
    !generatedPrivateKey.empty())
  {
    RCLCPP_INFO(node->get_logger(), "Both certificates available. Splitting policies...");
    RCLCPP_INFO(
      node->get_logger(), "  - Weaker policies (Basic128Rsa15, Aes128...): GENERATED cert");
    RCLCPP_INFO(
      node->get_logger(), "  - Stronger policies (Basic256Sha256, Aes256...): LOADED cert");

    // Iterate security policies and swap certificate for weaker ones
    for (size_t i = 0; i < ua_server_config->securityPoliciesSize; ++i)
    {
      UA_SecurityPolicy * policy = &ua_server_config->securityPolicies[i];
      std::string uri(reinterpret_cast<char *>(policy->policyUri.data), policy->policyUri.length);

      if (
        uri.find("Basic128Rsa15") != std::string::npos ||
        uri.find("Aes128_Sha256_RsaOaep") != std::string::npos)
      {
        if (policy->updateCertificateAndPrivateKey)
        {
          UA_StatusCode retval = policy->updateCertificateAndPrivateKey(
            policy, *generatedCertificate.handle(), *generatedPrivateKey.handle());
          if (retval == UA_STATUSCODE_GOOD)
          {
            certificateMapping[uri] = "GENERATED";
            RCLCPP_INFO(
              node->get_logger(), "  ✓ Updated '%s' to use GENERATED certificate", uri.c_str());
          }
          else
          {
            RCLCPP_ERROR(
              node->get_logger(), "  ✗ Failed to update certificate for '%s': %s", uri.c_str(),
              UA_StatusCode_name(retval));
          }
        }
      }
    }
  }

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

  // First, update the security levels of the endpoints
  // Security levels: None=0, Sign (older)=10, Sign (newer)=20, SignAndEncrypt (older)=110,
  // SignAndEncrypt (newer)=120
  for (size_t i = 0; i < ua_server_config->endpointsSize; ++i)
  {
    UA_EndpointDescription * endpoint = &ua_server_config->endpoints[i];
    if (endpoint->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
    {
      if (
        std::string(reinterpret_cast<char *>(endpoint->securityPolicyUri.data))
            .find("Basic256Sha256") != std::string::npos ||
        std::string(reinterpret_cast<char *>(endpoint->securityPolicyUri.data))
            .find("Aes256_Sha256_RsaPss") != std::string::npos)
      {
        endpoint->securityLevel = 120;
      }
      else
      {
        endpoint->securityLevel = 110;
      }
    }
    else if (endpoint->securityMode == UA_MESSAGESECURITYMODE_SIGN)
    {
      if (
        std::string(reinterpret_cast<char *>(endpoint->securityPolicyUri.data))
            .find("Basic256Sha256") != std::string::npos ||
        std::string(reinterpret_cast<char *>(endpoint->securityPolicyUri.data))
            .find("Aes256_Sha256_RsaPss") != std::string::npos)
      {
        endpoint->securityLevel = 20;
      }
      else
      {
        endpoint->securityLevel = 10;
      }
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

  // Sort endpoints by security level (lowest to highest)
  if (ua_server_config->endpointsSize > 1)
  {
    std::qsort(
      ua_server_config->endpoints, ua_server_config->endpointsSize, sizeof(UA_EndpointDescription),
      [](const void * a, const void * b) -> int
      {
        const auto * epA = static_cast<const UA_EndpointDescription *>(a);
        const auto * epB = static_cast<const UA_EndpointDescription *>(b);

        // Sort by security level (ascending: least secure first)
        return static_cast<int>(epA->securityLevel) - static_cast<int>(epB->securityLevel);
      });
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

  std::vector<float> currentPos{0.15f, -1.25f};
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

  // Print server configuration summary with certificate mapping
  RCLCPP_INFO(node->get_logger(), "\n========== Server Configuration ==========");
  RCLCPP_INFO(node->get_logger(), "Name: %s", APP_NAME);
  RCLCPP_INFO(node->get_logger(), "URI: %s", APP_URI);
  RCLCPP_INFO(node->get_logger(), "Listening on: %s", url.c_str());
  RCLCPP_INFO(node->get_logger(), "\nCertificate Mapping (Security Policy -> Certificate Source):");
  for (const auto & [policy, source] : certificateMapping)
  {
    RCLCPP_INFO(node->get_logger(), "  %-45s -> %s", policy.c_str(), source.c_str());
  }
  RCLCPP_INFO(node->get_logger(), "\nEndpoints: 7 total (sorted by security level)");
  RCLCPP_INFO(node->get_logger(), "  [0] None              (level 0)");
  RCLCPP_INFO(node->get_logger(), "  [1] Sign/Aes128       (level 10)");
  RCLCPP_INFO(node->get_logger(), "  [2] Sign/Basic256Sha256 (level 20)");
  RCLCPP_INFO(node->get_logger(), "  [3] Sign/Aes256       (level 20)");
  RCLCPP_INFO(node->get_logger(), "  [4] SignEncrypt/Aes128 (level 110)");
  RCLCPP_INFO(node->get_logger(), "  [5] SignEncrypt/Basic256Sha256 (level 120)");
  RCLCPP_INFO(node->get_logger(), "  [6] SignEncrypt/Aes256 (level 120)");
  RCLCPP_INFO(
    node->get_logger(), "\nUser Token Policies: Anonymous + UserName (with standard PolicyIDs)");
  RCLCPP_INFO(node->get_logger(), "==========================================\n");
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
