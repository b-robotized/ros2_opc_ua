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

#include "opcua_hardware_interface/opcua_helpers.hpp"
#include <sstream>

namespace opcua_hardware_interface
{
namespace opcua_helpers
{

opcua::ByteString readFile(const std::string & path)
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

inline CertificateInfo parseCertificate(const opcua::ByteString & cert_data)
{
  CertificateInfo info;

  if (cert_data.empty())
  {
    return info;
  }

  // Create BIO from certificate data
  BIO * bio = BIO_new_mem_buf(cert_data.data(), static_cast<int>(cert_data.length()));
  if (!bio)
  {
    return info;
  }

  // Parse DER format certificate
  X509 * cert = d2i_X509_bio(bio, nullptr);
  BIO_free(bio);

  if (!cert)
  {
    return info;
  }

  info.is_valid = true;

  // Extract subject information
  X509_NAME * subject = X509_get_subject_name(cert);
  if (subject)
  {
    char buffer[256];

    // Common Name (CN)
    if (X509_NAME_get_text_by_NID(subject, NID_commonName, buffer, sizeof(buffer)) > 0)
    {
      info.common_name = buffer;
    }

    // Organization (O)
    if (X509_NAME_get_text_by_NID(subject, NID_organizationName, buffer, sizeof(buffer)) > 0)
    {
      info.organization = buffer;
    }

    // Organizational Unit (OU)
    if (X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, buffer, sizeof(buffer)) > 0)
    {
      info.organizational_unit = buffer;
    }

    // Country (C)
    if (X509_NAME_get_text_by_NID(subject, NID_countryName, buffer, sizeof(buffer)) > 0)
    {
      info.country = buffer;
    }

    // State (ST)
    if (X509_NAME_get_text_by_NID(subject, NID_stateOrProvinceName, buffer, sizeof(buffer)) > 0)
    {
      info.state = buffer;
    }

    // Locality (L)
    if (X509_NAME_get_text_by_NID(subject, NID_localityName, buffer, sizeof(buffer)) > 0)
    {
      info.locality = buffer;
    }
  }

  // Extract issuer information
  X509_NAME * issuer = X509_get_issuer_name(cert);
  if (issuer)
  {
    char buffer[256];

    // Issuer Common Name
    if (X509_NAME_get_text_by_NID(issuer, NID_commonName, buffer, sizeof(buffer)) > 0)
    {
      info.issuer_cn = buffer;
    }

    // Issuer Organization
    if (X509_NAME_get_text_by_NID(issuer, NID_organizationName, buffer, sizeof(buffer)) > 0)
    {
      info.issuer_org = buffer;
    }
  }

  // Extract validity period
  const ASN1_TIME * not_before = X509_get0_notBefore(cert);
  const ASN1_TIME * not_after = X509_get0_notAfter(cert);

  if (not_before)
  {
    BIO * bio_nb = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio_nb, not_before);
    char nb_buffer[128];
    int nb_len = BIO_read(bio_nb, nb_buffer, sizeof(nb_buffer) - 1);
    if (nb_len > 0)
    {
      nb_buffer[nb_len] = '\0';
      info.not_before = nb_buffer;
    }
    BIO_free(bio_nb);
  }

  if (not_after)
  {
    BIO * bio_na = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio_na, not_after);
    char na_buffer[128];
    int na_len = BIO_read(bio_na, na_buffer, sizeof(na_buffer) - 1);
    if (na_len > 0)
    {
      na_buffer[na_len] = '\0';
      info.not_after = na_buffer;
    }
    BIO_free(bio_na);
  }

  X509_free(cert);

  return info;
}

std::string toString(opcua::ApplicationType applicationType)
{
  switch (applicationType)
  {
    case opcua::ApplicationType::Server:
      return "Server";
    case opcua::ApplicationType::Client:
      return "Client";
    case opcua::ApplicationType::ClientAndServer:
      return "Client and Server";
    case opcua::ApplicationType::DiscoveryServer:
      return "Discovery Server";
    default:
      return "Unknown";
  }
}

std::string toString(opcua::MessageSecurityMode securityMode)
{
  switch (securityMode)
  {
    case opcua::MessageSecurityMode::Invalid:
      return "Invalid";
    case opcua::MessageSecurityMode::None:
      return "None";
    case opcua::MessageSecurityMode::Sign:
      return "Sign";
    case opcua::MessageSecurityMode::SignAndEncrypt:
      return "Sign and Encrypt";
    default:
      return "No valid security mode";
  }
}

std::string toString(opcua::UserTokenType tokenType)
{
  switch (tokenType)
  {
    case opcua::UserTokenType::Anonymous:
      return "Anonymous";
    case opcua::UserTokenType::Username:
      return "UserName";
    case opcua::UserTokenType::Certificate:
      return "Certificate";
    case opcua::UserTokenType::IssuedToken:
      return "IssuedToken";
    default:
      return "Unknown";
  }
}

void print_servers_info(
  const std::vector<opcua::ApplicationDescription> & servers, const rclcpp::Logger & logger)
{
  size_t serverIndex = 0;
  opcua::Client client;
  for (const auto & server : servers)
  {
    std::stringstream ss;
    const auto & name = server.applicationUri();
    ss << "\nServer[" << serverIndex++ << "] " << name << "\n"
       << "\tName:             " << server.applicationName().text() << "\n"
       << "\tApplication URI:  " << server.applicationUri() << "\n"
       << "\tProduct URI:      " << server.productUri() << "\n"
       << "\tApplication type: " << toString(server.applicationType()) << "\n"
       << "\tDiscovery URLs:\n";

    const auto discoveryUrls = server.discoveryUrls();
    if (discoveryUrls.empty())
    {
      ss << "\tNo discovery urls provided. Skip endpoint search.\n";
    }
    for (const auto & url : discoveryUrls)
    {
      ss << "\t- " << url << "\n";
    }

    for (const auto & url : discoveryUrls)
    {
      size_t endpointIndex = 0;
      for (const auto & endpoint : client.getEndpoints(url))
      {
        ss << "\tEndpoint[" << endpointIndex++ << "]:\n"
           << "\t- Endpoint URL:      " << endpoint.endpointUrl() << "\n"
           << "\t- Transport profile: " << endpoint.transportProfileUri() << "\n"
           << "\t- Security mode:     " << toString(endpoint.securityMode()) << "\n"
           << "\t- Security profile:  " << endpoint.securityPolicyUri() << "\n"
           << "\t- Security level:    " << static_cast<int>(endpoint.securityLevel())
           << (endpoint.securityLevel() == 0 ? " (None)" : "") << "\n"
           << "\t- User identity token:\n";

        for (const auto & token : endpoint.userIdentityTokens())
        {
          ss << "\t  - PolicyId: " << token.policyId()
             << ", TokenType: " << toString(token.tokenType()) << "\n";
        }
      }
    }
    RCLCPP_INFO_STREAM(logger, ss.str());
  }
}

void print_client_info(
  const opcua::Client & client, const rclcpp::Logger & logger,
  const opcua::ByteString & client_cert, const opcua::ByteString & client_key,
  const opcua::ByteString & ca_cert, uint8_t selected_endpoint_security_level)
{
  std::stringstream ss;
  const auto & config = client.config();

  auto to_sv = [](const UA_String & s)
  {
    return (s.length > 0) ? std::string_view(reinterpret_cast<char *>(s.data), s.length)
                          : std::string_view();
  };

  auto to_text = [](const UA_LocalizedText & t)
  {
    return (t.text.length > 0)
             ? std::string_view(reinterpret_cast<char *>(t.text.data), t.text.length)
             : std::string_view();
  };

  ss << "\n========== Client Security Configuration ==========\n";
  ss << "Application Name: " << to_text(config->clientDescription.applicationName) << "\n";
  ss << "Application URI:  " << to_sv(config->clientDescription.applicationUri) << "\n";
  ss << "Connecting to:    " << to_sv(config->endpointUrl) << "\n\n";

  // Client Certificates
  ss << "Client Certificates:\n";
  bool has_client_certificate = !client_cert.empty() && !client_key.empty();
  if (has_client_certificate)
  {
    ss << "  ✓ Client certificate loaded (" << client_cert.length() << " bytes)\n";
    ss << "  ✓ Client private key loaded (" << client_key.length() << " bytes)\n";
  }
  else
  {
    ss << "  ✗ No client certificate (only 'None' security mode available)\n";
  }

  // Server Certificate Verification
  ss << "\nServer Certificate Verification:\n";
  if (!ca_cert.empty())
  {
    ss << "  ✓ ENABLED - Using CA certificate (" << ca_cert.length() << " bytes)\n";

    // Parse and display CA certificate information
    CertificateInfo ca_info = parseCertificate(ca_cert);
    if (ca_info.is_valid)
    {
      ss << "  CA Certificate Details:\n";
      if (!ca_info.common_name.empty())
      {
        ss << "    - CN:           " << ca_info.common_name << "\n";
      }
      if (!ca_info.organization.empty())
      {
        ss << "    - Organization: " << ca_info.organization << "\n";
      }
      if (!ca_info.organizational_unit.empty())
      {
        ss << "    - Org Unit:     " << ca_info.organizational_unit << "\n";
      }
      if (!ca_info.country.empty())
      {
        ss << "    - Country:      " << ca_info.country << "\n";
      }
      if (!ca_info.state.empty())
      {
        ss << "    - State:        " << ca_info.state << "\n";
      }
      if (!ca_info.locality.empty())
      {
        ss << "    - Locality:     " << ca_info.locality << "\n";
      }
      if (!ca_info.not_before.empty() && !ca_info.not_after.empty())
      {
        ss << "    - Valid From:   " << ca_info.not_before << "\n";
        ss << "    - Valid Until:  " << ca_info.not_after << "\n";
      }
    }

    ss << "  ✓ Server certificate will be validated against CA trustlist\n";
    ss << "  ✓ Certificate verification: ENABLED\n";
  }
  else
  {
    ss << "  ✗ DISABLED - No CA certificate provided\n";
    ss << "  ⚠ INSECURE: Trusting ALL server certificates (not recommended for production)\n";
    ss << "  ⚠ Provide 'security.ca_certificate_path' parameter to enable verification\n";
  }

  // Server CA Detection (check if server requires client certificate verification)
  ss << "\nServer Configuration (detected):\n";

  // If we're using a secure endpoint with high security level, the server likely has CA
  // verification
  if (selected_endpoint_security_level >= 100)
  {
    ss << "  ℹ Server likely using CA certificate verification\n";
    ss << "  ℹ Server will validate client certificates (high security endpoint selected)\n";
  }
  else if (selected_endpoint_security_level > 0)
  {
    ss << "  ℹ Server may or may not use CA certificate verification\n";
    ss << "  ℹ Medium security endpoint selected (level "
       << static_cast<int>(selected_endpoint_security_level) << ")\n";
  }
  else
  {
    ss << "  ℹ Server not using certificate verification (None security mode)\n";
  }

  // Selected Endpoint
  ss << "\nSelected Endpoint:\n";
  ss << "  Security Policy:  " << to_sv(config->securityPolicyUri) << "\n";
  ss << "  Security Mode:    "
     << toString(static_cast<opcua::MessageSecurityMode>(config->securityMode)) << "\n";
  ss << "  Security Level:   " << static_cast<int>(selected_endpoint_security_level) << "\n";

  // User Identity Token
  const UA_ExtensionObject * token = &config->userIdentityToken;
  ss << "  User Token Type:  ";

  if (token->content.decoded.type == &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN])
  {
    ss << "Anonymous";
    auto * anon = static_cast<UA_AnonymousIdentityToken *>(token->content.decoded.data);
    if (anon)
    {
      ss << " (PolicyId: " << to_sv(anon->policyId) << ")";
    }
    ss << "\n";
  }
  else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN])
  {
    auto * user = static_cast<UA_UserNameIdentityToken *>(token->content.decoded.data);
    if (user)
    {
      ss << "UserName (PolicyId: " << to_sv(user->policyId) << ")\n";
      ss << "  Username:         " << to_sv(user->userName) << "\n";
    }
    else
    {
      ss << "UserName\n";
    }
  }
  else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN])
  {
    ss << "X509 Certificate";
    auto * cert = static_cast<UA_X509IdentityToken *>(token->content.decoded.data);
    if (cert)
    {
      ss << " (PolicyId: " << to_sv(cert->policyId) << ")";
    }
    ss << "\n";
  }
  else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN])
  {
    ss << "Issued Token";
    auto * issued = static_cast<UA_IssuedIdentityToken *>(token->content.decoded.data);
    if (issued)
    {
      ss << " (PolicyId: " << to_sv(issued->policyId) << ")";
    }
    ss << "\n";
  }
  else
  {
    ss << "Other/Unknown\n";
  }

  ss << "===================================================\n";

  RCLCPP_INFO_STREAM(logger, ss.str());
}

// ClientConfig class methods definition
void ClientConfig::process_client_certificates(
  opcua::Client & client, std::string hwi_name, std::string & ca_cert_path, std::string & cert_path,
  std::string & key_path, std::vector<opcua::ua::EndpointDescription> & endpoints,
  const rclcpp::Logger & logger)
{
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
        RCLCPP_INFO(logger, "Loaded client certificate from %s", cert_path.c_str());
      }
      else
      {
        RCLCPP_WARN(
          logger, "Failed to read client certificate/key files from %s", cert_path.c_str());
      }
    }

    // Try loading CA certificate for server verification
    if (!ca_cert_path.empty())
    {
      ca_cert_ = readFile(ca_cert_path);
      if (!ca_cert_.empty())
      {
        RCLCPP_INFO(
          logger, "Loaded CA certificate from %s (%zu bytes)", ca_cert_path.c_str(),
          ca_cert_.length());
      }
      else
      {
        RCLCPP_WARN(logger, "Failed to read CA certificate file from %s", ca_cert_path.c_str());
      }
    }

    // If no certificate loaded, generate one
    if (client_cert_.empty() || client_key_.empty())
    {
      RCLCPP_INFO(logger, "Generating self-signed client certificate...");
      try
      {
        std::string cn_full = "CN=" + hwi_name;
        std::string dns_full = "DNS:localhost";
        std::string uri_full = "URI:" + app_uri_;

        std::vector<opcua::String> subject = {opcua::String(cn_full), opcua::String("O=ROS 2")};
        std::vector<opcua::String> subjectAltName = {
          opcua::String(dns_full), opcua::String(uri_full)};

        auto result = opcua::createCertificate(subject, subjectAltName);
        client_cert_ = std::move(result.certificate);
        client_key_ = std::move(result.privateKey);
        RCLCPP_INFO(logger, "Generated client certificate (%zu bytes)", client_cert_.length());
      }
      catch (const std::exception & e)
      {
        RCLCPP_ERROR(logger, "Client certificate generation failed: %s.", e.what());
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
        RCLCPP_INFO(logger, "Using CA certificate for server verification (trustList)");
      }

      UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(
        client.config().handle(), *client_cert_.handle(), *client_key_.handle(), trustList,
        trustListSize, nullptr, 0);

      if (retval != UA_STATUSCODE_GOOD)
      {
        RCLCPP_ERROR(logger, "Failed to set default encryption: %s", UA_StatusCode_name(retval));
      }
      else
      {
        has_client_certificate_ = true;
        RCLCPP_INFO(logger, "Client encryption configured successfully!");

        // Configure certificate verification based on CA availability
        if (!ca_cert_.empty())
        {
          // CA certificate is provided, always enable verification
          RCLCPP_INFO(logger, "Certificate verification ENABLED with CA trustlist.");
        }
        else
        {
          // No CA certificate provided - disable verification (trust all certificates)
          client.config()->certificateVerification.clear = +[](UA_CertificateVerification *) {};
          client.config()->certificateVerification.verifyCertificate =
            +[](const UA_CertificateVerification *, const UA_ByteString *) -> UA_StatusCode
          { return UA_STATUSCODE_GOOD; };

          RCLCPP_WARN(
            logger,
            "Certificate verification DISABLED (no CA certificate provided, trust all). "
            "This is INSECURE and should only be used for testing! "
            "Provide 'security.ca_certificate_path' to enable verification.");
        }
      }
    }
    else
    {
      RCLCPP_WARN(logger, "No client certificate available. Will only use None security mode.");
    }
  }
  else
  {
    RCLCPP_INFO(logger, "No secure endpoints found. Skipping certificate configuration.");
  }
}

bool ClientConfig::select_endpoint(
  std::string & cert_path, std::string & username,
  std::vector<opcua::ua::EndpointDescription> & endpoints, const rclcpp::Logger & logger)
{
  // Simplified Selection Logic: Just use Security Level (highest = best)
  uint8_t bestSecurityLevel = 0;

  RCLCPP_INFO(logger, "Username is: %s", username.c_str());

  for (const auto & endpoint : endpoints)
  {
    // Skip secure endpoints if we don't have a client certificate
    if (
      !has_client_certificate_ &&
      (endpoint.securityMode() == opcua::MessageSecurityMode::Sign ||
       endpoint.securityMode() == opcua::MessageSecurityMode::SignAndEncrypt))
    {
      RCLCPP_INFO(logger, "Skipped secure endpoints as we don't have a client certificate");
      continue;  // Skip this endpoint
    }

    // Check if we can authenticate with this endpoint
    const opcua::ua::UserTokenPolicy * candidatePolicy = nullptr;

    for (const auto & tokenPolicy : endpoint.userIdentityTokens())
    {
      if (!username.empty())
      {
        RCLCPP_INFO(logger, "if (!username.empty())");

        if (tokenPolicy.tokenType() == opcua::UserTokenType::Username)
        {
          RCLCPP_INFO(logger, "tokenPolicy.tokenType() == opcua::UserTokenType::Username");
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

  if (!selectedEndpoint)
  {
    RCLCPP_INFO(logger, "!selectedEndpoint");
  }

  if (!selectedTokenPolicy)
  {
    RCLCPP_INFO(logger, "!selectedTokenPolicy");
  }

  if (!selectedEndpoint || !selectedTokenPolicy)
  {
    RCLCPP_FATAL(logger, "Could not find a suitable endpoint for provided credentials.");
    return false;
  }

  return true;
}

void ClientConfig::configure_client(
  opcua::Client & client, std::string & username, std::string & password,
  const rclcpp::Logger & logger)
{
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

  RCLCPP_INFO(logger, "Client Application URI set to: %s", app_uri_.c_str());

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
  print_client_info(
    client, logger, client_cert_, client_key_, ca_cert_, selectedEndpoint->securityLevel());
}
}  // namespace opcua_helpers

}  // namespace opcua_hardware_interface
