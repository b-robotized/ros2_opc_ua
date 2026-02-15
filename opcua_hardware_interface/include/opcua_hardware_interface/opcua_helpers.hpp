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

#ifndef OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_
#define OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_

#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

// OpenSSL includes for certificate parsing
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/x509.h"

#include "open62541pp/client.hpp"
#include "rclcpp/rclcpp.hpp"

namespace opcua_hardware_interface
{
namespace opcua_helpers
{

// Helper structure to hold certificate information
struct CertificateInfo
{
  std::string common_name;
  std::string organization;
  std::string organizational_unit;
  std::string country;
  std::string state;
  std::string locality;
  std::string not_before;
  std::string not_after;
  std::string issuer_cn;
  std::string issuer_org;
  bool is_valid = false;
};

// Parse X.509 certificate from DER format
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
  const opcua::ByteString & client_cert = opcua::ByteString(),
  const opcua::ByteString & client_key = opcua::ByteString(),
  const opcua::ByteString & ca_cert = opcua::ByteString(), bool verify_certificates = false,
  uint8_t selected_endpoint_security_level = 0)
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
    if (verify_certificates)
    {
      ss << "  ✓ Certificate verification: STRICT\n";
    }
    else
    {
      ss << "  ⚠ Certificate verification: DISABLED by parameter (INSECURE)\n";
    }
  }
  else
  {
    ss << "  ✗ DISABLED - No CA certificate provided\n";
    if (!verify_certificates)
    {
      ss << "  ⚠ INSECURE: Trusting ALL server certificates (not recommended for production)\n";
    }
    else
    {
      ss << "  ⚠ Using default truststore (connection may fail)\n";
    }
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

}  // namespace opcua_helpers

}  // namespace opcua_hardware_interface

#endif  // OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_
