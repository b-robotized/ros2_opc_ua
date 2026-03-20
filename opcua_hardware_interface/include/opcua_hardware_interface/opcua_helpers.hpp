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

#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// OpenSSL includes for certificate parsing
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/x509.h"

#include "open62541/client_config_default.h"
#include "open62541pp/plugin/create_certificate.hpp"

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

// Helper to read file content
opcua::ByteString readFile(const std::string & path);

// Parse X.509 certificate from DER format
inline CertificateInfo parseCertificate(const opcua::ByteString & cert_data);

// Convert enums to strings for logging
std::string toString(opcua::ApplicationType applicationType);
std::string toString(opcua::MessageSecurityMode securityMode);
std::string toString(opcua::UserTokenType tokenType);

void print_servers_info(
  opcua::Client & client, const std::vector<opcua::ApplicationDescription> & servers,
  const rclcpp::Logger & logger);

void print_client_info(
  const opcua::Client & client, const rclcpp::Logger & logger,
  const opcua::ByteString & client_cert = opcua::ByteString(),
  const opcua::ByteString & client_key = opcua::ByteString(),
  const opcua::ByteString & ca_cert = opcua::ByteString(),
  uint8_t selected_endpoint_security_level = 0);

// Client identification and security
class ClientConfig
{
private:
  bool has_client_certificate_;
  opcua::ByteString client_cert_;
  opcua::ByteString client_key_;
  opcua::ByteString ca_cert_;
  const opcua::ua::EndpointDescription * selectedEndpoint;
  const opcua::ua::UserTokenPolicy * selectedTokenPolicy;

public:
  std::string app_uri_;
  std::string app_name_;

  void process_client_certificates(
    opcua::Client & client, std::string hwi_name, std::string & ca_cert_path,
    std::string & cert_path, std::string & key_path,
    std::vector<opcua::ua::EndpointDescription> & endpoints, const rclcpp::Logger & logger);

  bool select_endpoint(
    std::string & cert_path, std::string & username,
    std::vector<opcua::ua::EndpointDescription> & endpoints, const rclcpp::Logger & logger);

  void configure_client(
    opcua::Client & client, std::string & username, std::string & password,
    const rclcpp::Logger & logger);
};

}  // namespace opcua_helpers

}  // namespace opcua_hardware_interface

#endif  // OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_
