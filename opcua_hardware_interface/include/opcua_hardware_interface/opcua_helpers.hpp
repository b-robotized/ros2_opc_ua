#ifndef OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_
#define OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_

#include <string>
#include <string_view>
#include <sstream>
#include <vector>

#include "open62541pp/client.hpp"
#include "rclcpp/rclcpp.hpp"

namespace opcua_hardware_interface
{
    namespace opcua_helpers
    {
        std::string toString(opcua::ApplicationType applicationType) {
            switch (applicationType) {
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

        std::string toString(opcua::MessageSecurityMode securityMode) {
            switch (securityMode) {
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

        std::string toString(opcua::UserTokenType tokenType) {
            switch (tokenType) {
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

        void print_servers_info(const std::vector<opcua::ApplicationDescription> & servers, const rclcpp::Logger & logger)
        {
            size_t serverIndex = 0;
            opcua::Client client;
            for (const auto& server : servers) {
                std::stringstream ss;
                const auto& name = server.applicationUri();
                ss  << "\nServer[" << serverIndex++ << "] " << name << "\n"
                    << "\tName:             " << server.applicationName().text() << "\n"
                    << "\tApplication URI:  " << server.applicationUri() << "\n"
                    << "\tProduct URI:      " << server.productUri() << "\n"
                    << "\tApplication type: " << toString(server.applicationType()) << "\n"
                    << "\tDiscovery URLs:\n";

                const auto discoveryUrls = server.discoveryUrls();
                if (discoveryUrls.empty()) {
                    ss << "No discovery urls provided. Skip endpoint search.";
                }
                for (const auto& url : discoveryUrls) {
                    ss << "\t- " << url << "\n";
                }

                for (const auto& url : discoveryUrls) {
                    size_t endpointIndex = 0;
                    for (const auto& endpoint : client.getEndpoints(url)) {
                        ss  << "\tEndpoint[" << endpointIndex++ << "]:\n"
                            << "\t- Endpoint URL:      " << endpoint.endpointUrl() << "\n"
                            << "\t- Transport profile: " << endpoint.transportProfileUri() << "\n"
                            << "\t- Security mode:     " << toString(endpoint.securityMode()) << "\n"
                            << "\t- Security profile:  " << endpoint.securityPolicyUri() << "\n"
                            << "\t- Security level:    " << static_cast<int>(endpoint.securityLevel()) << (endpoint.securityLevel() == 0 ? " (None)" : "") << "\n"
                            << "\t- User identity token:\n";

                        for (const auto& token : endpoint.userIdentityTokens()) {
                            ss << "\t  - PolicyId: " << token.policyId() << ", TokenType: " << toString(token.tokenType()) << "\n";
                        }
                    }
                }
                RCLCPP_INFO_STREAM(logger, ss.str());
            }
        }

        void print_client_info(const opcua::Client & client, const rclcpp::Logger & logger)
        {
            std::stringstream ss;
            const auto& config = client.config();

            auto to_sv = [](const UA_String& s) {
                return (s.length > 0) ? std::string_view((char*)s.data, s.length) : std::string_view();
            };
            
            auto to_text = [](const UA_LocalizedText& t) {
                return (t.text.length > 0) ? std::string_view((char*)t.text.data, t.text.length) : std::string_view();
            };
            
            ss << "\nClient Configuration:\n"
               << "\tApplication Name:       " << to_text(config->clientDescription.applicationName) << "\n"
               << "\tApplication URI:        " << to_sv(config->clientDescription.applicationUri) << "\n"
               << "\tEndpoint:\n"
               << "\t  - URL:                " << to_sv(config->endpointUrl) << "\n"
               << "\t  - Security Mode:      " << toString(static_cast<opcua::MessageSecurityMode>(config->securityMode)) << "\n"
               << "\t  - Security Policy:    " << to_sv(config->securityPolicyUri) << "\n"
               << "\t  - Session Timeout:    " << config->requestedSessionTimeout << "ms\n";

            // User Identity Token
            const UA_ExtensionObject *token = &config->userIdentityToken;
            ss << "\tUser Identity Token:\n";
            
            if (token->content.decoded.type == &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]) {
                 ss << "\t  - Type: Anonymous\n";
                 auto* anon = static_cast<UA_AnonymousIdentityToken*>(token->content.decoded.data);
                 if (anon) {
                     ss << "\t  - PolicyId: " << to_sv(anon->policyId) << "\n";
                 }
            } else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
                 ss << "\t  - Type: UserName\n";
                 auto* user = static_cast<UA_UserNameIdentityToken*>(token->content.decoded.data);
                 if (user) {
                     ss << "\t  - PolicyId: " << to_sv(user->policyId) << "\n";
                     ss << "\t  - Username: " << to_sv(user->userName) << "\n";
                     ss << "\t  - Password: " << to_sv(user->password) << "\n";
                 }
            } else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) {
                 ss << "\t  - Type: X509 Certificate\n";
                 auto* cert = static_cast<UA_X509IdentityToken*>(token->content.decoded.data);
                 if (cert) {
                     ss << "\t  - PolicyId: " << to_sv(cert->policyId) << "\n";
                 }
            } else if (token->content.decoded.type == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
                 ss << "\t  - Type: Issued Token\n";
                 auto* issued = static_cast<UA_IssuedIdentityToken*>(token->content.decoded.data);
                 if (issued) {
                     ss << "\t  - PolicyId: " << to_sv(issued->policyId) << "\n";
                 }
            } else {
                 ss << "\t  - Type: Other/Unknown\n";
            }

            RCLCPP_INFO_STREAM(logger, ss.str());
        }

    }  // namespace opcua_helpers

}  // namespace opcua_hardware_interface

#endif // OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_