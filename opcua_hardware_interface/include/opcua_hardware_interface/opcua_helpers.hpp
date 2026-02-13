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

        void print_servers_info(const std::vector<opcua::ApplicationDescription> & servers, const rclcpp::Logger & logger)
        {
            size_t serverIndex = 0;
            opcua::Client client;
            for (const auto& server : servers) {
                std::stringstream ss;
                const auto& name = server.applicationUri();
                ss  << "Server[" << serverIndex++ << "] " << name << "\n"
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
                            << "\t- Security level:    " << endpoint.securityLevel() << "\n"
                            << "\t- User identity token:\n";

                        for (const auto& token : endpoint.userIdentityTokens()) {
                            ss << "\t  - " << token.policyId() << "\n";
                        }
                    }
                }
                RCLCPP_INFO_STREAM(logger, ss.str());
            }
        }

    }  // namespace opcua_helpers

}  // namespace opcua_hardware_interface

#endif // OPCUA_HARDWARE_INTERFACE__OPCUA_HELPERS_HPP_