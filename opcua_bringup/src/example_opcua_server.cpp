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
#include <iostream>
#include <vector>

#include "open62541pp/callback.hpp"
#include <open62541pp/node.hpp>
#include <open62541pp/plugin/accesscontrol_default.hpp>
#include <open62541pp/server.hpp>

using opcua::AccessControlDefault;
using opcua::AccessLevel;
using opcua::ua::DataTypeId;
using opcua::ua::EndpointDescription;

// Custom access control based on AccessControlDefault.
// If a user logs in with the username "admin", a session attribute "isAdmin" is stored. As an
// example, the user "admin" has write access level to the created variable node. So admins can
// change the value of the created variable node, anonymous users and the user "user" can't.
// Session attributes are available since open62541 v1.3, so this example requires at least v1.3.
class AccessControlCustom : public AccessControlDefault
{
  public:
    using AccessControlDefault::AccessControlDefault;  // inherit constructors

    opcua::StatusCode activateSession(opcua::Session &session,
                                      const EndpointDescription &endpointDescription,
                                      const opcua::ByteString &secureChannelRemoteCertificate,
                                      const opcua::ExtensionObject &userIdentityToken) override
    {
        // Grant admin rights if user is logged in as "admin"
        // Store attribute "isAdmin" as session attribute to use it in access callbacks
        const auto *token = userIdentityToken.decodedData<opcua::ua::UserNameIdentityToken>();
        const bool isAdmin = (token != nullptr && token->userName() == "admin");
        std::cout << "User has admin rights: " << isAdmin << std::endl;
        session.setSessionAttribute({0, "isAdmin"}, opcua::Variant{isAdmin});

        return AccessControlDefault::activateSession(
            session, endpointDescription, secureChannelRemoteCertificate, userIdentityToken);
    }

    opcua::Bitmask<AccessLevel> getUserAccessLevel(opcua::Session &session,
                                                   const opcua::NodeId & /*nodeId */) override
    {
        const bool isAdmin = session.getSessionAttribute({0, "isAdmin"}).scalar<bool>();
        return isAdmin ? AccessLevel::CurrentRead | AccessLevel::CurrentWrite
                       : AccessLevel::CurrentRead;
    }
};

int main()
{
    opcua::ServerConfig config;

    // Use handle to access the open62541 methods
    UA_ServerConfig *ua_server_config = config.handle();
    std::string url = "opc.tcp://127.0.0.1:4840";

    // clear and free existing server URLs
    if (ua_server_config->serverUrlsSize > 0)
    {
        for (size_t i = 0; i < ua_server_config->serverUrlsSize; i++)
        {
            UA_String_clear(&ua_server_config->serverUrls[i]);
        }
        UA_free(ua_server_config->serverUrls);
    }
    // allocate array
    ua_server_config->serverUrls = reinterpret_cast<UA_String *>(UA_malloc(sizeof(UA_String)));
    ua_server_config->serverUrlsSize = 1;
    // allocate the string
    ua_server_config->serverUrls[0] = UA_STRING_ALLOC(url.c_str());

    config.setApplicationName("open62541pp server example");
    config.setApplicationUri("urn:open62541pp.server.application");
    config.setProductUri("https://open62541pp.github.io");

    // Exchanging usernames/passwords without encryption as plain text is dangerous.
    // We are doing this just for demonstration, don't use it in production!
    AccessControlCustom accessControl{
        true,  // allow anonymous
        {
            opcua::Login{opcua::String{"admin"}, opcua::String{"ua_password"}},
        }};

    config.setAccessControl(accessControl);

#if UAPP_OPEN62541_VER_GE(1, 4)
    config->allowNonePolicyPassword = true;
#endif

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
    std::cout << "The answer is: " << myIntegerNode.readValue().to<int>() << std::endl;
    std::cout << "The curentPos is: [ " << currentPosNode.readValue().to<std::vector<float>>().at(0)
              << " , " << currentPosNode.readValue().to<std::vector<float>>().at(1) << " ]."
              << std::endl;
    std::cout << "The commandPos is: [ " << commandPosNode.readValue().to<std::vector<bool>>().at(0)
              << " , " << commandPosNode.readValue().to<std::vector<bool>>().at(1) << " ]."
              << std::endl;

    server.run();

    opcua::removeCallback(server, id1);
}
