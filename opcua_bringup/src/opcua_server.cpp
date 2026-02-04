#include <iostream>

#include <open62541pp/node.hpp>
#include <open62541pp/server.hpp>
#include <open62541pp/plugin/accesscontrol_default.hpp>

using namespace opcua;

// Custom access control based on AccessControlDefault.
// If a user logs in with the username "admin", a session attribute "isAdmin" is stored. As an
// example, the user "admin" has write access level to the created variable node. So admins can
// change the value of the created variable node, anonymous users and the user "user" can't.
// Session attributes are available since open62541 v1.3, so this example requires at least v1.3.
class AccessControlCustom : public AccessControlDefault
{
public:
    using AccessControlDefault::AccessControlDefault; // inherit constructors

    StatusCode activateSession(
        Session &session,
        const EndpointDescription &endpointDescription,
        const ByteString &secureChannelRemoteCertificate,
        const ExtensionObject &userIdentityToken) override
    {
        // Grant admin rights if user is logged in as "admin"
        // Store attribute "isAdmin" as session attribute to use it in access callbacks
        const auto *token = userIdentityToken.decodedData<UserNameIdentityToken>();
        const bool isAdmin = (token != nullptr && token->userName() == "admin");
        std::cout << "User has admin rights: " << isAdmin << std::endl;
        session.setSessionAttribute({0, "isAdmin"}, Variant{isAdmin});

        return AccessControlDefault::activateSession(
            session, endpointDescription, secureChannelRemoteCertificate, userIdentityToken);
    }

    Bitmask<AccessLevel> getUserAccessLevel(Session &session, const NodeId &nodeId) override
    {
        const bool isAdmin = session.getSessionAttribute({0, "isAdmin"}).scalar<bool>();
        std::cout << "Get user access level of node id " << opcua::toString(nodeId) << std::endl;
        std::cout << "Admin rights granted: " << isAdmin << std::endl;
        return isAdmin
                   ? AccessLevel::CurrentRead | AccessLevel::CurrentWrite
                   : AccessLevel::CurrentRead;
    }
};

int main()
{
    opcua::ServerConfig config;

    // Use handle to access the open62541 methods
    UA_ServerConfig *ua_server_config = config.handle();
    std::string ip_address = "192.168.1.109";
    ua_server_config->customHostname = UA_STRING(ip_address.data()); //! UA_STRING only accepts non const char*

    config.setApplicationName("open62541pp server example");
    config.setApplicationUri("urn:open62541pp.server.application");
    config.setProductUri("https://open62541pp.github.io");

    // Exchanging usernames/passwords without encryption as plain text is dangerous.
    // We are doing this just for demonstration, don't use it in production!
    AccessControlCustom accessControl{
        true, // allow anonymous
        {
            Login{String{"admin"}, String{"ua_password"}},
        }};

    config.setAccessControl(accessControl);

#if UAPP_OPEN62541_VER_GE(1, 4)
    config->allowNonePolicyPassword = true;
#endif

    opcua::Server server{std::move(config)};

    // Add a variable node to the Objects node
    opcua::Node parentNode{server, opcua::ObjectId::ObjectsFolder};

    opcua::Node myIntegerNode = parentNode.addVariable(
        {1, 1},                     //! nodeId (ns=1 ; s=TheAnswer)
        "The Answer",               //! browse name
        opcua::VariableAttributes{} //! attributes (c.f node.hpp line 156)
            .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
            .setDisplayName({"en-US", "The Answer"})
            .setDescription({"en-US", "Answer to the Ultimate Question of Life"})
            .setDataType<int>());

    // Write a value (attribute) to the node
    myIntegerNode.writeValue(opcua::Variant{42});

    // Read the value (attribute) from the node
    std::cout << "The answer is: " << myIntegerNode.readValue().to<int>() << std::endl;

    server.run();
}