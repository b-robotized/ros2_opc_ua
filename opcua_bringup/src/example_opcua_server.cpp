#include <cmath>
#include <iostream>
#include <vector>
#include <fstream> // for file checks

#include "open62541pp/callback.hpp"
#include <open62541pp/node.hpp>
#include <open62541pp/plugin/accesscontrol_default.hpp>
#include <open62541pp/server.hpp>
#include <open62541pp/types.hpp>

// Include create_certificate if available, otherwise we will use external files
#include <open62541pp/config.hpp>
#if UAPP_HAS_CREATE_CERTIFICATE
#include <open62541pp/plugin/create_certificate.hpp>
#endif

#include "rclcpp/rclcpp.hpp"

using namespace opcua;

// Helper to read file content
static ByteString readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return ByteString{};
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size <= 0) return ByteString{};

    std::vector<char> buffer(static_cast<size_t>(size));
    if (file.read(buffer.data(), size)) {
        return ByteString(std::string_view(buffer.data(), static_cast<size_t>(size)));
    }
    return ByteString{};
}

// Custom access control based on AccessControlDefault.
// If a user logs in with the username "admin", a session attribute "isAdmin" is stored. As an
// example, the user "admin" has write access level to the created variable node. So admins can
// change the value of the created variable node, anonymous users and the user "user" can't.
// Session attributes are available since open62541 v1.3, so this example requires at least v1.3.
class AccessControlCustom : public AccessControlDefault
{
  public:
    AccessControlCustom(bool allow_anonymous, const std::initializer_list<Login>& logins, rclcpp::Logger logger)
        : AccessControlDefault(allow_anonymous, logins), logger_(logger) {}

    StatusCode activateSession(Session &session, const EndpointDescription &endpointDescription,
                               const ByteString &secureChannelRemoteCertificate,
                               const ExtensionObject &userIdentityToken) override
    {
        // Check for unsafe configuration: UserName + SecurityMode::None
        const auto *token = userIdentityToken.decodedData<UserNameIdentityToken>();
        if (token != nullptr) {
            if (endpointDescription.securityMode() == MessageSecurityMode::None) {
                RCLCPP_WARN(logger_, "Security Warning: UserName authentication used over insecure channel (SecurityMode: None)! This is not safe.");
            }
        }

        // Grant admin rights if user is logged in as "admin"
        // Store attribute "isAdmin" as session attribute to use it in access callbacks
        const bool isAdmin = (token != nullptr && token->userName() == "admin");
        std::cout << "User has admin rights: " << isAdmin << std::endl;
        session.setSessionAttribute({0, "isAdmin"}, Variant{isAdmin});

        return AccessControlDefault::activateSession(session, endpointDescription, secureChannelRemoteCertificate,
                                                     userIdentityToken);
    }

    Bitmask<AccessLevel> getUserAccessLevel(Session &session, const NodeId & /*nodeId */) override
    {
        const bool isAdmin = session.getSessionAttribute({0, "isAdmin"}).scalar<bool>();
        return isAdmin ? AccessLevel::CurrentRead | AccessLevel::CurrentWrite : AccessLevel::CurrentRead;
    }

  private:
    rclcpp::Logger logger_;
};

int main(int argc, char **argv)
{
    rclcpp::init(argc, argv);
    auto node = std::make_shared<rclcpp::Node>("opcua_server_node");

    // Declare the parameter "allow_anonymous" with a default value of false
    // This allows enabling/disabling anonymous access via ROS 2 parameters
    bool allow_anonymous = node->declare_parameter("allow_anonymous", false);

    // Security parameters
    std::string security_policy = node->declare_parameter("security.policy", "None"); // "None", "Sign", "SignAndEncrypt"
    std::string cert_path = node->declare_parameter("security.certificate_path", "");
    std::string key_path = node->declare_parameter("security.private_key_path", "");
    bool auto_generate_certs = node->declare_parameter("security.auto_generate_certificates", true);

    // Prepare certificates
    ByteString certificate;
    ByteString privateKey;

    if (security_policy != "None") {
        if (!cert_path.empty() && !key_path.empty()) {
            RCLCPP_INFO(node->get_logger(), "Loading certificate from: %s", cert_path.c_str());
            certificate = readFile(cert_path);
            privateKey = readFile(key_path);
            if (certificate.empty() || privateKey.empty()) {
                RCLCPP_ERROR(node->get_logger(), "Failed to load certificate or private key files. Fallback to None?");
                return 1;
            }
        } else if (auto_generate_certs) {
#if UAPP_HAS_CREATE_CERTIFICATE
            RCLCPP_INFO(node->get_logger(), "Generating self-signed certificate...");
            try {
                auto result = opcua::createCertificate(
                    {{"CN", "ros2_opc_ua example server"}, {"O", "ROS 2"}},
                    {{"DNS", "localhost"}, {"URI", "urn:open62541pp.server.application:ros2_opc_ua"}}
                );
                certificate = std::move(result.certificate);
                privateKey = std::move(result.privateKey);
            } catch (const std::exception& e) {
                RCLCPP_ERROR(node->get_logger(), "Certificate generation failed: %s", e.what());
                return 1;
            }
#else
            RCLCPP_ERROR(node->get_logger(), "Automatic certificate generation is not available (requires OpenSSL backend). "
                                             "Please provide paths to certificate and private key using 'security.certificate_path' and 'security.private_key_path'.");
            return 1;
#endif
        } else {
            RCLCPP_ERROR(node->get_logger(), "Security Policy '%s' requested but no certificates provided. "
                                             "Set 'security.certificate_path' and 'security.private_key_path' OR enable 'security.auto_generate_certificates'.",
                                             security_policy.c_str());
            return 1;
        }
    }

    // Configure Server
    std::unique_ptr<opcua::ServerConfig> config_ptr;

    if (!certificate.empty() && !privateKey.empty()) {
        // Create server config with encryption support
        // This constructor automatically enables secure policies supported by the library
        // (Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep) depending on build options.
        // It ALSO enables None policy by default usually, but we can check.
        config_ptr = std::make_unique<opcua::ServerConfig>(4840, certificate, privateKey, Span<const ByteString>{}, Span<const ByteString>{});
    } else {
        config_ptr = std::make_unique<opcua::ServerConfig>(); // Default None policy
    }

    opcua::ServerConfig& config = *config_ptr;

    // Use handle to access the open62541 methods
    UA_ServerConfig *ua_server_config = config.handle();
    std::string url = "opc.tcp://127.0.0.1:4840";

    // clear and free existing server URLs
    if (ua_server_config->serverUrlsSize > 0) {
        for (size_t i = 0; i < ua_server_config->serverUrlsSize; i++) {
            UA_String_clear(&ua_server_config->serverUrls[i]);
        }
        UA_free(ua_server_config->serverUrls);
    }
    // allocate array
    ua_server_config->serverUrls = (UA_String*)UA_malloc(sizeof(UA_String));
    ua_server_config->serverUrlsSize = 1;
    // allocate the string
    ua_server_config->serverUrls[0] = UA_STRING_ALLOC(url.c_str());

    config.setApplicationName("ros2_opc_ua server example (based on open62541pp)");
    config.setApplicationUri("urn:open62541pp.server.application:ros2_opc_ua");
    config.setProductUri("https://github.com/b-robotized/ros2_opc_ua");

    // Exchanging usernames/passwords without encryption as plain text is dangerous.
    // We are doing this just for demonstration, don't use it in production!
    AccessControlCustom accessControl{allow_anonymous, // allow anonymous set via ROS 2 parameter
                                      {
                                          Login{String{"admin"}, String{"ua_password"}},
                                      },
                                      node->get_logger()}; // Pass logger

    config.setAccessControl(accessControl);

    // If "None" policy is used with Password, allow it explicitly
    // Note: If using Sign/Encrypt, this might still be needed if the client explicitly chooses None.
    config->allowNonePolicyPassword = true;

    opcua::Server server{std::move(config)};


    // Add a variable node to the Objects node
    opcua::Node parentNode{server, opcua::ObjectId::ObjectsFolder};

    opcua::Node myIntegerNode =
        parentNode.addVariable({1, 1},                     //! nodeId (ns=1 ; s=1)
                               "The Answer",               //! browse name
                               opcua::VariableAttributes{} //! attributes (c.f node.hpp line 156)
                                   .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
                                   .setDisplayName({"en-US", "The Answer"})
                                   .setDescription({"en-US", "Answer to the Ultimate Question of Life"})
                                   .setDataType<int>()
                                   .setValueRank(ValueRank::Scalar)
                                   .setValue(opcua::Variant{42}));

    std::vector<float> currentPos{0.15, -1.25};
    opcua::Node currentPosNode =
        parentNode.addVariable({1, 10}, "Current Position Array",
                               opcua::VariableAttributes{}
                                   .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
                                   .setDisplayName({"en-US", "Array of current position"})
                                   .setDataType(DataTypeId::Float)
                                   .setArrayDimensions({0})               //! single dimension but unknown in size
                                   .setValueRank(ValueRank::OneDimension) //! (c.f common.hpp line 157)
                                   .setValue(opcua::Variant{currentPos}));

    std::vector<UA_Boolean> commandPos = {UA_FALSE, UA_TRUE};
    // std::bool is not supported, UA_Boolean is uint8_t
    opcua::Node commandPosNode =
        parentNode.addVariable({1, 11}, "Command Position Array",
                               opcua::VariableAttributes{}
                                   .setAccessLevel(AccessLevel::CurrentRead | AccessLevel::CurrentWrite)
                                   .setDisplayName({"en-US", "Array of boolean command position"})
                                   .setDataType(DataTypeId::Boolean)
                                   .setArrayDimensions({0})               //! single dimension but unknown in size
                                   .setValueRank(ValueRank::OneDimension) //! (c.f common.hpp line 157)
                                   .setValue(opcua::Variant{commandPos}));

    // Add a callback fucnction to simulate change over time
    size_t counter = 0;
    const double interval = 500; // milliseconds
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
            std::cout << "commandPos is: [ " << commandPos[0] << " , " << commandPos[1] << " ]" << std::endl;
            std::cout << "CurrentPos is: [ " << currentPos[0] << " , " << currentPos[1] << " ]" << std::endl;

            commandPosNode.writeValue(opcua::Variant(commandPos));
            currentPosNode.writeValue(opcua::Variant(currentPos));
        },
        interval);

    // Read the initial value (attribute) from the node
    std::cout << "The answer is: " << myIntegerNode.readValue().to<int>() << std::endl;
    std::cout << "The curentPos is: [ " << currentPosNode.readValue().to<std::vector<float>>().at(0) << " , "
              << currentPosNode.readValue().to<std::vector<float>>().at(1) << " ]." << std::endl;
    std::cout << "The commandPos is: [ " << commandPosNode.readValue().to<std::vector<bool>>().at(0) << " , "
              << commandPosNode.readValue().to<std::vector<bool>>().at(1) << " ]." << std::endl;

    server.run();

    opcua::removeCallback(server, id1);
    rclcpp::shutdown();
}