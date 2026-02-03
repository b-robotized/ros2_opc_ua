#ifndef opcua_hardware_interface__OPCUA_SYSTEM_HPP_
#define opcua_hardware_interface__OPCUA_SYSTEM_HPP_

#include <string>
#include <vector>
#include <limits>

#include "hardware_interface/system_interface.hpp"
#include "hardware_interface/handle.hpp"
#include "hardware_interface/hardware_info.hpp"
#include "hardware_interface/types/hardware_interface_return_values.hpp"
#include "rclcpp/macros.hpp"
#include "rclcpp_lifecycle/state.hpp"

#include <open62541pp/node.hpp>
#include <open62541pp/client.hpp>

namespace opcua_hardware_interface
{
    enum class UAType
    {
        // Using enum instead of raw strings for faster iterations in read/write
        UA_Boolean,
        UA_Byte,
        UA_Int16,
        UA_UInt16,
        UA_Int32,
        UA_UInt32,
        UA_Int64,
        UA_UInt64,
        UA_Float,
        UA_Double,
        UNKNOWN
    };

    class OPCUAHardwareInterface : public hardware_interface::SystemInterface
    {
    public:
        hardware_interface::CallbackReturn on_init(const hardware_interface::HardwareComponentParams &params);

        hardware_interface::CallbackReturn on_configure(
            const rclcpp_lifecycle::State &previous_state) override;

        hardware_interface::CallbackReturn on_activate(
            const rclcpp_lifecycle::State &previous_state) override;

        hardware_interface::CallbackReturn on_deactivate(
            const rclcpp_lifecycle::State &previous_state) override;

        hardware_interface::CallbackReturn on_shutdown(
            const rclcpp_lifecycle::State &previous_state) override;

        hardware_interface::return_type read(
            const rclcpp::Time &time, const rclcpp::Duration &period) override;

        hardware_interface::return_type write(
            const rclcpp::Time &time, const rclcpp::Duration &period) override;

    private:
        rclcpp::Logger getLogger() { return rclcpp::get_logger("OPCUAHardwareInterface"); }
        std::shared_ptr<rclcpp::Clock> logging_throttle_clock_;

        // ========= OPC UA ==============================
        // OPC UA type helper
        UAType strToUAType(const std::string &type_str);
        size_t UAToROS2Type(UAType ua_type);

        bool configure_ua_client();

        opcua::Client client;
    };

} // namespace opcua_hardware_interface

#endif // opcua_hardware_interface__OPCUA_SYSTEM_HPP_