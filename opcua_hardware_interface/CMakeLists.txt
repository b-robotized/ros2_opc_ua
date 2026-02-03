cmake_minimum_required(VERSION 3.20)
project(opcua_hardware_interface)

if(CMAKE_CXX_COMPILER_ID MATCHES "(GNU|Clang)")
  add_compile_options(-Wall -Wextra -Werror=conversion -Werror=unused-but-set-variable -Werror=return-type -Werror=shadow)
endif()

if(POLICY CMP0148)
  cmake_policy(SET CMP0148 OLD)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(rclcpp_lifecycle REQUIRED)
find_package(hardware_interface REQUIRED)
find_package(pluginlib REQUIRED)
find_package(open62541pp_vendor REQUIRED)

add_library(
  opcua_hardware_interface
  SHARED
  src/opcua_hardware_interface.cpp
)

target_include_directories(
  opcua_hardware_interface
  PUBLIC
  include
)
target_link_libraries(opcua_hardware_interface PUBLIC
  hardware_interface::hardware_interface
  hardware_interface::mock_components
  rclcpp::rclcpp
  rclcpp_lifecycle::rclcpp_lifecycle
  open62541pp::open62541pp
)

# prevent pluginlib from using boost
target_compile_definitions(opcua_hardware_interface PUBLIC "PLUGINLIB__DISABLE_BOOST_FUNCTIONS")

pluginlib_export_plugin_description_file(
  hardware_interface opcua_hardware_interface.xml)

install(
  TARGETS
  opcua_hardware_interface
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)

install(
  DIRECTORY include/
  DESTINATION include
)

ament_export_include_directories(
  include
)
ament_export_libraries(
  opcua_hardware_interface
)
ament_export_dependencies(
  hardware_interface
  pluginlib
  rclcpp
  rclcpp_lifecycle
  open62541pp_vendor
)

ament_package()
