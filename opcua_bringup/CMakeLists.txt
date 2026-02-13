cmake_minimum_required(VERSION 3.20)
project(opcua_bringup)

if(CMAKE_CXX_COMPILER_ID MATCHES "(GNU|Clang)")
  add_compile_options(-Wall -Wextra -Werror=conversion -Werror=unused-but-set-variable -Werror=return-type -Werror=shadow)
endif()

if(POLICY CMP0148)
  cmake_policy(SET CMP0148 OLD)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(open62541pp_vendor REQUIRED)
# uncomment the following section in order to fill in
# further dependencies manually.
# find_package(<dependency> REQUIRED)

add_executable(example_opcua_server src/example_opcua_server.cpp)

target_link_libraries(example_opcua_server open62541pp::open62541pp)
install(TARGETS
  example_opcua_server
  DESTINATION lib/${PROJECT_NAME}
)

install(
  DIRECTORY urdf launch config
  DESTINATION share/${PROJECT_NAME}
)

ament_package()
