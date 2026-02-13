# Copyright (c) 2026, b»robotized group
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from launch import LaunchDescription

from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.actions import Node
from launch_ros.substitutions import FindPackageShare


def generate_launch_description():
    pkg_share = FindPackageShare("opcua_bringup")

    # Default paths to certificates
    default_cert_path = PathJoinSubstitution([pkg_share, "config", "server_cert.der"])
    default_key_path = PathJoinSubstitution([pkg_share, "config", "server_key.der"])

    return LaunchDescription(
        [
            DeclareLaunchArgument(
                "security_policy",
                default_value="Sign",
                description="Security Policy: None, Sign, or SignAndEncrypt",
            ),
            DeclareLaunchArgument(
                "certificate_path",
                default_value=default_cert_path,
                description="Path to the server certificate (DER format)",
            ),
            DeclareLaunchArgument(
                "private_key_path",
                default_value=default_key_path,
                description="Path to the server private key (DER format)",
            ),
            DeclareLaunchArgument(
                "auto_generate_certificates",
                default_value="false",
                description="Automatically generate certificates if missing",
            ),
            DeclareLaunchArgument(
                "allow_anonymous", default_value="true", description="Allow anonymous access"
            ),
            Node(
                package="opcua_bringup",
                executable="example_opcua_server",
                name="opcua_server",
                output="screen",
                parameters=[
                    {
                        "security.policy": LaunchConfiguration("security_policy"),
                        "security.certificate_path": LaunchConfiguration("certificate_path"),
                        "security.private_key_path": LaunchConfiguration("private_key_path"),
                        "security.auto_generate_certificates": LaunchConfiguration(
                            "auto_generate_certificates"
                        ),
                        "allow_anonymous": LaunchConfiguration("allow_anonymous"),
                    }
                ],
            ),
        ]
    )
