# Copyright (c) 2020 Cisco and/or its affiliates.
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

# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type
import pdb

from dnacentersdk import exceptions
from unittest.mock import patch

from ansible_collections.cisco.dnac.plugins.modules import accesspoint_workflow_manager
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData

import json
import copy
import logging

class TestDnacAccesspointWorkflow(TestDnacModule):

    module = accesspoint_workflow_manager

    test_data = loadPlaybookData("accesspoint_workflow_manager")
    playbook_config_series_error = test_data.get("playbook_config_series_error")
    playbook_config = test_data.get("playbook_config")
    playbook_config_provision = test_data.get("playbook_config_provision")
    playbook_config_missing_rf_profile = test_data.get("playbook_config_missing_rf_profile")
    playbook_config_series_error = test_data.get("playbook_config_series_error")
    playbook_config_missing_update = test_data.get("playbook_config_missing_update")


    def setUp(self):
            super(TestDnacAccesspointWorkflow, self).setUp()

            self.mock_dnac_init = patch(
                "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__")
            self.run_dnac_init = self.mock_dnac_init.start()
            self.run_dnac_init.side_effect = [None]
            self.mock_dnac_exec = patch(
                "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
            )
            self.run_dnac_exec = self.mock_dnac_exec.start()

            self.load_fixtures()

    def tearDown(self):
            super(TestDnacAccesspointWorkflow, self).tearDown()
            self.mock_dnac_exec.stop()
            self.mock_dnac_init.stop()

    def load_fixtures(self, response=None, device=""):
        """
        Load fixtures for user.
        """
        if "already_provision_device" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_device_detail"), 
                self.test_data.get("get_site_exist_response"),
                self.test_data.get("get_membership"),
                self.test_data.get("verify_get_device_info"),
                self.test_data.get("get_accesspoint_config"),
                self.test_data.get("provision_ap_response"),
                self.test_data.get("provision_status"),
                self.test_data.get("camel_to_snake_case"), 
                self.test_data.get("provision_get_ap_response"),
            ]
        elif "provision_device" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_device_detail"), 
                self.test_data.get("get_site_exist_response"),
                self.test_data.get("get_membership_empty"),
                self.test_data.get("verify_get_device_info"),
                self.test_data.get("get_accesspoint_config"),
                self.test_data.get("provision_ap_response"),
                self.test_data.get("provision_execution_response"),
                self.test_data.get("provision_status"),
                self.test_data.get("camel_to_snake_case"), 
                self.test_data.get("provision_get_ap_response"),
            ]
        elif "update_accesspoint_series_error" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_device_detail_series_error"),
                self.test_data.get("get_site_exist_response"),
                self.test_data.get("get_membership_empty"),
                self.test_data.get("verify_get_device_info"),
                self.test_data.get("get_accesspoint_config"),
                self.test_data.get("provision_ap_response"),
                self.test_data.get("ap_update_response"),
                self.test_data.get("ap_task_status"),
                self.test_data.get("ap_update_status"),
                self.test_data.get("camel_to_snake_case"),
                self.test_data.get("provision_get_ap_response"),
            ]
        elif "update_accesspoint" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_device_detail_all_data"),
                self.test_data.get("get_accesspoint_config"),
                self.test_data.get("ap_update_response"),
                self.test_data.get("ap_task_status"),
                self.test_data.get("ap_update_status"),
            ]
        elif "site_exists" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_site_exist_response"),
            ]

        elif "accesspoint_workflow_manager_invalid_config" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_device_list")
            ]

    def test_accesspoint_workflow_manager_update_accesspoint_series_error(self):
        """
        Test case for user role workflow manager when creating a user.

        This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_config_series_error
            )
        )
        result = self.execute_module(changed=False, failed=True)
        self.assertEqual(
            result.get('msg'),
            "Successfully validated config params: {'mac_address': '90:e9:5e:03:f3:40', 'management_ip_address': None, 'hostname': None, 'rf_profile': 'HIGH', 'site': {'floor': {'name': 'FLOOR2', 'parent_name': 'Global/USA/New York/BLDNYC'}}, 'type': None, 'ap_name': 'LTTS-test1', 'admin_status': None, 'led_status': 'Enabled', 'led_brightness_level': 5, 'ap_mode': 'Local', 'location': 'LTTS/Cisco/Chennai', 'failover_priority': 'Low', 'primary_controller_name': None, 'primary_ip_address': None, 'secondary_controller_name': None, 'secondary_ip_address': None, 'tertiary_controller_name': None, 'tertiary_ip_address': None, 'clean_air_si_2.4ghz': 'Enabled', 'clean_air_si_5ghz': 'Enabled', 'clean_air_si_6ghz': 'Disabled', '2.4ghz_radio': {'admin_status': 'Enabled', 'antenna_name': 'C-ANT9104-2.4GHz', 'radio_role_assignment': 'Client-Serving', 'channel_number': 2, 'powerlevel': 2, 'radio_type': 1}, '5ghz_radio': {'admin_status': 'Enabled', 'antenna_name': 'AIR-ANT2513P4M-N-5GHz', 'radio_role_assignment': 'Client-Serving', 'channel_number': 44, 'powerlevel': 2, 'channel_width': '20 MHz', 'radio_type': 2}, '6ghz_radio': None, 'xor_radio': None, 'tri_radio': None, 'ap_selected_fields': 'id,hostname,family,type,mac_address,management_ip_address,ap_ethernet_mac_address', 'ap_config_selected_fields': 'mac_address,eth_mac,ap_name,led_brightness_level,led_status,location,radioDTOs'}"
        )

    def test_accesspoint_workflow_manager_update_accesspoint(self):
        """
        Test case for user role workflow manager when creating a user.

        This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_config
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            #result.get('response').get('accesspoints_updates').get('ap_update_msg'),
            result.get('ap_update_msg'),
            'AP Configuration - NY-AP1-9130AXE updated Successfully'
        )

    def test_accesspoint_workflow_manager_missing_rf_profile(self):
        """
        Test case for user role workflow manager when creating a user.

        This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_config_missing_rf_profile
            )
        )
        result = self.execute_module(changed=True, failed=True)
        self.assertEqual(
            result.get('msg'),
            "MAC Address is not Access point"
        )

    def test_accesspoint_workflow_manager_already_provision_device(self):
        """
        Test case for user role workflow manager when creating a user.

        This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_config_provision
            )
        )
        result = self.execute_module(changed=False, failed=False)
        self.assertEqual(
            #result.get('response').get('accesspoints_updates').get('ap_update_msg'),
            result.get('ap_update_msg'),
            "AP - NY-AP1-9130AXE does not need any update"
        )

    def test_accesspoint_workflow_manager_provision_device(self):
        """
        Test case for user role workflow manager when creating a user.

        This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_config_provision
            )
        )
        result = self.execute_module(changed=False, failed=False)
        self.assertEqual(
            result.get('response').get('accesspoints_updates').get('provision_message'),
            #result.get('ap_update_msg'),
            "AP NFW-AP2-3802I provisioned Successfully"
        )

    # def test_accesspoint_workflow_manager_missing_updates_update_accesspoint(self):
    #     """
    #     Test case for user role workflow manager when creating a user.

    #     This test case checks the behavior of the user workflow when creating a new user in the specified Cisco Catalyst Center.
    #     """
    #     set_module_args(
    #         dict(
    #             dnac_host="1.1.1.1",
    #             dnac_username="dummy",
    #             dnac_password="dummy",
    #             dnac_log=True,
    #             state="merged",
    #             config=self.playbook_config_missing_update
    #         )
    #     )
    #     result = self.execute_module(changed=True, failed=False)
    #     self.assertEqual(
    #         result.get('ap_update_msg'),
    #         'AP Configuration - NY-AP1-9130AXE updated Successfully'
    #     )