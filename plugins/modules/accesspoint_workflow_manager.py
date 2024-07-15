# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import time
import re
import json
__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Megha Kandari, Sonali Deepthi Kesali, Natarajan, Madhan Sankaranarayanan, Abhishek Maheshwari")

DOCUMENTATION = r"""
---
module: accesspoint_workflow_manager
short_description: accesspoint_workflow_manager used to automate bulk AP configuration changes.
description:
  - Automates bulk configuration changes for Access Points (APs).
  - Modify AP display names, AP names, or other parameters.
  - Filter specific device details, such as selecting devices with hostnames matching "NFW-AP1-9130AXE".
  - Compares input details with current AP configurations and applies desired changes only to relevant APs.

version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.accesspoint_workflow_manager
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Sonali Deepthi Kesali (@skesali)
  - Megha Kandari (@mekandar)
  - Natarajan (@natarajan)
  - Madhan Sankaranarayanan (@madhansansel)
  - Abhishek Maheshwari (@abmahesh)

options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center config after applying the playbook config.
    type: bool
    default: False
  state:
    description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [merged]
    default: merged
  config:
    description: List of details of AP being managed.
    type: list
    elements: dict
    required: True
    suboptions:
      mac_address:
        description: |
          MAC Address field used to identify the device. If MAC address is known,
          it must be provided. This field cannot be modified.
          To identify the specific access point, any one of the (mac_address, hostname,
          management_ip_address) parameters is required.
          Example: mac_address: "90:e9:5e:03:f3:40"
        type: str
        required: True
      rf_profile:
        description: |
          Radio Frequency (RF) profile of the Access Point (e.g., 'HIGH').
        type: str
        example: "HIGH"
      site:
        description: |
          Current site details where the Access Point is located.
        type: object
        suboptions:
          floor:
            description: |
              Floor details of the current site.
            type: object
            suboptions:
              name:
                description: |
                  Name of the floor (e.g., 'FLOOR1').
                type: str
              parent_name:
                description: |
                  Parent name of the floor in the site hierarchy (e.g., 'Global/USA/New York/BLDNYC').
                type: str
      ap_name:
        description: |
          Current AP name that needs to be changed along with the new AP name.
          Example: ap_name: "Test2", ap_name_new: "NFW-AP1-9130AXE"
        type: str
        required: False
      admin_status:
        description: |
          Status of the AP configuration. Accepts "Enabled" or "Disabled".
          Example: admin_status: "Enabled"
        type: str
        required: False
      led_status:
        description: |
          State of the AP's LED. Accepts "Enabled" or "Disabled".
          Example: led_status: "Enabled"
        type: str
        required: False
      led_brightness_level:
        description: |
          Brightness level of the AP's LED. Accepts values from 1 to 8.
          Example: led_brightness_level: 3
        type: int
        required: False
      ap_mode:
        description: |
          Mode of operation for the Access Point (AP). Possible values include "local/flexconnect" or "monitor" or "sniffer" or Bridge/Flex+Bridge.
          - If Ap mode is local/flex, then only radio role assignment can be changed.
          Example: ap_mode: "local"
        type: str
        required: False
      location:
        description: |
          Location name of the AP. Provide this data if a change is required.
          Example: location: "Bangalore"
        type: str
        required: False
      failover_priority:
        description: |
          Priority order for failover in AP configuration. Accepts "Low" or "Medium" or "High" or "Critical".
        type: str
        required: False
      clean_air_si_2.4ghz/5ghz/6ghz:
        description: |
          Clean Air Spectrum Intelligence (SI) feature status for 2.4/5/6GHz band. Indicates whether Clean Air Spectrum Intelligence is enabled or disabled.
          Example: clean_air_si_2.4ghz: "Enabled"
        type: str
        required: False
      primary_controller_name:
        description: |
          Name or identifier of the primary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: primary_controller_name: "SJ-EWLC-1"
        type: str
        required: False
      primary_ip_address:
        description: |
          IP address of the primary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: primary_ip_address:
                   address: "204.192.4.200"
        type: str
        required: False
      secondary_controller_name:
        description: |
          Name or identifier of the secondary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: secondary_controller_name: "Inherit from site/Clear"
        type: str
        required: False
      secondary_ip_address:
        description: |
          IP address of the secondary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: secondary_ip_address:
                   address: "10.0.0.2"
        type: str
        required: False
      tertiary_controller_name:
        description: |
          Name or identifier of the tertiary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: tertiary_controller_name: "Clear"
        type: str
        required: False
      tertiary_ip_address:
        description: |
          IP address of the tertiary wireless LAN controller (WLC) managing the Access Point (AP).
          Example: tertiary_ip_address:
                   address: "10.0.0.3"
        type: str
        required: False
      2.4ghz_radio/5ghz_radio/6ghz_radio/xor_radio/tri_radio:
        suboptions:
          admin_status:
            description: |
              Administrative status for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface.
              Example: admin_status: "Enabled"
            type: str
            required: False
          antenna_name:
            description: |
              Name or type of antenna used for the 2.4GHz/5GHz/xor_radio/tri_radio radio interface.
              Example: antenna_name: "other"
            type: str
            required: False
          antenna_gain:
            description: |
              Antenna gain value in decibels (dB) for the 2.4GHz/5GHz/xor_radio/tri_radio radio interface.
              Example: antenna_gain: 4
            type: int
            required: False
          radio_role_assignment:
            description: |
              Role assignment mode for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface. Accepts "Auto" or "Client-serving" or "Monitor".
              - If radio_role_assignment is "client-serving", then only power-level and channel-level can be changed.
              Example: radio_role_assignment: "Auto"
            type: str
            required: False
          cable_loss:
            description: |
              Cable loss in dB for the 2.4GHz/5GHz/xor_radio/tri_radio radio interface.
              Example: cable_loss: 75
            type: int
            required: False
          antenna_cable_name:
            description: |
              Name or type of antenna cable used for the 2.4GHz/5GHz/xor_radio/tri_radio radio interface.
              Example: antenna_cable_name: "other"
            type: str
            required: False
          channel_assignment_mode:
            description: |
              Mode of channel assignment for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface. Accepts "Global" or "Custom".
              - For 5GHz Custom, it accepts values like 36, 40, 44, 48, 52, 56, 60, 64, 100,
                104, 108, 112, 116, 120, 124, 128, 132,
                136, 140, 144, 149, 153, 157, 161, 165,
                169, 173.
              - For 2.4GHz Custom, it accepts values like 1 to 12.
              Example: channel_assignment_mode: "Custom"
            type: str
            required: False
          channel_number:
            description: |
              Custom channel number configured for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface.
              Example: channel_number: 36
            type: int
            required: False
          channel_width:
            description: |
              Width of the channel configured for the 5GHz/6GHz/xor_radio/tri_radio radio interface. Accepts values "20MHz" or "40MHz" or "80MHz" or "160MHz".
              Example: channel_width: "20 MHz"
            type: str
            required: False
          power_assignment_mode:
            description: |
              Mode of power assignment for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface. Accepts "Global" or "Custom".
              - In Custom, it accepts values 1 to 8.
              Example: power_assignment_mode: "Custom"
            type: str
            required: False
          powerlevel:
            description: |
              Custom power level configured for the 2.4GHz/5GHz/6GHz/xor_radio/tri_radio radio interface.
              Example: powerlevel: 1
            type: int
            required: False
          dual_radio_mode:
            description: |
              Mode of operation configured for the tri_radio radio interface. Specifies how the access point (AP) manages its dual radio functionality.
              Example: dual_radio_mode: "Auto"
            type: str
            required: False


requirements:
- dnacentersdk >= 2.4.5
- python >= 3.8
notes:
  - SDK Method used are
    devices.get_device_list
    wireless.get_access_point_configuration
    sites.get_site
    sda.get_device_info
    sites.assign_devices_to_site
    wireless.ap_provision
    wireless.configure_access_points
    sites.get_membership

  - Paths used are
    get /dna/intent/api/v1/network-device
    get /dna/intent/api/v1/site
    GET/dna/intent/api/v1/business/sda/device
    post /dna/intent/api/v1/wireless/ap-provision
    GET/dna/intent/api/v1/membership/{siteId}
    GET/dna/intent/api/v1/wireless/accesspoint-' + 'configuration/details/{task_id}'
    post /dna/intent/api/v2/wireless/accesspoint-configuration
    Post/dna/intent/api/v1/assign-device-to-site/{siteId}/device
"""

EXAMPLES = r"""
- name: Provision/Move/Update Wireless Access Point Configuration
  hosts: dnac_servers
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
  tasks:
  - name: Create/Update Wireless Access Point Configuration
  hosts: dnac_servers
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-2.4GHz"
              radio_role_assignment: "Client-Serving"
              powerlevel: 5
              channel_number: 7
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              power_assignment_mode: "Global"
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              channel_assignment_mode: "Global"
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 44
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        config:
          - mac_address: 90:e9:5e:03:f3:40
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9104-Single-D0-5GHz"
              channel_number: 52
              powerlevel: 5
              channel_width: "40 MHz"
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9103-2.4GHz"
              channel_number: 9
              powerlevel: 4
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9103-5GHz"
              channel_number: 40
              powerlevel: 3
              channel_width: "20 MHz"
      register: output_list

    - name: Provisioning and Re-provisiong Access Point Site details
      cisco.dnac.accesspoint_movement:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        state: merged
        force_sync: False
        config:
              - ap_type: "Unified AP"
                mac_address:  90:e9:5e:03:f3:40
                rf_profile: "HIGH"
                site:
                  floor:
                    name: "FLOOR1"
                    parent_name: "Global/USA/New York/BLDNYC"
      register: output_list

    - name: Updating Access Point Site / Configuration details
      cisco.dnac.accesspoint_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: False
        state: merged
        force_sync: False
        config:
          - mac_address: 90:e9:5e:03:f3:40
            rf_profile: "HIGH"
            site:
              floor:
                name: "FLOOR1"
                parent_name: "Global/USA/New York/BLDNYC"
            ap_name: "LTTS-test2"
            admin_status: "Enabled"
            led_status: "Enabled"
            led_brightness_level: 5
            ap_mode: "Local"
            location: "LTTS/Cisco/Chennai"
            failover_priority: "Low"
            2.4ghz_radio:
              admin_status: "Enabled"
              antenna_name: "C-ANT9104-2.4GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 5
              powerlevel: 2
            5ghz_radio:
              admin_status: "Enabled"
              antenna_name: "AIR-ANT2513P4M-N-5GHz"
              radio_role_assignment: "Client-Serving"
              channel_number: 36
              powerlevel: 2
              channel_width: "40 MHz"
      register: output_list
"""

RETURN = r"""
#Case-1: Modification of the AP details updated and Rebooted Access Point
response:
  description: A list of dictionaries containing details about the AP updates and verification
                results, as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    "response": [
        {
            "accesspoints_updates": {
                "response": {
                    "macAdress": "34:5d:a8:0e:20:b4",
                    "response": {
                        "taskId": "2ce139fa-1d58-4739-a6ad-b735b97e4dfe",
                        "url": "/api/v1/task/2ce139fa-1d58-4739-a6ad-b735b97e4dfe"
                    }
                }
            }
        },
        {
            "accesspoints_verify": {
                "have": [
                    {
                        "ap_name": "NFW-AP1-9130AXE",
                        "eth_mac": "34:5d:a8:0e:20:b4",
                        "led_brightness_level": 2,
                        "led_status": "Enabled",
                        "location": "LTTS-Bangalore",
                        "mac_address": "90:e9:5e:03:f3:40"
                    }
                ],
                "message": "The update for AP Config 'NFW-AP1-9130AXE' has been successfully verified.",
                "want": {
                    "ap_name": "LTTS-Test1",
                    "ap_name_new": "NFW-AP1-9130AXE",
                    "hostname": null,
                    "led_brightness_level": 2,
                    "led_status": "Enabled",
                    "location": "LTTS-Bangalore",
                    "mac_address": "90:e9:5e:03:f3:40",
                    "management_ip_address": null
                }
            }
        }
    ]
#Case-2: Provisioning and Re-Provisioning of Accesspoint
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
                        {
                            'bapiKey': 'd897-19b8-47aa-a9c4',
                                'bapiName': 'AP Provision',
                                    'bapiExecutionId': '97d5edd5-d5db-40d8-9ab6-f15dc4a5cc30',
                                        'tartTime': 'Wed Jul 03 18:37:24 UTC 2024',
                                        'startTimeEpoch': 1720031844919,
                                        'endTimeEpoch': 0,
                                    'timeDuration': 0,
                                'status': 'IN_PROGRESS',
                            'runtimeInstanceId': 'DNACP_Runtime_3f8f258c-9f7a-4511-b361-592ee9e0c4d2'
                        }
                    }

"""


from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_str,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule


class Accesspoint(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.payload = module.params
        self.keymap = {}
        self.radio_interface = ["6ghz_radio", "xor_radio", "tri_radio"]
        self.allowed_series = {
            "6ghz_radio": ["9136I", "9162I", "9163E", "9164I", "IW9167IH", "9178I", "9176I",
                           "9176D1"],
            "xor_radio": ["2800", "3800", "4800", "9120", "9166"],
            "tri_radio": ["9124AXE", "9130AXI", "9130AXE"]
        }
        self.allowed_channel_no = {
            "2.4ghz_radio": list(range(1, 12)),
            "5ghz_radio": (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
                           124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173)
        }

    def validate_input_yml(self):
        """
        Validate fields provided in a YAML file against predefined specifications.
        Checks playbook configuration to ensure it matches expected structure and data types.

        Parameters:
        - self (object): Instance of a class for Cisco Catalyst Center interaction.

        Returns:
        - Updates instance attributes:
            - self.msg: Validation result message.
            - self.status: Validation status ('success' or 'failed').
            - self.validated_config: Validated 'config' parameter if successful.

        Description:
        Example:
        Instantiate the class and call 'validate_input_yml'.
        - 'self.status' is 'success' on successful validation; 'self.validated_config' holds
            validated data.
        - 'self.status' is 'failed' on validation failure; 'self.msg' describes issues.
        """

        self.log('Validating the Playbook Yaml File..', "INFO")
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        aplist = self.payload.get("config")
        aplist = self.camel_to_snake_case(aplist)
        aplist = self.update_site_type_key(aplist)
        accesspoint_spec = {
            "mac_address": {"required": False, "type": "str"},
            "management_ip_address": {"required": False, "type": "str"},
            "hostname": {"required": False, "type": "str"},
            "rf_profile": {"required": False, "type": "str"},
            "site": {"required": False, "type": "dict"},
            "type": {"required": False, "type": "str"},
            "ap_name": {"required": False, "type": "str"},
            "admin_status": {"required": False, "type": "str"},
            "led_status": {"required": False, "type": "str"},
            "led_brightness_level": {"required": False, "type": "int"},
            "ap_mode": {"required": False, "type": "str"},
            "location": {"required": False, "type": "str"},
            "failover_priority": {"required": False, "type": "str"},
            "primary_controller_name": {"required": False, "type": "str"},
            "primary_ip_address": {"required": False, "type": "dict"},
            "secondary_controller_name": {"required": False, "type": "str"},
            "secondary_ip_address": {"required": False, "type": "dict"},
            "tertiary_controller_name": {"required": False, "type": "str"},
            "tertiary_ip_address": {"required": False, "type": "dict"},
            "clean_air_si_2.4ghz": {"required": False, "type": "str"},
            "clean_air_si_5ghz": {"required": False, "type": "str"},
            "clean_air_si_6ghz": {"required": False, "type": "str"},
            "2.4ghz_radio": {"required": False, "type": "dict"},
            "5ghz_radio": {"required": False, "type": "dict"},
            "6ghz_radio": {"required": False, "type": "dict"},
            "xor_radio": {"required": False, "type": "dict"},
            "tri_radio": {"required": False, "type": "dict"},
            "ap_selected_fields": {"required": False, "type": "str"},
            "ap_config_selected_fields": {"required": False, "type": "str"}
        }

        invalid_list_radio = []
        for each_radio in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio", "xor_radio", "tri_radio"):
            radio_config = aplist[0].get(each_radio)
            valid_param_radio, invalid_params_radio = (None, None)
            if radio_config:
                radio_config_sepc = {
                    "admin_status": {"required": False, "type": "str"},
                    "dual_radio_mode": {"required": False, "type": "str"},
                    "antenna_name": {"required": False, "type": "str"},
                    "antenna_gain": {"required": False, "type": "int"},
                    "radio_role_assignment": {"required": False, "type": "str"},
                    "cable_loss": {"required": False, "type": "int"},
                    "antenna_cable_name": {"required": False, "type": "str"},
                    "channel_assignment_mode": {"required": False, "type": "str"},
                    "channel_number": {"required": False, "type": "int"},
                    "power_assignment_mode": {"required": False, "type": "str"},
                    "powerlevel": {"required": False, "type": "int"},
                    "channel_width": {"required": False, "type": "str"},
                    "radio_band": {"required": False, "type": "str"}
                }
                valid_param_radio, invalid_params_radio = \
                    validate_list_of_dicts([radio_config], radio_config_sepc)
                if len(invalid_params_radio) > 0:
                    invalid_list_radio.append(each_radio + str(invalid_params_radio))

        valid_param, invalid_params = validate_list_of_dicts(aplist, accesspoint_spec)

        if invalid_params or invalid_list_radio:
            self.msg = "Invalid parameters in playbook: {0} ".format(
                "\n".join(invalid_params) + "\n".join(invalid_list_radio)
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_param
        self.msg = "Successfully validated playbook config params:{0}".format(
            self.pprint(valid_param[0]))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_want(self, ap_config):
        """
        Retrieve Access Point configuration and site-related details from the playbook
        needed for AP configuration, provisioning, and re-provisioning.
        Parameters:
            self (object): An instance of a class for Cisco Catalyst Center interaction.
            ap_config (dict): Dictionary containing Access Point configuration information.

        Returns:
            self (object): Updated instance with extracted Access Point configuration
            stored in 'want'.

        Description:
            Extracts all Access Point configuration details from 'ap_config', excluding
            fields such as 'ap_selected_fields' and 'ap_config_selected_fields'.
            The extracted information is stored in the 'want' attribute of the
            instance for use in subsequent workflow steps.
        """
        want = {}

        for key, value in ap_config.items():
            if key not in ("ap_selected_fields", "ap_config_selected_fields"):
                if ap_config.get(key) is not None:
                    want[key] = value

        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")
        return self

    def get_have(self, input_config):
        """
        Retrieve current Access Point configuration and site releated details from
        Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class for Cisco Catalyst Center interaction.
            input_config (dict): Dictionary containing configuration details.

        Returns:
            self (object): Updated instance with retrieved Access Point configuration stored \
                in 'have'.

        Description:
            Checks if the specified Access Point configuration and site exists in the system.
            If found, retrieves details such as MAC address, IP address, hostname,
            associated WLC IP, AP type and site information if available, these details
            are stored in the 'have' attribute of the instance.
        """
        ap_exists = False
        current_ap_config = None
        (ap_exists, current_ap_config) = self.get_current_config(input_config)

        self.log("Current AP config details (have): {0}".format(self.pprint(
            current_ap_config)), "DEBUG")
        have = {}

        if ap_exists:
            have["mac_address"] = current_ap_config.get("mac_address")
            have["ap_exists"] = ap_exists
            have["current_ap_config"] = current_ap_config
            have["ip_address"] = self.payload["access_point_details"]["management_ip_address"]
            have["wlc_provision_status"] = self.payload.get("wlc_provision_status")
            have["associated_wlc_ip"] = self.payload["access_point_details"]["associated_wlc_ip"]
            have["hostname"] = self.payload["access_point_details"]["hostname"]
            have["ap_type"] = self.payload["access_point_details"]["family"]

        if self.payload.get("site_exists"):
            have["site_name_hierarchy"] = self.want["site_name"]
            have["site_exists"] = self.payload["current_site"]
            have["site_required_changes"] = False if self.payload["site_changes"] else True
            have["site_id"] = self.payload["current_site"]["site_id"]

        self.have = have
        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        return self

    def get_diff_merged(self, ap_config):
        """
        Provision, re-provision, update, or create wireless access point configurations in
        Cisco Catalyst Center using playbook-provided fields.
        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            ap_config (dict): Dictionary containing configuration information.

        Returns:
            self (object): Updated instance with operation results stored in 'result'.

        Description:
            Determines whether to Provision, re-provision, update or create the Access Point
            configuration in Cisco Catalyst Center based on provided information.
            If the Access Point and site exists, it compares current configuration
            with input data. If changes are required, it updates the configuration using the
            'configure_access_points' function from the Cisco Catalyst Center API.
            If no updates are needed, it logs that the configuration is up to date.
            Handles provisioning and site assignment if specified by playbook data.
        """
        task_response = None
        self.validate_ap_config_parameters(ap_config).check_return_status()

        if self.have.get("ap_exists"):
            consolidated_data = self.compare_ap_config_with_inputdata(
                self.have["current_ap_config"])
            responses = {}
            if not consolidated_data:
                self.msg = "AP - {0} does not need any update"\
                    .format(self.have.get("current_ap_config").get("ap_name"))
                self.log(self.msg, "INFO")
                del self.payload["access_point_details"]
                responses["accesspoints_updates"] = {
                    "ap_config_response": self.payload["access_point_config"],
                    "ap_config_message": self.msg
                }
                self.result['ap_update_msg'] = self.msg
                self.result["changed"] = False
            else:
                self.log('Final AP Configuration data to update {0}'.format(self.pprint(
                    consolidated_data)), "INFO")
                task_response = self.update_ap_configuration(consolidated_data)

                if task_response and isinstance(task_response, dict):
                    resync_retry_count = self.payload.get("dnac_api_task_timeout", 100)
                    resync_retry_interval = self.payload.get("dnac_task_poll_interval", 1)
                    while resync_retry_count:
                        task_details_response = self.get_task_details(
                            task_response["response"]["taskId"])
                        self.log("Status of the task: {0} .".format(self.status), "INFO")
                        if task_details_response.get("endTime") is not None and\
                           task_details_response.get("isError") is False:
                            self.result['changed'] = True
                            self.log("Task Details: {0} .".format(self.pprint(
                                task_details_response)), "INFO")
                            self.msg = "AP Configuration - {0} updated Successfully"\
                                .format(self.have["current_ap_config"].get("ap_name"))
                            self.log(self.msg, "INFO")
                            responses["accesspoints_updates"] = {
                                "ap_update_config_task_response": task_response,
                                "ap_update_config_task_details": task_details_response,
                                "ap_config_update_status": self.msg
                            }
                            self.result['ap_update_msg'] = self.msg
                            break
                        if task_details_response.get("endTime") is not None and \
                           task_details_response.get("isError") is True:
                            self.result['changed'] = False
                            self.status = "failed"
                            self.msg = "Unable to get success response, hence AP config not updated"
                            self.log(self.msg, "ERROR")
                            self.log("Task Details: {0} .".format(self.pprint(
                                task_details_response)), "ERROR")
                            responses["accesspoints_updates"] = {
                                "ap_update_config_task_response": task_response,
                                "ap_update_config_task_details": task_details_response,
                                "ap_config_update_status": self.msg}
                            self.module.fail_json(msg=self.msg, response=responses)
                            break

                        time.sleep(resync_retry_interval)
                        resync_retry_count = resync_retry_count - 1

            if self.have.get("site_required_changes") and self.want.get("site") is not None:
                if self.have["wlc_provision_status"] == "success":
                    provision_status, provision_details = self.provision_device()
                    if provision_status == "SUCCESS":
                        self.result['changed'] = True
                        self.msg = "AP {0} provisioned Successfully".format(self.have["hostname"])
                        self.log(self.msg, "INFO")
                        responses["accesspoints_updates"].update({
                            "provision_response": provision_details,
                            "provision_message": self.msg
                        })
            elif self.want.get("site") is not None:
                self.msg = "AP {0} already provisioned in the same site {1}".format(
                    self.have["hostname"], self.have.get("site_name_hierarchy"))
                self.log(self.msg, "INFO")
                self.result['changed'] = False
                responses["accesspoints_updates"].update({"provision_message": self.msg})

            self.result["response"] = responses
            return self
        self.status = "failed"
        self.msg = "Unable to call update AP config API "
        self.log(self.msg, "ERROR")
        return self

    def verify_diff_merged(self, config):
        """
        Verify if configuration changes for an Access Point (AP) have been successfully applied
        in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.

        Returns:
            self (object): Updated instance reflecting verification results.

        Description:
            Checks the current and desired states of the AP configuration in Cisco Catalyst Center.
            Logs the current and desired configuration states and verifies if the AP exists and
            whether updates are required. If the configuration matches the desired state,
            it logs a success message. Otherwise, it indicates a potential issue with the
            merge operation.
        """

        self.get_have(config)
        self.log("Current AP Config (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired AP Config (want): {0}".format(str(self.want)), "INFO")

        ap_exists = self.have.get("ap_exists")
        ap_name = self.have.get("current_ap_config").get("ap_name")

        if not ap_exists:
            self.status = "failed"
            self.msg = "AP Config '{0}' does not exist in the system.".format(ap_name)
            self.log(self.msg, "ERROR")
            return self
        else:
            self.status = "success"
            self.msg = """The requested AP Config '{0}' is present in the Cisco Catalyst Center
                        and its creation has been verified.""".format(ap_name)
            self.log(self.msg, "INFO")

        require_update = self.compare_ap_config_with_inputdata(self.have["current_ap_config"])
        self.log(str(require_update), "INFO")

        if not require_update:
            msg = "The update for AP Config '{0}' has been successfully verified.".format(ap_name)
            self.log(msg, "INFO")
            self.status = "success"

            ap_selected_fields = self.payload.get("config")[0].get("ap_selected_fields")
            if ap_selected_fields is None or ap_selected_fields == "" or \
               ap_selected_fields == "all":
                self.payload["access_point_details"] = self.payload["access_point_details"]
            else:
                self.payload["access_point_details"] = self.data_frame(
                    ap_selected_fields, [self.payload["access_point_details"]])

            ap_config_selected_fields =\
                self.payload.get("config")[0].get("ap_config_selected_fields")

            if ap_config_selected_fields is None or ap_config_selected_fields == "" \
               or ap_config_selected_fields == "all":
                self.payload["access_point_config"] = self.payload["access_point_config"]
            else:
                self.payload["access_point_config"] = self.data_frame(
                    ap_config_selected_fields, [self.payload["access_point_config"]])

            self.have["current_ap_config"] = self.payload["access_point_config"]

            responses = {}
            responses["accesspoints_verify"] = {"want": self.want,
                                                "have": self.have,
                                                "message": msg}
            self.result['response'].append(responses)
        else:
            self.msg = "Configuration for AP '{0}' does not match the desired state."\
                .format(ap_name)
            self.log(self.msg, "INFO")
            self.status = "failed"

        return self

    def validate_radio_series(self, ap_config):
        """
        Additional validation to check if the provided input radio configuration data series
        can be updated to the Access Point radio configuration in Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            ap_config (dict): Dictionary containing the input configuration details.

        Returns:
            list: List of invalid radio interfaces with details.

        Description:
            Iterates through available radio interfaces and checks if the Access Point
            series supports the specified radio type. If not supported, adds details
            to the 'invalid_series' list. Returns the list of invalid radio interfaces
            for further action or validation.
        """
        invalid_series = []
        for each_series in self.radio_interface:
            if ap_config.get(each_series):
                set_flag = False
                for series in self.allowed_series:
                    pattern = rf'\b{series}\b'
                    match = re.search(pattern, self.payload["access_point_details"][0]["series"],
                                      re.IGNORECASE)
                    if match:
                        set_flag = True
                        break
                if set_flag is False:
                    invalid_series.append(
                        "Access Point series '{0}' not supported for the radio type {1} allowed\
                        series {2} ".format(self.payload["access_point_details"][0]["series"],
                                            each_series, ", ".join(self.allowed_series)))
        return invalid_series

    def validate_ap_config_parameters(self, ap_config):
        """
        Additional validation for the update API AP configuration, AP provisioning,
        and re-provisioning payload.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - ap_config (dict): A dictionary containing the input configuration details.

        Returns:
        An instance of the class with updated attributes:
            - self.msg (str): A message describing the validation result.
            - self.status (str): The status of the validation ('success' or 'failed').

        Description:
        This method validates various parameters in the AP configuration, AP provisioning, and
        re-provisioning provided by the playbook. It checks and logs errors for fields such as
        MAC address validity, IP address formats, string lengths, and specific values for
        fields like LED status and radio settings.

        Example:
        To use this method, create an instance of the class and call 'validate_ap_config_parameters'
        on it. If validation succeeds, 'self.status' will be 'success'. If it fails, 'self.status'
        will be 'failed', and 'self.msg' will describe the validation issues.
        """

        errormsg = []
        invalid_series = self.validate_radio_series(ap_config)

        if len(invalid_series) > 0:
            errormsg.append(invalid_series)

        if ap_config.get("mac_address"):
            mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if not mac_regex.match(ap_config["mac_address"]):
                errormsg.append("mac_address : Invalid MAC Address '{0}' in playbook.".format(
                                ap_config["mac_address"]))

        if ap_config.get("management_ip_address"):
            if not self.is_valid_ipv4(ap_config["management_ip_address"]):
                errormsg.append("management_ip_address: Invalid Management IP Address '{0}'\
                                in playbook".format(ap_config["management_ip_address"]))

        if ap_config.get("rf_profile"):
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_config["rf_profile"], param_spec, "rf_profile", errormsg)

        if ap_config.get("site"):
            if ap_config.get("site").get("floor").get("name"):
                if not isinstance(ap_config.get("site").get("floor").get("name"), str) or \
                len(ap_config.get("site").get("floor").get("name")) > 32:
                    errormsg.append("name: Invalid type or length > 32 characters \
                                        in playbook.")

            if ap_config.get("site").get("floor").get("parent_name"):
                if not isinstance(ap_config.get("site").get("floor").get("parent_name"), str) or \
                len(ap_config.get("site").get("floor").get("parent_name")) > 64:
                    errormsg.append("parent_name: Invalid type or length > 64 characters \
                                        in playbook.")

        if ap_config.get("ap_name"):
            param_spec = dict(type="str", length_max=32)
            validate_str(ap_config["ap_name"], param_spec, "ap_name", errormsg)

        if ap_config.get("led_brightness_level"):
            if ap_config["led_brightness_level"] not in range(1, 9):
                errormsg.append("led_brightness_level: Invalid LED Brightness level '{0}'\
                                in playbook".format(ap_config["led_brightness_level"]))

        if ap_config.get("led_status") and ap_config.get("led_status")\
            not in ("Disabled", "Enabled"):
                errormsg.append("led_status: Invalid LED Status '{0}' in playbook".format(
                                ap_config["led_status"]))

        if ap_config.get("location"):
            param_spec = dict(type="str", length_max=255)
            validate_str(ap_config["location"], param_spec, "location", errormsg)

        if ap_config.get("ap_mode"):
            if ap_config.get("ap_mode") not in ("Local", "Monitor", "Sniffer",
                                                "Bridge"):
                errormsg.append("ap_mode: Invalid value '{0}' for ap_mode in playbook.\
                                Must be one of: Local, Monitor, Sniffer or Bridge."\
                                .format(ap_config.get("ap_mode")))

        if ap_config.get("failover_priority"):
            if ap_config.get("failover_priority") not in ("Low", "Medium", "High", "Critical"):
                errormsg.append("failover_priority: Invalid value '{0}' for failover_priority\
                                in playbook. Must be one of:  Low, Medium, High or Critical."\
                                .format(ap_config.get("failover_priority")))

        if ap_config.get("clean_air_si_2.4ghz"):
            if ap_config.get("clean_air_si_2.4ghz") not in ("Enabled", "Disabled"):
                errormsg.append("clean_air_si_2.4ghz: Invalid value '{0}' for clean air 2.4ghz\
                            in playbook. Must be either 'Enabled' or 'Disabled'."\
                            .format(ap_config.get("clean_air_si_2.4ghz")))

        if ap_config.get("clean_air_si_5ghz"):
            if ap_config.get("clean_air_si_5ghz") not in ("Enabled", "Disabled"):
                errormsg.append("clean_air_si_5ghz: Invalid value '{0}' for clean air 6ghz\
                            in playbook. Must be either 'Enabled' or 'Disabled'."\
                            .format(ap_config.get("clean_air_si_5ghz")))

        if ap_config.get("clean_air_si_6ghz"):
            if ap_config.get("clean_air_si_6ghz") not in ("Enabled", "Disabled"):
                errormsg.append("clean_air_si_6ghz: Invalid value '{0}' for clean air 6ghz\
                            in playbook. Must be either 'Enabled' or 'Disabled'."\
                            .format(ap_config.get("clean_air_si_6ghz")))

        if ap_config.get("primary_controller_name"):
            if ap_config["primary_controller_name"] == "":
                errormsg.append("primary_controller_name: Invalid primary controller name '{0}'\
                                in playbook. Please select one of: Inherit from site/Clear or \
                                Controller name."\
                                .format(ap_config["primary_controller_name"]))

        if ap_config.get("secondary_controller_name"):
            if ap_config["secondary_controller_name"] == "":
                errormsg.append("secondary_controller_name: Invalid Secondary Controller Name '{0}'\
                                in playbook. Please select one of: Inherit from site/Clear or \
                                controller name."\
                                .format(ap_config["secondary_controller_name"]))

        if ap_config.get("tertiary_controller_name"):
            if ap_config["tertiary_controller_name"] == "":
                errormsg.append("tertiary_controller_name: Invalid Tertiary Controller Name '{0}' \
                                in playbook. Please select: Clear or Controller name."\
                                .format(ap_config["tertiary_controller_name"]))

        if ap_config.get("primary_ip_address"):
            if not self.is_valid_ipv4(ap_config["primary_ip_address"]["address"]):
                errormsg.append("primary_ip_address: Invalid Primary IP Address '{0}' in playbook"\
                                .format(ap_config["primary_ip_address"]))

        if ap_config.get("secondary_ip_address"):
            if not self.is_valid_ipv4(ap_config["secondary_ip_address"]["address"]):
                errormsg.append("secondary_ip_address: Invalid Secondary IP Address '{0}'\
                                in playbook".format(ap_config["secondary_ip_address"]))

        if ap_config.get("tertiary_ip_address"):
            if not self.is_valid_ipv4(ap_config["tertiary_ip_address"]["address"]):
                errormsg.append("tertiary_ip_address: Invalid Tertiary IP Address '{0}'\
                                 in playbook".format(ap_config["tertiary_ip_address"]))

        if ap_config.get("dual_radio_mode") and \
            ap_config.get("dual_radio_mode") not in ["Auto", "Enable", "Disable"]:
            errormsg.append("dual_radio_mode: Invalid value '{0}' for Dual Radio Mode in playbook.\
                             Must be one of: Auto, Enable, Disable."\
                            .format(ap_config.get("dual_radio_mode")))

        for radio_series in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio", "xor_radio", "tri_radio"):
            if ap_config.get(radio_series):
                each_radio = ap_config.get(radio_series)
                if each_radio.get("admin_status") not in ("Enabled", "Disabled"):
                    errormsg.append("""admin_status: Invalid value '{0}' for admin_status
                                    in playbook. Must be either 'Enabled' or 'Disabled'."""\
                                    .format(each_radio.get("admin_status")))

                if self.have["current_ap_config"]["ap_mode"] not in ("Local/FlexConnect",
                                                                             "Local"):
                    errormsg.append("Radio Params cannot be changed when AP mode is in {0}."\
                        .format(self.have["current_ap_config"]["ap_mode"]))

                if radio_series in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio", "xor_radio"):
                    if radio_series == "2.4ghz_radio":
                        ap_config[radio_series]["radio_type"] = 1
                    elif radio_series == "5ghz_radio":
                        ap_config[radio_series]["radio_type"] = 2
                    elif radio_series == "6ghz_radio":
                        ap_config[radio_series]["radio_type"] = 6
                    elif radio_series == "xor_radio":
                        ap_config[radio_series]["radio_type"] = 3
                    self.want[radio_series]["radio_type"] = ap_config[radio_series]["radio_type"]
                    self.keymap["radio_type"] = "radioType"

                if each_radio.get("antenna_name") is not None:
                    param_spec = dict(type="str", length_max=32)
                    validate_str(each_radio["antenna_name"], param_spec, "antenna_name", errormsg)

                if each_radio.get("antenna_gain") is not None:
                    if each_radio["antenna_gain"] not in range(1, 10):
                        errormsg.append("antenna_gain: Invalid Antenna Gain '{0}' in playbook"\
                                .format(each_radio["antenna_gain"]))

                if each_radio.get("channel_assignment_mode") is not None:
                    if each_radio.get("channel_assignment_mode") not in ("Global", "Custom"):
                        errormsg.append("channel_assignment_mode: Invalid value '{0}' \
                            for Channel Assignment Mode in playbook. \
                            Must be either 'Global' or 'Custom'."\
                            .format(each_radio.get("channel_assignment_mode")))

                if each_radio.get("channel_number") is not None:
                    if each_radio.get("channel_number") not in \
                        self.allowed_channel_no[radio_series] :
                        errormsg.append("channel_number: Invalid value '{0}'\
                            for Channel Number in playbook. Must be one of: {1}."\
                            .format(each_radio.get("channel_number"),
                                 str(self.allowed_channel_no[radio_series])))
                    else:
                        current_radio_role = self.check_current_radio_role_assignment(
                            radio_series, self.have["current_ap_config"]["radio_dtos"])
                        if current_radio_role != "Client-Serving":
                            errormsg.append("channel_number: This configuration is only supported\
                                            with Client-Serving Radio Role Assignment {} "\
                            .format(current_radio_role))

                if each_radio.get("channel_width") is not None:
                    if each_radio.get("channel_width") not in ("20 MHz", "40 MHz", "80 MHz",
                                                               "160 MHz"):
                        errormsg.append("channel_width: Invalid value '{0}' \
                        for Channel width in playbook. \
                        Must be one of: '20 MHz', '40 MHz', '80 MHz', or '160 MHz'."\
                        .format(each_radio.get("channel_width")))

                if each_radio.get("power_assignment_mode") is not None:
                    if each_radio.get("power_assignment_mode") not in ("Global", "Custom"):
                        errormsg.append("power_assignment_mode: Invalid value '{0}' \
                            for Power assignment mode in playbook. \
                            Must be either 'Global' or 'Custom'."\
                            .format(each_radio.get("power_assignment_mode")))

                if each_radio.get("powerlevel") is not None:
                    if each_radio["powerlevel"] not in range(1, 9):
                        errormsg.append("powerlevel: Invalid Power level '{0}' in playbook\
                            Must be between 1 to 8.".format(each_radio["powerlevel"]))
                    else:
                        current_radio_role = self.check_current_radio_role_assignment(
                            radio_series, self.have["current_ap_config"]["radio_dtos"])
                        if current_radio_role != "Client-Serving":
                            errormsg.append("channel_number: This configuration is only supported\
                                            with Client-Serving Radio Role Assignment {} "\
                            .format(current_radio_role))

                if each_radio.get("radio_band") is not None:
                    if each_radio.get("radio_band") not in ("2.4 GHz", "5 GHz"):
                        errormsg.append("radio_band: Invalid value '{0}' for Radio band\
                                        in playbook. Must be either '2.4 GHz' or '5 GHz'."\
                            .format(each_radio.get("radio_band")))

                if each_radio.get("radio_role_assignment") is not None:
                    if each_radio.get("radio_role_assignment") not in ("Auto",
                        "Client-Serving", "Monitor"):
                        errormsg.append("radio_role_assignment: Invalid value '{0}' \
                                        for radio role assignment in playbook.\
                            Must be one of: 'Auto', 'Monitor' or 'Client-Serving'."\
                            .format(each_radio.get("radio_role_assignment")))
                    else:
                        if self.have["current_ap_config"]["ap_mode"] not in ("Local/FlexConnect",
                                                                             "Local"):
                            errormsg.append("radio_role_assignment: Invalid value '{0}' \
                                        Hence, AP mode is not Local. Kindly change the AP mode to Local \
                            Then change the radio_role_assignment to Auto ."\
                            .format(each_radio.get("radio_role_assignment")))

        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: '{0}' "\
                     .format(str(" \n ".join(errormsg)))
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params:{0}".format(str(ap_config))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def check_current_radio_role_assignment(self, radio_type, radio_dtos):
        """
        Check the current radio role assignment based on radio type and DTOs.

        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - radio_type (str): Type of radio ("2.4ghz_radio", "5ghz_radio", or "6ghz_radio").
        - radio_dtos (list): List of radio data transfer objects containing slot IDs and
            role assignments.

        Returns:
        - str: Current radio role assignment corresponding to the specified radio type.

        Description:
        This method iterates through the provided list of radio DTOS to find and return
        the radio role assignment based on the specified radio type (2.4 GHz, 5 GHz, or 6 GHz).

        Example:
        To check the current radio role assignment for the 5 GHz radio, call this method with
        '5ghz_radio' as 'radio_type' and the list of radio DTOS.
        """

        for each_dto in radio_dtos:
            if radio_type == "2.4ghz_radio" and "_"+ str(each_dto["slot_id"]) == "_"+str(0):
                return each_dto["radio_role_assignment"]
            elif radio_type == "5ghz_radio" and each_dto["slot_id"] == 1:
                return each_dto["radio_role_assignment"]
            elif radio_type == "6ghz_radio" and each_dto["slot_id"] == 2:
                return each_dto["radio_role_assignment"]

    def get_accesspoint_details(self, input_config):
        """
        Retrieves the current details of an device in Cisco Catalyst Center.

        Parameters:
        - self (object): An instance of the class containing the method.
        - input_config (dict): A dictionary containing the input configuration details.

        Returns:
        A tuple containing a boolean indicating if the device exists and a
        dictionary of the current inventory details based on the input given from
        playbook either mac_address or management_ip_address or hostname
        (
            True,
            {
                "ap_name": "NFW-AP1-9130AXE",
                "eth_mac": "34:5d:a8:0e:20:b4",
                "led_brightnessLevel": 3,
                "led_status": "Enabled",
                "location": "LTTS",
                "mac_address": "90:e9:5e:03:f3:40"
            }
        )

        Description:
        Retrieve device details from Cisco Catalyst Center using provided MAC address, management IP, or hostname.
        If found, return current device details; otherwise, log errors and fail the function.
        """
        accesspoint_exists = False
        current_configuration = {}
        ap_response = None
        input_param = {}
        self.keymap = self.map_config_key_to_api_param(self.keymap, input_config)
        self.keymap["mac_address"] = "macAddress"
        self.keymap["management_ip_address"] = "managementIpAddress"
        self.keymap["hostname"] = "hostname"
        for key in ['mac_address', 'management_ip_address', 'hostname']:
            if input_config.get(key):
                input_param[self.keymap[key]]= input_config[key]
                break

        if not input_param:
            msg = """Required param of mac_address, management_ip_address or hostname
                      is not in playbook config"""
            self.log(msg, "WARNING")
            self.module.fail_json(msg=msg, response=msg)
            return (accesspoint_exists, current_configuration)

        try:
            ap_response = self.dnac._exec(
                family="devices",
                function='get_device_list',
                op_modifies=True,
                params=input_param,
            )

            if ap_response and ap_response.get("response"):
                ap_response = self.camel_to_snake_case(ap_response["response"])
                accesspoint_exists = True
                current_configuration = ap_response[0]

        except Exception as e:
            self.msg = "The provided device '{0}' is either invalid or not present in the \
                     Cisco Catalyst Center.".format(str(input_param))
            self.log(msg + str(e), "WARNING")

        if not accesspoint_exists:
            self.msg = "The provided device '{0}' is either invalid or not present in the \
                     Cisco Catalyst Center.".format(str(input_param))
            self.module.fail_json(msg="MAC Address not exist:", response=str(self.msg))
        else:
            if current_configuration["family"] != "Unified AP":
                self.msg = "Provided device is not Access Point."
                self.module.fail_json(msg="MAC Address is not Access point")
        return accesspoint_exists, current_configuration

    def get_current_config(self, input_config):
        """
        Retrieves the current configuration of an access point and site releated details
        from Cisco Catalyst Center.

        Parameters:
          - self (object): An instance of the class containing the method.
          - input_config (dict): A dictionary containing the input configuration details.
        Returns:
            A tuple containing a boolean indicating if the access point and site exists and a
            dictionary of the current configuration based on the input given from
            playbook either mac_address or management_ip_address or hostname
            (
                True
                {
                    "ap_name": "NFW-AP1-9130AXE",
                    "eth_mac": "34:5d:a8:0e:20:b4",
                    "led_brightnessLevel": 3,
                    "led_status": "Enabled",
                    "location": "LTTS",
                    "mac_address": "90:e9:5e:03:f3:40"
                }
            )
        Description:
            Queries the Cisco Catalyst Center for the existence of an Access Point
            using the provided input configuration details such as MAC address,
            management IP address, or hostname. If found, it retrieves the current
            Access Point configuration and returns it.
        """
        accesspoint_exists = False
        current_configuration = {}

        accesspoint_exists, current_configuration = self.get_accesspoint_details(
            input_config)
        if input_config.get("site"):
            site_exists, current_site = self.site_exists(input_config)
            if site_exists:
                self.payload["site_exists"] = site_exists
                self.payload["current_site"] = current_site
                self.payload["site_changes"] = self.get_site_device(current_site["site_id"],
                                    current_configuration["mac_address"])
                provision_status, wlc_details = self.verify_ap_provision(
                    current_configuration["associated_wlc_ip"])
                self.payload["wlc_provision_status"] = provision_status

        if accesspoint_exists:
            self.payload["access_point_details"] = current_configuration
            ap_ethernet_mac_address = current_configuration["ap_ethernet_mac_address"]
            ap_config_exists, current_configuration = self.get_accesspoint_config(
                ap_ethernet_mac_address)
            if ap_config_exists:
                self.payload["access_point_config"] = current_configuration

        return (accesspoint_exists, current_configuration)

    def get_accesspoint_config(self, ap_ethernet_mac_address):
        """
        Retrieves the access point configuration data from Cisco Catalyst Center.

        Parameters:
          - self (object): An instance of the class containing the method.
          - ap_ethernet_mac_address (str): The Ethernet MAC address of the access point.
          - tuple: A tuple containing a boolean indicating if the access point exists and
            a dictionary of the current configuration.
        Returns:
            (
                True
                {
                    "ap_name": "NFW-AP1-9130AXE",
                    "eth_mac": "34:5d:a8:0e:20:b4",
                    "led_brightnessLevel": 3,
                    "led_status": "Enabled",
                    "location": "LTTS",
                    "mac_address": "90:e9:5e:03:f3:40"
                }
            )
        Description:
            Requests the current configuration of an access point from the Cisco Catalyst Center
            using the Ethernet MAC address. The response is then processed and returned
            as a dictionary.
        """
        input_param = {}
        input_param["key"] = ap_ethernet_mac_address
        current_configuration = {}
        accesspoint_config_exists = False

        try:
            ap_config_response = self.dnac._exec(
                family="wireless",
                function='get_access_point_configuration',
                params=input_param,
            )

            if ap_config_response:
                self.keymap = self.map_config_key_to_api_param(self.keymap, ap_config_response)
                current_configuration = self.camel_to_snake_case(ap_config_response)
                self.log("Received API response from 'get_access_point_configuration': {0}"\
                            .format(self.pprint(current_configuration)), "INFO")
                accesspoint_config_exists = True
        except Exception as e:
            self.log("Unable to get the Accesspoint configuratoin for '{0}' ."\
                        .format(str(input_param) + str(e)), "WARNING")

        return (accesspoint_config_exists, current_configuration)

    def site_exists(self, input_config):
        """
        Checks if the site exists in Cisco Catalyst Center and retrieves current site details
        if they exist.

        Parameters:
        - self (object): An instance of the class containing the method.
        - input_config (dict): A dictionary containing the input configuration details.

        Returns:
        A tuple containing a boolean indicating if the site exists and a dictionary of the
        current site details.

        Description:
        Checks the existence of a site in Cisco Catalyst Center using the provided site details
        from the input configuration. If the site is found, returns current site details;
        otherwise, logs errors and fails the function.
        """
        site_exists = False
        name = None
        parent_name = None
        if input_config.get("site").get("floor"):
            name = input_config.get("site").get("floor").get("name")
            parent_name = input_config.get("site").get("floor").get("parent_name")

        if name and parent_name:
            site_name = parent_name + "/" + name
            self.want["site_name"] = site_name
            try:
                response = self.dnac._exec(
                    family="sites",
                    function='get_site',
                    op_modifies=True,
                    params={"name": site_name},
                )
                if response.get("response"):
                    site = response["response"][0]
                    self.log("Site response: {0}".format(self.pprint(site)), "INFO")
                    location = get_dict_result(site.get("additionalInfo"), 'nameSpace',
                                                    "Location")
                    type_info = location.get("attributes", {}).get("type")

                    if type_info == "floor":
                        site_info = {
                            "floor": {
                                "name": site.get("name"),
                                "parentName": site.get("siteNameHierarchy").split(
                                    "/" + site.get("name"))[0]
                            }
                        }

                    current_site = {
                        "type": type_info,
                        "site": site_info,
                        "site_id": site.get("id"),
                        "site_name": site_info["floor"]["parentName"] +"/" +\
                            site_info["floor"]["name"]
                    }
                    self.log('Current site details: {0}'.format(str(current_site)), "INFO")
                    self.log("Site '{0}' exists in Cisco Catalyst Center".format(site.get("name")),
                            "INFO")
                    site_exists = True
            except Exception as e:
                msg = "The provided site name '{0}' is either invalid or not present in the \
                        Cisco Catalyst Center.".format(self.want.get("site_name"))
                self.log(msg + str(e), "WARNING")
                self.module.fail_json(msg=msg)
                return site_exists, None

        return site_exists, current_site

    def get_site_device(self, site_id, ap_mac_address):
        """
        Fetches device information associated with a specific site and checks if a given AP
        MAC address is present.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_id (str): The identifier for the site whose devices are to be fetched.
            ap_mac_address (str): The MAC address of the Access Point (AP) device to check.

        Returns:
            bool: True if the AP MAC address is found in the site's devices, otherwise False.

        Description:
            This method utilizes the 'get_membership' API to retrieve details about devices
            associated with the specified 'site_id'. It verifies if the AP device identified by
            'ap_mac_address' is among the devices retrieved for the site. If found, it logs a
            success message indicating presence; otherwise, it logs a failure message.

            If the AP MAC address is found in the site, the method returns True. If the device is
            not found or if an error occurs during the API call, it returns False.
        """
        try:
            response = self.dnac._exec(
                family="sites",
                function="get_membership",
                op_modifies=True,
                params={"site_id": site_id}
            )
            if response.get("device"):
                device_mac_info = []
                for device_info in response.get('device', []):
                    response_list = device_info.get('response', [])
                    for response_item in response_list:
                        mac_address = response_item.get('macAddress')
                        if mac_address:
                            device_mac_info.append(mac_address)
                if ap_mac_address in device_mac_info:
                    self.log("Device with MAC address: {macAddress} found in site: {sId},\
                        Proceeding with ap_site updation.".format(macAddress= ap_mac_address,
                                                                sId = site_id), "INFO")
                    return True
                else:
                    self.log("Device with MAC address: {macAddress} not found in site:\
                        {sId}".format(macAddress=ap_mac_address, sId=site_id), "INFO")
                    return False
        except Exception as e:
            self.log("Failed to execute the get_membership function '{}'\
                      Error: {}".format(site_id, str(e)), "ERROR")
            return False

    def verify_ap_provision(self, wlc_ip_address):
        """
        Verifies if the AP (device) is provisioned.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            wlc_ip_address (str): The management IP address of the Wireless LAN Controller (WLC).

        Returns:
            tuple: A tuple containing the provisioning status ("success" or "failed") and
            the provisioning details or error message.

        Description:
            Checks if the WLC specified by the management IP address is provisioned.
            Returns "success" and details if provisioned, otherwise logs an error
            and returns "failed" with error details.
        """

        provision_status = "failed"
        provision_details = None
        device_management_ip_address = wlc_ip_address

        try:
            response = self.dnac._exec(
                family="sda",
                function='get_device_info',
                op_modifies=True,
                params={"device_management_ip_address": device_management_ip_address}
            )
            if response and response.get("status") == "success":
                self.log('Response from get_device_info: {0}'.format(self.pprint(response)),
                         "INFO")
                self.log("WLC already provisioned.", "INFO")
                provision_status = "success"
                provision_details = self.pprint(response)
        except Exception as e:
            msg = "Wireles controller is not provisioned:"
            self.log(msg + str(e), "ERROR")
            provision_details = str(e)
            self.status = "failed"
            self.module.fail_json(msg=msg, response=provision_details)

        return provision_status, provision_details

    def provision_device(self):
        """
        Provisions a device (AP) to a specific site.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            tuple: A tuple containing the provisioning status ("SUCCESS" or "failed") and
            the provisioning details or error message.

        Description:
            Provisions an Access Point (AP) to a specified site using the provided
            site name hierarchy, RF profile, hostname, and AP type. Logs details
            and handles
        """

        provision_status = "failed"
        provision_details = None
        try:
            site_name_hierarchy = self.have.get("site_name_hierarchy")
            rf_profile = self.want.get("rf_profile")
            host_name = self.have.get("hostname")
            type_name = self.have.get("ap_type")

            if not site_name_hierarchy or not rf_profile or not host_name:
                error_msg = ("Cannot provision device: Missing parameters - \
                            site_name_hierarchy: {0}, rf_profile: {1}, host_name: {2}").\
                             format(site_name_hierarchy, rf_profile, host_name)
                self.log(error_msg, "ERROR")
                self.module.fail_json(msg=error_msg)

            provision_params = [{
                "rfProfile": rf_profile,
                "deviceName": host_name,
                "type": type_name,
                "siteNameHierarchy": site_name_hierarchy
            }]
            self.log('Current device details: {0}'.format(self.pprint(provision_params)), "INFO")

            response = self.dnac._exec(
                family="wireless",
                function='ap_provision',
                op_modifies=True,
                params={"payload": provision_params},
            )

            self.log('Response from ap_provision: {0}'.format(str(response)), "INFO")
            if response and isinstance(response, dict):
                executionid = response.get("executionId")
                resync_retry_count = self.want.get("resync_retry_count", 100)
                resync_retry_interval = self.want.get("resync_retry_interval", 5)

                while resync_retry_count:
                    execution_details = self.get_execution_details(executionid)
                    if execution_details.get("status") == "SUCCESS":
                        self.result['changed'] = True
                        self.result['response'] = execution_details
                        provision_status = "SUCCESS"
                        provision_details = execution_details
                        break

                    elif execution_details.get("bapiError"):
                        self.module.fail_json(msg=execution_details.get("bapiError"),
                                              response=execution_details)
                        break
                    time.sleep(resync_retry_interval)
                    resync_retry_count = resync_retry_count - 1

            self.log("Provisioned device with host '{0}' to site '{1}' successfully.".format(
                host_name, site_name_hierarchy), "INFO")
        except Exception as e:
            error_msg = 'An error occurred during device provisioning: {0}'.format(str(e))
            self.log(error_msg, "ERROR")
            self.status = "failed"

        return provision_status, provision_details

    def compare_radio_config(self, current_radio, want_radio):
        """
        Compares the current radio configuration with the desired radio configuration and
        returns a dictionary of unmatched values.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            current_radio (dict): A dictionary containing the current radio configuration.
            want_radio (dict): A dictionary containing the desired radio configuration.

        Returns:
            dict: A dictionary of unmatched configuration values.

        Description:
            This function checks the current radio configuration against the desired
            configuration for specific keys based on the radio slot ID. If discrepancies
            are found, they are collected and returned in a dictionary.
        """

        available_key = {
            "_0": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                  "power_assignment_mode", "powerlevel", "channel_assignment_mode",
                  "channel_number", "cable_loss", "antenna_cable_name", "radio_type"),
            "_1": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                  "power_assignment_mode", "powerlevel", "channel_assignment_mode",
                  "channel_number", "cable_loss", "antenna_cable_name", "channel_width",
                  "radio_type"),
            "_2": ("admin_status", "radio_role_assignment", "radio_type",
                  "power_assignment_mode", "powerlevel", "channel_assignment_mode",
                  "channel_number", "channel_width"),
            "_3": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                  "power_assignment_mode", "powerlevel", "channel_assignment_mode",
                  "channel_number", "cable_loss", "antenna_cable_name", "radio_band",
                  "channel_width", "radio_type"),
            "_4": ("admin_status", "antenna_gain", "antenna_name", "radio_role_assignment",
                  "power_assignment_mode", "powerlevel", "channel_assignment_mode",
                  "channel_number", "cable_loss", "antenna_cable_name", "dual_radio_mode",
                  "channel_width", "radio_type")
        }
        temp_dtos = {}
        unmatch_count = 0
        dtos_keys = list(want_radio.keys())

        for dto_key in dtos_keys:
            if dto_key in available_key["_"+ str(current_radio["slot_id"])]:
                if dto_key == "antenna_name":
                    temp_dtos[dto_key] = want_radio[dto_key]
                    unmatch_count = unmatch_count + 1
                elif dto_key == "cable_loss":
                    temp_dtos[dto_key] = want_radio[dto_key]
                elif dto_key == "antenna_cable_name":
                    temp_dtos[dto_key] = want_radio[dto_key]
                elif dto_key == "radio_type":
                    temp_dtos["radioType"] = want_radio[dto_key]
                else:
                    if want_radio[dto_key] != current_radio[dto_key]:
                        temp_dtos[self.keymap[dto_key]] = want_radio[dto_key]
                        unmatch_count = unmatch_count + 1
        temp_dtos["unmatch"] = unmatch_count
        return temp_dtos

    def compare_ap_config_with_inputdata(self, current_ap_config):
        """
        Compares the desired AP configuration with the current configuration and identifies
        changes.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            current_ap_config (dict): A dictionary containing the current AP configuration.

        Returns:
            dict: A dictionary with configuration updates needed to match the desired AP configuration.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.compare_ap_config_with_inputdata(current_ap_config)
        """
        update_config = {}

        if self.want and current_ap_config:
            if self.want.get("mac_address") == current_ap_config["mac_address"] or \
                    self.want.get("hostname") == current_ap_config["ap_name"] or \
                    self.want.get("management_ip_address") == self.have["ip_address"]:
                configurable_keys = list(self.want.keys())

                excluded_keys = ("mac_address", "hostname", "management_ip_address",
                                 "rf_profile", "site", "site_name")
                for value in excluded_keys:
                    if value in configurable_keys:
                        configurable_keys.remove(value)

                temp_dtos_list = []
                for each_key in configurable_keys :
                    if each_key == "ap_name":
                        if self.want["ap_name"] != current_ap_config.get("ap_name"):
                            update_config["apNameNew"] = self.want["ap_name"]
                            update_config["apName"] = current_ap_config.get("ap_name")
                    elif each_key in ("primary_ip_address", "secondary_ip_address",
                                      "tertiary_ip_address"):
                        if current_ap_config.get(each_key) != self.want.get(each_key):
                            update_config[self.keymap[each_key]] = {}
                            update_config[self.keymap[each_key]]["address"] = \
                                self.want[each_key]["address"]
                    elif each_key in ("2.4ghz_radio", "5ghz_radio", "6ghz_radio",
                                      "xor_radio", "tri_radio"):
                        current_radio_dtos = current_ap_config.get("radio_dtos")
                        radio_data = {}
                        for each_radio in current_radio_dtos:
                            if each_key == "2.4ghz_radio" and each_radio["slot_id"] == 0:
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "5ghz_radio" and each_radio["slot_id"] == 1:
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "6ghz_radio" and each_radio["slot_id"] == 2:
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "xor_radio" and each_radio["slot_id"] == 3:
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                            elif each_key == "tri_radio" and each_radio["slot_id"] == 4:
                                radio_data = self.compare_radio_config(each_radio,
                                                                       self.want[each_key])
                        if radio_data.get("unmatch") != 0:
                            temp_dtos_list.append(radio_data)
                    elif each_key in ("clean_air_si_2.4ghz", "clean_air_si_5ghz",
                                      "clean_air_si_6ghz"):
                        current_radio_dtos = current_ap_config.get("radio_dtos")
                        for each_dtos in current_radio_dtos:
                            if each_key == "clean_air_si_2.4ghz" and each_dtos["slot_id"] == 0 \
                                and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI24"] = self.want[each_key]
                                break
                            elif each_key == "clean_air_si_5ghz" and each_dtos["slot_id"] == 1 \
                                and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI5"] = self.want[each_key]
                                break
                            elif each_key == "clean_air_si_6ghz" and each_dtos["slot_id"] == 2 \
                                and each_dtos["clean_air_si"] != self.want.get(each_key):
                                update_config["cleanAirSI6"] = self.want[each_key]
                                break
                    else:
                        if self.want[each_key] != current_ap_config.get(each_key):
                            update_config[self.keymap[each_key]] = self.want[each_key]

                if temp_dtos_list:
                    update_config["radioConfigurations"] = temp_dtos_list
                if update_config.get("apName") is not None and \
                    update_config.get("apNameNew") is None:
                    del update_config["apName"]

                if self.want.get("primary_controller_name") == "Inherit from site/Clear":
                    update_config[self.keymap["primary_ip_address"]] = {}
                    update_config[self.keymap["primary_ip_address"]]["address"] = \
                        self.payload["access_point_details"][0]["associated_wlc_ip"]
                    update_config[self.keymap["primary_controller_name"]] = \
                        self.want["primary_controller_name"]
                    self.want["primary_ip_address"] = {}
                    self.want["primary_ip_address"]["address"] = \
                        self.payload["access_point_details"][0]["associated_wlc_ip"]

                if update_config:
                    update_config["macAddress"] = current_ap_config["eth_mac"]

            if update_config:
                self.log("Consolidated config to update AP configuration: {0}"\
                         .format(self.pprint(update_config)), "INFO")
                return update_config

            self.log('Playbook AP configuration remain same in current AP configration', "INFO")
            return None

    def update_ap_configuration(self, ap_config):
        """
        Updates the Access Point (AP) configuration based on the provided device data.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ap_config (dict): Final input config data response from
                              compare_ap_config_with_inputdata.

        Returns:
            dict: A dictionary containing the task ID and URL from the update response.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.update_ap_configuration(ap_config)
        """

        self.log("Updating access point configuration information: {0}"\
                    .format(ap_config[self.keymap["mac_address"]]), "INFO")
        ap_config["adminStatus"] = True
        ap_config["configureAdminStatus"] = True

        ap_config["apList"] = []
        temp_dict = {}

        if ap_config.get(self.keymap["ap_name"]) is not None:
            temp_dict[self.keymap["ap_name"]] = ap_config.get(self.keymap["ap_name"])
            temp_dict["apNameNew"] = ap_config["apNameNew"]
            temp_dict[self.keymap["mac_address"]] = ap_config[self.keymap["mac_address"]]
            del ap_config[self.keymap["ap_name"]]
            del ap_config["apNameNew"]
        elif ap_config.get(self.keymap["mac_address"]) is not None:
            temp_dict[self.keymap["mac_address"]] = ap_config.get(self.keymap["mac_address"])

        ap_config["apList"].append(temp_dict)

        if ap_config.get(self.keymap["location"]) is not None:
            ap_config["configureLocation"] = True
        else:
            ap_config["isAssignedSiteAsLocation"] = True

        if ap_config.get(self.keymap["led_brightness_level"]) is not None:
            ap_config["configureLedBrightnessLevel"] = True

        if ap_config.get(self.keymap["led_status"]) is not None:
            ap_config["configureLedStatus"] = True
            ap_config[self.keymap["led_status"]] = True \
                if ap_config[self.keymap["led_status"]] == "Enabled" else False

        if ap_config.get(self.keymap["ap_mode"]) is not None:
            if ap_config.get(self.keymap["ap_mode"]) == "Local":
                ap_config[self.keymap["ap_mode"]] = 0
            elif ap_config.get(self.keymap["ap_mode"]) == "Monitor":
                ap_config[self.keymap["ap_mode"]] = 1
            elif ap_config.get(self.keymap["ap_mode"]) == "Sniffer":
                ap_config[self.keymap["ap_mode"]] = 4
            else:
                ap_config[self.keymap["ap_mode"]] = 5
            ap_config["configureApMode"] = True

        if ap_config.get(self.keymap["primary_controller_name"]) is not None or \
            ap_config.get(self.keymap["secondary_controller_name"]) is not None or \
            ap_config.get(self.keymap["tertiary_controller_name"]) is not None or \
            ap_config.get(self.keymap["primary_ip_address"]) is not None or \
            ap_config.get(self.keymap["secondary_ip_address"]) is not None or \
            ap_config.get(self.keymap["tertiary_ip_address"]) is not None :
            ap_config["configureHAController"] = True

        if ap_config.get(self.keymap["failover_priority"]) is not None:
            if ap_config.get(self.keymap["failover_priority"]) == "Low":
                ap_config[self.keymap["failover_priority"]] = 1
            elif ap_config.get(self.keymap["failover_priority"]) == "Medium":
                ap_config[self.keymap["failover_priority"]] = 2
            elif ap_config.get(self.keymap["failover_priority"]) == "High":
                ap_config[self.keymap["failover_priority"]] = 3
            else:
                ap_config[self.keymap["failover_priority"]] = 4
            ap_config["configureFailoverPriority"] = True

        if ap_config.get("cleanAirSI24") is not None:
            ap_config["configureCleanAirSI24Ghz"] = True
            ap_config["cleanAirSI24"] = True \
                if ap_config["cleanAirSI24"] == "Enabled" else False

        if ap_config.get("cleanAirSI5") is not None:
            ap_config["configureCleanAirSI5Ghz"] = True
            ap_config["cleanAirSI5"] = True \
                if ap_config["cleanAirSI5"] == "Enabled" else False

        if ap_config.get("cleanAirSI6") is not None:
            ap_config["configureCleanAirSI6Ghz"] = True
            ap_config["cleanAirSI6"] = True \
                if ap_config["cleanAirSI6"] == "Enabled" else False

        if ap_config.get("radioConfigurations") is not None:
            radio_config_list = ap_config.get("radioConfigurations")
            temp_radio_dtos_list = []
            for each_radio in radio_config_list:
                radio_dtos = {}

                radio_dtos["configureAdminStatus"] = True
                radio_dtos["adminStatus"] = True

                if each_radio.get(self.keymap["channel_assignment_mode"]) is not None:
                    radio_dtos[self.keymap["channel_assignment_mode"]] = 1 \
                        if each_radio[self.keymap["channel_assignment_mode"]] == "Global" else 2
                    radio_dtos["configureChannel"] = True

                if each_radio.get(self.keymap["channel_number"]) is not None:
                    radio_dtos[self.keymap["channel_number"]] = \
                        each_radio.get(self.keymap["channel_number"])
                    radio_dtos["configureChannel"] = True
                    radio_dtos[self.keymap["channel_assignment_mode"]] = 2

                if each_radio.get(self.keymap["channel_width"]) is not None:
                    if each_radio.get(self.keymap["channel_width"]) == "20 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 3
                    elif each_radio.get(self.keymap["channel_width"]) == "40 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 4
                    elif each_radio.get(self.keymap["channel_width"]) == "80 MHz":
                        radio_dtos[self.keymap["channel_width"]] = 5
                    else:
                        radio_dtos[self.keymap["channel_width"]] = 6
                    radio_dtos["configureChannelWidth"] = True

                if each_radio.get(self.keymap["power_assignment_mode"]) is not None:
                    if each_radio[self.keymap["power_assignment_mode"]] == "Global":
                        radio_dtos[self.keymap["power_assignment_mode"]] = 1
                    else:
                        radio_dtos[self.keymap["power_assignment_mode"]] = 2
                    radio_dtos["configurePower"] = True

                if each_radio.get(self.keymap["powerlevel"]) is not None:
                    radio_dtos[self.keymap["powerlevel"]] = \
                        each_radio.get(self.keymap["powerlevel"])
                    radio_dtos[self.keymap["power_assignment_mode"]] = 2
                    radio_dtos["configurePower"] = True

                if each_radio.get("antenna_cable_name") is not None:
                    radio_dtos["antennaCableName"] = \
                        each_radio.get("antenna_cable_name")
                    radio_dtos["configureAntennaCable"] = True

                if each_radio.get("antenna_name") is not None:
                    radio_dtos["antennaPatternName"] = each_radio.get("antenna_name")
                    radio_dtos["configureAntennaPatternName"] = True

                if each_radio.get(self.keymap["radio_band"]) is not None:
                    radio_dtos[self.keymap["radio_band"]] = "RADIO24" \
                        if each_radio[self.keymap["radio_band"]] == "2.4 GHz" else "RADIO5"

                if each_radio.get(self.keymap["radio_role_assignment"]) is not None:
                    if each_radio.get(self.keymap["radio_role_assignment"]) == "Auto":
                        radio_dtos[self.keymap["radio_role_assignment"]] = "AUTO"
                    elif each_radio.get(self.keymap["radio_role_assignment"]) == \
                        "Client-Serving":
                        radio_dtos[self.keymap["radio_role_assignment"]] = "SERVING"
                    else:
                        radio_dtos[self.keymap["radio_role_assignment"]] = "MONITOR"
                    radio_dtos["configureRadioRoleAssignment"] = True

                if each_radio.get(self.keymap["radio_type"]) is not None:
                    radio_dtos[self.keymap["radio_type"]] = \
                        each_radio.get(self.keymap["radio_type"])

                if each_radio.get("cable_loss") is not None:
                    radio_dtos["cableLoss"] = each_radio.get("cable_loss")
                    radio_dtos["antennaCableName"] = "other"
                    radio_dtos["configureAntennaCable"] = True

                if each_radio.get(self.keymap["antenna_gain"]) is not None:
                    if each_radio.get(self.keymap["antenna_gain"]) is not None and \
                        each_radio.get(self.keymap["antenna_gain"]) > 0:
                        radio_dtos[self.keymap["antenna_gain"]] = \
                            each_radio.get(self.keymap["antenna_gain"])
                        radio_dtos["antennaPatternName"] = "other"
                        radio_dtos["configureAntennaPatternName"] = True

                temp_radio_dtos_list.append(radio_dtos)
            ap_config["radioConfigurations"] = temp_radio_dtos_list

        for key_to_remove in ("mac_address", "hostname", "management_ip_address",
                                "macAddress"):
            if ap_config.get(key_to_remove):
                del ap_config[key_to_remove]
        self.log("CHECKIN update: {0}".format(self.pprint(ap_config)),
                        "INFO")
        try:
            response = self.dnac._exec(
                family="wireless",
                function='configure_access_points',
                op_modifies=True,
                params={"payload": ap_config}
            )

            if response:
                response = response.get("response")
                self.log("Response of Access Point Configuration: {0}".format(
                    self.pprint(response)), "INFO")
                return dict(mac_address=self.have["mac_address"], response=response)

        except Exception as e:
            self.log("AP config update Error: {0} {1}".format(self.pprint(ap_config), str(e)),
                     "ERROR")
            return None

    def data_frame(self, fields_to_include=None, records=list):
        """
        Filters the input data to include only the specified fields.

        Parameters:
            fields_to_include (str): Comma-separated string of keys to display.
            records (list of dict): A list of dictionaries with only the specified fields.

        Returns:
            list: A list of dictionaries containing filtered records.

        Example:
            functions = Accesspoint(module)
            final_input_data = functions.data_frame(ap_selected_fields, device_records)
        """
        try:
            if records is None:
                return []

            records = self.camel_to_snake_case(records)

            if not fields_to_include or fields_to_include.strip() == '':
                return records

            field_names = [field.strip() for field in fields_to_include.split(",")]
            filtered_data = []

            for record in records:
                filtered_record = {}

                for field in field_names:
                    filtered_record[field] = record.get(field)

                filtered_data.append(filtered_record)

            return filtered_data

        except Exception as e:
            self.log("Unable to filter fields: {0}".format(str(e)) , "ERROR")
            return None

    def map_config_key_to_api_param(self, keymap=any, data=any):
        """
        Converts keys in a dictionary from CamelCase to snake_case and creates a keymap.

        Parameters:
            keymap (dict): Already existing key map dictionary to add to or empty dict {}.
            data (dict): Input data where keys need to be mapped using the key map.

        Returns:
            dict: A dictionary with the original keys as values and the converted snake_case
                    keys as keys.

        Example:
            functions = Accesspoint(module)
            keymap = functions.map_config_key_to_api_param(keymap, device_data)
        """

        if keymap is None:
            keymap = {}

        if isinstance(data, dict):
            keymap.update(keymap)

            for key, value in data.items():
                new_key = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key).lower()
                keymap[new_key] = key

                if isinstance(value, dict):
                    self.map_config_key_to_api_param(keymap, value)
                elif isinstance(value, list):

                    for item in value:
                        if isinstance(item, dict):
                            self.map_config_key_to_api_param(keymap, item)

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self.map_config_key_to_api_param(keymap, item)

        return keymap

    def pprint(self, jsondata):
        """
        Pretty prints JSON/dictionary data in a readable format.

        Parameters:
            jsondata (dict): Dictionary data to be printed.

        Returns:
            str: Formatted JSON string.
        """
        return json.dumps(jsondata, indent=4, separators=(',', ': '))

    def camel_to_snake_case(self, config):
        """
        Convert camel case keys to snake case keys in the config.

        Parameters:
            config (dict or list): Configuration data to be transformed.

        Returns:
            dict or list: Updated config with snake_case keys.
        """

        if isinstance(config, dict):
            new_config = {}
            for key, value in config.items():
                new_key = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key).lower()
                new_value = self.camel_to_snake_case(value)
                new_config[new_key] = new_value
        elif isinstance(config, list):
            return [self.camel_to_snake_case(item) for item in config]
        else:
            return config
        return new_config


def main():
    """ main entry point for module execution
    """
    accepoint_spec = {
        'dnac_host': {'required': True, 'type': 'str'},
        'dnac_port': {'type': 'str', 'default': '443'},
        'dnac_username': {'type': 'str', 'default': 'admin'},
        'dnac_password': {'type': 'str', 'no_log': True},
        'dnac_verify': {'type': 'bool', 'default': 'True'},
        'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
        'dnac_debug': {'type': 'bool', 'default': False},
        'dnac_log': {'type': 'bool', 'default': False},
        'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
        "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
        'config_verify': {'type': 'bool', "default": False},
        "dnac_log_append": {"type": 'bool', "default": True},
        'dnac_api_task_timeout': {'type': 'int', "default": 300},
        'dnac_task_poll_interval': {'type': 'int', "default": 2},
        'config': {'required': True, 'type': 'list', 'elements': 'dict'},
        'validate_response_schema': {'type': 'bool', 'default': True},
        'state': {'default': 'merged', 'choices': ['merged', 'deleted']},
        'force_sync': {'type': 'bool'}
    }
    module = AnsibleModule(
        argument_spec=accepoint_spec,
        supports_check_mode=True
    )

    ccc_network = Accesspoint(module)
    state = ccc_network.params.get("state")

    if state not in ccc_network.supported_states:
        ccc_network.status = "invalid"
        ccc_network.msg = "State {0} is invalid".format(state)
        ccc_network.check_return_status()

    ccc_network.validate_input_yml().check_return_status()
    config_verify = ccc_network.params.get("config_verify")

    for config in ccc_network.validated_config:
        ccc_network.reset_values()
        ccc_network.get_want(config).check_return_status()
        ccc_network.get_have(config).check_return_status()
        ccc_network.get_diff_state_apply[state](config).check_return_status()

        if config_verify:
            time.sleep(20)
            ccc_network.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_network.result)


if __name__ == '__main__':
    main()
