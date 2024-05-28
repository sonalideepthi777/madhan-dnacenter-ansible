#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

import time
import pandas as pd
from dnacentersdk import api
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase
)
from ansible_collections.cisco.dnac.plugins.module_utils.pydentic_validation import *
from ansible.module_utils.basic import AnsibleModule

__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Natarajan")

DOCUMENTATION = r"""
---
module: accesspoint_workflow_manager
short_description: accesspoint_workflow_manager used to automate bulk AP configuration changes.
description:
- We can change the AP display name, AP name or Other Param based on the input.yml file
- Using by this package we can filter specific device details like family = Switches and Hubs
- We can compare input details with current AP configuration.
- Desired configuration will be updated to the needed APs Only
- Also able to reboot the Accesspoint if needed.
version_added: '6.7.0'
extends_documentation_fragment:
  - accesspoint_workflow_manager
author: A Mohamed Rafeek (@mohamedrafeek)
        Natarajan (@natarajan)

options:
    config_verify:
        description: Set to True to verify the Cisco Catalyst Center config after applying the playbook config.
    type: bool
    default: False
    state:
        description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [ merged ]
    default: merged

config:
    mac_address: It is string MAC address format(also it is Required)
    below param based on the requirement.
    led_brightness_level: It should be Number 1 to 8
    led_status: "Enabled" or "Disabled"
    location: It should be String
    ap_name: It should be String
    accesspointradiotype: It is number and should be 1,2,3 and 6
        1 - Will be 2.4 Ghz
        2 - Will be 5 Ghz
        3 - Will be XOR
        6 - Will be 6 Ghz

requirements:
- dnacentersdk >= 2.4.5
- python >= 3.10
notes:
  - dnacsdk Method used 
"""

EXAMPLES = r"""
- name: Configure device credentials on Cisco DNA Center
  hosts: sandboxdnac.cisco.com
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
    - "input.yml"
  tasks:
    - name: Get Device info and updating access point details
      cisco.dnac.accesspoint_workflow_manager:
        device_fields: "{{device_fields}}"
        ap_selected_field: "{{ap_selected_field}}"
        dnac_host: "{{dnac_host}}"
        dnac_username: "{{dnac_username}}"
        dnac_password: "{{dnac_password}}"
        dnac_verify: "{{dnac_verify}}"
        dnac_port: "{{dnac_port}}"
        dnac_version: "{{dnac_version}}"
        dnac_debug: "{{dnac_debug}}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        config: "{{ config }}"
      register: output_list
    - name: iterate through module output (a list)
      debug:
        msg: '{{ item }}'   
        with_items: "{{output_list.output }}"
"""

RETURN = r"""
#Case: Modification of the AP details updated and Rebooted Accesspoint
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "response": {
            "taskId": "string",
            "url": "string"
        },
        "version": "string"
    }
"""

class Accesspoint(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged"]
        self.payload = module.params
        # Need to follow Camel Case to snake case
        # So we are using the Key maping for API fields
        self.keymap = {
            "led_brightness_level": "ledBrightnessLevel",
            "led_status": "ledStatus",
            "primary_ip_address": "primaryIpAddress",
            "eth_mac": "ethMac",
            "ap_name": "apName",
            "ap_ethernet_mac_address": "apEthernetMacAddress",
            "ap_manager_interface_ip": "apManagerInterfaceIp",
            "associated_wlc_ip": "associatedWlcIp",
            "boot_date_time": "bootDateTime",
            "collection_interval": "collectionInterval",
            "collection_status": "collectionStatus",
            "description": "description",
            "device_support_level": "deviceSupportLevel",
            "error_code": "errorCode",
            "error_description": "errorDescription",
            "family": "family",
            "hostname": "hostname",
            "id": "id",
            "instance_tenantId": "instanceTenantId",
            "instance_uuid": "instanceUuid",
            "interface_count": "interfaceCount",
            "inventory_status_detail": "inventoryStatusDetail",
            "last_update_time": "lastUpdateTime",
            "last_updated": "lastUpdated",
            "line_card_count": "lineCardCount",
            "line_card_id": "lineCardId",
            "location": "location",
            "location_name": "locationName",
            "mac_address": "macAddress",
            "managed_atleast_once": "managedAtleastOnce",
            "management_ip_address": "managementIpAddress",
            "management_state": "managementState",
            "memory_size": "memorySize",
            "platform_id": "platformId",
            "reachability_failure_reason": "reachabilityFailureReason",
            "reachability_status": "reachabilityStatus",
            "role": "role",
            "role_source": "roleSource",
            "serial_number": "serialNumber",
            "series": "series",
            "snmp_contact": "snmpContact",
            "snmp_location": "snmpLocation",
            "software_type": "softwareType",
            "software_version": "softwareVersion",
            "tag_count": "tagCount",
            "tunnel_udp_port": "tunnelUdpPort",
            "type": "type",
            "up_time": "upTime",
            "uptime_seconds": "uptimeSeconds",
            "waas_device_mode": "waasDeviceMode"
        }

        self.baseurl = "https://" + module.params["dnac_host"]+ ":" + module.params["dnac_port"]
        self.log('Login DNAC using by user: ' + module.params["dnac_username"], "INFO")
        try:
            self.dnac = api.DNACenterAPI(base_url=self.baseurl, 
                                    username = module.params["dnac_username"],
                                    password = module.params["dnac_password"],
                                    verify = False)
        except Exception as e:
            self.log("Unable to Login DNAC "+ str(e) , "ERROR")

    # Below function used pydentic validation over the ansible validation
    # We can customize validation, if it not required we can remove this function.
    def validate_input(self, inputdata):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based pydentics package.
        Parameters:
          - inputdata: To validate the input file of yaml keys values will be validated.
        Returns:
          The method not returns anything just validation input if anything worng will stop execution.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
          If the validation succeeds, this will allow to go next step, unless this will stop execution.
          based on the fields.
        """
        self.log('Validating the Yaml File..', "INFO")
        try:
            CheckUrl(hosturl="https://" + inputdata["dnac_host"])
            CheckNames(names=inputdata["dnac_username"])
            CheckNames(names=inputdata["dnac_password"])
            CheckPort(port=inputdata["dnac_port"])
            aplist = inputdata.get("config")
            for eachap in aplist:
                CheckMACaddress(mac_address=eachap["mac_address"])
                CheckNames(names=eachap["location"])
                CheckNames(names=eachap["ap_name"])
                CheckBrightnessLevel(led_brightness_level=int(eachap["led_brightness_level"]))
                CheckEnabledDisabledStatus(EnabledDisabledStatus=eachap["led_status"])
                #CheckRadioType(ap_radiotype=int(eachap["accesspointradiotype"]))
            self.log("Successfully validated playbook config ", "INFO")
            self.msg = "Successfully validated input from the playbook"
            self.status = "success"
            return self
        except ValidationError as e:
            self.log("Invalid Param provided in input Yml File." + str(e), "ERROR")
            self.msg = "Invalid parameters in playbook: " + str(e)
            self.status = "failed"
            return self

    # Below function used to show the current state of the network divices
    # As Accesss point Device info, Config and Final field to pass in the Update data
    def get_have(self):
        """
        This function used to get AP device details as json response from DNAC site.
        by giving MAC address as a input in the URL GET Method
        Device information given in the input file
        Device Configuration Details 
        Conpare with input data and current config data
        """
        responses = {}
        ap_data = []
        final_ap_data = []
        devices_list = self.get_state()
        # Check if AP list is empty due to MAC Addres might not be
        # in the given DNAC
        if devices_list is None:
            responses["accesspoint"] = dict(
                final_input=devices_list,
                msg="Given MAC Address not available in DNAC")
        else:
            ap_data = self.get_ap_configuration()
            final_ap_data = self.compare_ap_cofig_with_inputdata(ap_data)
            # If the final_ap_data is None means no changes required to update
            if final_ap_data is None:
                responses["accesspoint"] = dict(
                    final_input=final_ap_data,
                    msg="Input Access Point Configuration remain same in Current AP configration")
            else:
                responses["accesspoint"] = {
                    "device_list": devices_list,
                    "device_configs": ap_data,
                    "final_input": final_ap_data,
                    "msg": "Filtered AP Device data list for update AP config"}

        self.result["response"].append(responses)
        self.log("Current AP State "+ str(responses["accesspoint"]) , "INFO")
        return final_ap_data

    # below function not required for the current scenario but required for upcomming. 
    def get_state(self):
        """
        This function used to get device details as json response from DNAC site based
        on the config field given on the input yml file
        Parameters:
          - config:
            -   mac_address: "90:e9:5e:03:f3:40" (Required Field)
                led_brightness_level: 4 
                led_status: "Enabled"
                location: "LTTS"
                ap_name: "NFW-AP1-9130AXE"
        Returns:
            {
                "apEthernetMacAddress": "34:5d:a8:0e:20:b4",
                "family": "Unified AP",
                "hostname": "NFW-AP1-9130AXE",
                "id": "37b05b0f-1b1e-496a-b101-8f277f0af8ff",
                "lastUpdated": "2024-05-28 08:36:19",
                "macAddress": "90:e9:5e:03:f3:40",
                "managementIpAddress": "204.1.216.2",
                "type": "Cisco Catalyst 9130AXE Unified Access Point",
                "upTime": "08:22:37.080"
            }
        Example:
            functions = Accesspoint(module)
            device_data = functions.get_state()
        """
        self.log('Getting Network Device information', "INFO")
        try:
            all_mac_address = [eachdevice["mac_address"] for eachdevice in self.payload["config"]]
            device_list = self.dnac.devices.get_device_list(macAddress=all_mac_address)
            if self.payload["device_fields"] == "" or self.payload["device_fields"] == "all":
                self.payload["device_list"] = device_list['response']
                return self.payload["device_list"]

            fields = [str(self.keymap[x]) for x in self.payload["device_fields"].split(",")]
            if len(device_list) != 0:
                df = pd.DataFrame.from_records(device_list['response'])
                selected_data = df[fields]
                self.payload["device_list"] = selected_data.to_dict('records')
                return self.payload["device_list"]
            else:
                return None
        except Exception as e:
            self.log("Unable to get device info "+ str(e) , "ERROR")

    def get_ap_configuration(self):
        """
        This function used to get AP device details as json response from DNAC site.
        by giving MAC address as a input in the URL GET Method
        Parameters:
            We are not using input param already passed in the module.param
          - self.payload: used from yml input files input.yml we are using accesspoints section
            if ap_selected_field in input.yml is empty or all this will show all field
            else ap_selected_field: "mac_address,eth_mac,ap_name,led_status,location"
            then will show only listed field.
        Returns:
            [
                {
                    "apName": "NFW-AP1-9130AXE",
                    "ethMac": "34:5d:a8:0e:20:b4",
                    "ledBrightnessLevel": 3,
                    "ledStatus": "Enabled",
                    "location": "LTTS",
                    "macAddress": "90:e9:5e:03:f3:40"
                }
            ]
        Example:
            functions = Accesspoint(module)
            ap_data = functions.get_ap_configuration()
        """
        ap_config_data = []
        for device in self.payload["device_list"]:
            self.log('Getting Access Point Configuration Information for ' \
                     + device['apEthernetMacAddress'], "INFO")
            try:
                jsondata = self.dnac.wireless.get_access_point_configuration(
                    key=str(device['apEthernetMacAddress']))
                ap_config_data.append(jsondata)
            except Exception as e:
                self.log(jsondata['error'] + e, "ERROR")
        self.log('Access Point Configuration Information: ' + str(ap_config_data), "INFO")
        if self.payload["ap_selected_field"] == "" or self.payload["ap_selected_field"] == "all":
            return ap_config_data

        fields = [str(self.keymap[x]) for x in self.payload["ap_selected_field"].split(",")]
        if len(ap_config_data) != 0:
            df = pd.DataFrame.from_records(ap_config_data)
            selected_data = df[fields]
            return selected_data.to_dict('records')
        else:
            return None

    def compare_ap_cofig_with_inputdata(self, apconfig):
        """
        This function used to compare with the input ap detail with the current ap configuration
        information are not same, those data will be updated in the AP input information.
        Parameters:
          - apconfig: This is response of the get_ap_configuration
        Returns:
            This will be the return the final data for update AP detail.
            "final_input": [
                {
                    "adminStatus": true,
                    "apList": [
                        {
                            "macAddress": "34:5d:a8:0e:20:b4"
                        }
                    ],
                    "configureLedBrightnessLevel": true,
                    "ledBrightnessLevel": 4,
                    "macAddress": "34:5d:a8:0e:20:b4"
                } ]
        Example:
            functions = Accesspoint(module)
            final_input_data = functions.compare_ap_cofig_with_inputdata(all_apconfig)
        """
        final_apchange = []
        for each_input in self.payload["config"]:
            for eachap in apconfig:
                # We are identifing AP based on the AP mac Address so we cannot update this field.
                if each_input["mac_address"] == eachap["macAddress"]:
                    newdict = {}
                    for each_key in list(each_input.keys()):
                        if each_input[each_key] != eachap[self.keymap[each_key]]:
                            if each_key == "ap_name":
                                newdict[self.keymap[each_key]] = eachap[self.keymap[each_key]]
                                newdict[self.keymap[each_key] + "New"] = each_input[each_key]
                            else:
                                newdict[self.keymap[each_key]] = each_input[each_key]

                    if newdict:
                        newdict["macAddress"] = eachap["ethMac"]
                        final_apchange.append(newdict)
        if len(final_apchange) > 0:
            return final_apchange
        else:
            self.log('Input Access Point Configuration remain same in Current AP configration',
                      "INFO")
            return None

    def get_want(self, device_data):
        update_apconfig = self.update_ap_configuration(device_data)
        time.sleep(30)
        devices_config = self.get_ap_configuration()
        responses = {}
        responses["accesspoints_updates"] = {"response": update_apconfig,
                                             "after_update": devices_config,
            "msg": "Below list APs updated successfully"}
        self.result["response"].append(responses)
        return update_apconfig

    def update_ap_configuration(self, device_data):
        """
        This function used to update the ap detail with the current ap configuration
        Final data received from compare_ap_cofig_with_inputdata response will be the 
        input of this function.
        Parameters:
          - device_data: DNAC final device data response from compare_ap_cofig_with_inputdata
        Returns:
            {
                "response": {
                    "taskId": "string",
                    "url": "string"
                },
                "version": "string"
            }
        Example:
            functions = Accesspoint(module)
            final_input_data = functions.update_ap_configuration(device_data)
        """
        all_response = []
        for device in device_data:
            try:
                self.log("Updating Access Point Configuration Information "+ device["macAddress"],
                          "INFO")
                # Below code might changed once we receive the dev dnac credentials
                device["adminStatus"] = True
                if device.get("apName") is not None:
                    device["apList"] = [dict(apName = device["apName"],
                                        apNameNew = device["apNameNew"],
                                        macAddress = device["macAddress"])]
                    del device["apName"]
                    del device["apNameNew"]
                elif device.get("apName") is None and device.get("macAddress") is not None:
                    device["apList"] = [dict(macAddress = device["macAddress"])]

                if device.get("location") is not None:
                    device["configureLocation"] = True
                if device.get("ledBrightnessLevel") is not None:
                    device["configureLedBrightnessLevel"] = True
                if device.get("ledStatus") is not None:
                    device["configureLedStatus"] = True
                    device["ledStatus"] = True if device["ledStatus"] == "Enabled" else False

                self.log("Response of Access Point Configuration: " + str(device), "INFO")
                response = self.dnac.wireless.configure_access_points(**device)
                self.log("Response of Access Point Configuration: " + str(response), "INFO")
                all_response.append(dict(macAdress=device["macAddress"], response=response))
            except Exception as e:
                self.log("AP config update Error" + device["macAddress"] + str(e), "ERROR")

        if len(all_response) > 0:
            return all_response


def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check or assign default.
    accepoint_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'device_fields': {'required': True, 'type': 'str'},
                    'ap_selected_field': {'required': True, 'type': 'str'},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    'config_verify': {'type': 'bool', "default": False},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True}
                }
    module = AnsibleModule(
        argument_spec=accepoint_spec,
        supports_check_mode=True
    )

    ccc_network = Accesspoint(module)

    # Check the Input file should not be empty config param
    if len(module.params.get('config')) < 1:
        module.fail_json(msg='Access Point Should not be Empty, You may forget to pass input.yml',
                         **ccc_network.result)

    ccc_network.validate_input(module.params).check_return_status()

    # Getting the AP details by passing the Mac Address of the device
    # Comparing input data with current AP configuration detail
    final_config = ccc_network.get_have()

    if final_config:
        # Updating the final filtered data to the update AP information
        ccc_network.get_want(final_config)

    module.exit_json(**ccc_network.result)

if __name__ == '__main__':
    main()
